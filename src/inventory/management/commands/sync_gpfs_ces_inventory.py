# inventory/management/commands/sync_gpfs_ces_inventory.py
import os
import re
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Dict

import paramiko
import requests
from urllib3.exceptions import InsecureRequestWarning

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from inventory.models import HPCCluster, Host, HostStatus


# -----------------------------
# GPFS command
# -----------------------------
CES_LIST_CMD = "mmlscluster -Y | awk -F: '/clusterNode/ {print $8}' | tail -n +2 | sed 's/-gpfs.*//' | grep -E 'ces|xphhpc'"


# -----------------------------
# SSH helper (PASSWORD auth)
# -----------------------------
def ssh_run(host: str, username: str, password: str, cmd: str, timeout: int = 60) -> str:
    """Run SSH command with explicit channel timeouts to prevent hanging reads."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )

        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        stdout.channel.settimeout(timeout)
        stderr.channel.settimeout(timeout)

        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        client.close()

        if err.strip():
            out = out + "\n" + err
        return out

    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return f"SSH_ERROR: {type(e).__name__}: {str(e)}"


# -----------------------------
# Shell helpers
# -----------------------------
def sh_quote(s: str) -> str:
    if s is None:
        s = ""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def wrap_login(cmd: str) -> str:
    return f"bash -lc {sh_quote(cmd)}"


def normalize_name(name: str) -> str:
    return (name or "").strip().rstrip(".")


# -----------------------------
# Parse CES output robustly
# -----------------------------
def parse_ces_nodes(text: str) -> List[str]:
    nodes: List[str] = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        low = line.lower()
        if "mmces: command not found" in low or low.startswith("bash:") or low.startswith("ssh_error:"):
            continue

        parts = re.split(r"\s+", line)
        if not parts:
            continue

        host = normalize_name(parts[-1])
        if host:
            nodes.append(host)

    # de-dupe preserving order
    seen = set()
    uniq: List[str] = []
    for n in nodes:
        if n not in seen:
            uniq.append(n)
            seen.add(n)
    return uniq


# -----------------------------
# Inventory mappings
# -----------------------------
def infer_host_type(hostname: str) -> str:
    """
    Infer host type from hostname:
      - contains 'ces' → ces            (e.g. dcwipphces*, dcmipphces*)
      - else  → storage-infra  (e.g. dcwixphhpc*)
    """
    name = (hostname or "").lower()
    if "ces" in name.lower():
        return "ces"
    if "xphhpc" in name:
        return "storage-infra"


def map_gpfs_to_inventory_status() -> str:
    return HostStatus.AVAILABLE


# -----------------------------
# iDRAC naming rule
# -----------------------------
def idrac_from_host_fqdn(host_fqdn: str) -> str:
    hf = normalize_name(host_fqdn)
    if "." in hf:
        short, domain = hf.split(".", 1)
        mapped = short.replace("ph", "rm")
        return f"{mapped}.{domain}"
    return hf.replace("ph", "rm")


# -----------------------------
# Redfish helpers (Dell + Supermicro)
# -----------------------------
def get_nested(d: dict, path: List[str]) -> Optional[object]:
    cur: object = d
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def extract_serial_and_asset(system_json: dict) -> Tuple[Optional[str], Optional[str]]:
    """
    Policy:
      - Dell asset_tag = Oem.Dell.DellSystem.NodeID
      - Supermicro asset_tag = SerialNumber (since AssetTag is typically null)
      - Fallback asset_tag = AssetTag if present else SerialNumber
    """
    oem = system_json.get("Oem") or {}

    serial = system_json.get("SerialNumber") or system_json.get("UUID")

    dell = oem.get("Dell") or {}
    serial = serial or dell.get("ServiceTag")

    sm = oem.get("Supermicro") or oem.get("SuperMicro") or {}
    serial = serial or sm.get("SystemSerialNumber") or sm.get("SerialNumber")

    node_id = get_nested(system_json, ["Oem", "Dell", "DellSystem", "NodeID"])
    if isinstance(node_id, str) and node_id.strip():
        return serial, node_id.strip()

    asset = system_json.get("AssetTag") or system_json.get("AssetTagNumber")
    if isinstance(asset, str) and asset.strip():
        return serial, asset.strip()

    return serial, serial


def discover_system_id_direct(sess, base: str, timeout: int, stdout, style) -> str:
    try:
        r = sess.get(f"{base}/redfish/v1/Systems", timeout=timeout, headers={"Accept": "application/json"})
        if r.status_code == 200:
            data = r.json()
            members = data.get("Members", [])
            if members:
                odata_id = members[0].get("@odata.id", "")
                sid = odata_id.split("/")[-1] if odata_id else None
                if sid:
                    stdout.write(style.SUCCESS(f"  → Discovered System ID: {sid}"))
                    return sid
    except Exception:
        pass
    stdout.write(style.WARNING("  → Discovery failed, falling back to common IDs"))
    return "System.Embedded.1"


def redfish_get_system_info_direct(
    idrac_host: str,
    user: str,
    password: str,
    timeout: int,
    stdout,
    style,
) -> Dict[str, Optional[str]]:
    stdout.write(f"Attempting iDRAC direct → {idrac_host}")

    base = f"https://{idrac_host}"
    sess = requests.Session()
    sess.auth = (user, password)
    sess.verify = False
    sess.headers.update({"Accept": "application/json"})

    system_id = discover_system_id_direct(sess, base, timeout, stdout, style)

    candidates = [
        f"/redfish/v1/Systems/{system_id}",
        "/redfish/v1/Systems/System.Embedded.1",
        "/redfish/v1/Systems/System.1",
        "/redfish/v1/Systems/1",
    ]
    candidates = list(dict.fromkeys(candidates))

    system_json = None
    last_err = None
    for path in candidates:
        try:
            r = sess.get(base + path, timeout=timeout, headers={"Accept": "application/json"})
            if r.status_code == 200:
                system_json = r.json()
                stdout.write(style.SUCCESS(f"  → Used endpoint: {path}"))
                break
            last_err = f"HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)

    if not system_json:
        stdout.write(style.WARNING(f"FAILED iDRAC direct {idrac_host} → {last_err}"))
        return {"name": None, "model": None, "bios": None, "serial": None, "asset_tag": None, "error": last_err}

    model = system_json.get("Model")
    name = system_json.get("HostName") or system_json.get("DNSHostName") or system_json.get("Name")
    bios = system_json.get("BiosVersion")

    if not bios:
        bios_link = system_json.get("Bios", {}).get("@odata.id")
        if bios_link:
            try:
                rb = sess.get(base + bios_link, timeout=timeout, headers={"Accept": "application/json"})
                if rb.status_code == 200:
                    bj = rb.json()
                    bios = bj.get("Version") or bj.get("Name")
            except Exception:
                pass

    serial, asset_tag = extract_serial_and_asset(system_json)

    stdout.write(
        style.SUCCESS(
            f"Success iDRAC direct {idrac_host} → model={model or '—'}, bios={bios or '—'}, "
            f"serial={serial or '—'}, asset={asset_tag or '—'}"
        )
    )
    return {"name": name, "model": model, "bios": bios, "serial": serial, "asset_tag": asset_tag, "error": None}


# -----------------------------
# Jump -> root -> cluster execution
# -----------------------------
def run_on_cluster_as_root_via_jump(
    jump: str,
    jump_user: str,
    jump_password: str,
    cluster: str,
    remote_cmd: str,
    timeout: int,
) -> str:
    remote = wrap_login(remote_cmd)
    jump_side = (
        "sudo -S -p '' "
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"root@{cluster} {sh_quote(remote)}"
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=jump,
            username=jump_user,
            password=jump_password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )

        stdin, stdout, stderr = client.exec_command(jump_side, timeout=timeout, get_pty=True)
        stdin.write(jump_password + "\n")
        stdin.flush()

        stdout.channel.settimeout(timeout)
        stderr.channel.settimeout(timeout)

        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        client.close()

        if err.strip():
            out = out + "\n" + err
        return out
    except Exception as e:
        try:
            client.close()
        except Exception:
            pass
        return f"SSH_ERROR: {type(e).__name__}: {str(e)}"


# -----------------------------
# OS discovery over SSH to host
# -----------------------------
def parse_pretty_name(text: str) -> Optional[str]:
    m = re.search(r'^PRETTY_NAME\s*=\s*"(.*)"\s*$', (text or "").strip(), flags=re.M)
    if m:
        return m.group(1).strip() or None
    m2 = re.search(r"^PRETTY_NAME\s*=\s*(.*)\s*$", (text or "").strip(), flags=re.M)
    if m2:
        val = m2.group(1).strip().strip('"')
        return val or None
    return None


def parse_single_line(text: str) -> Optional[str]:
    s = (text or "").strip()
    if not s or s.startswith("SSH_ERROR"):
        return None
    return s.splitlines()[0].strip() or None


def parse_used_for(text: str) -> Optional[str]:
    if not text or text.startswith("SSH_ERROR"):
        return None
    for line in text.splitlines():
        v = line.strip()
        if v:
            return v
    return None


class Command(BaseCommand):
    help = "Sync GPFS CES nodes via jump+root; optionally enrich with iDRAC + used_for/os_type/kernal_version via SSH to hosts."

    def add_arguments(self, parser):
        parser.add_argument("--timeout", type=int, default=30)
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--disable-missing", action="store_true")
        parser.add_argument("--host-domain", default=os.getenv("GPFS_HOST_DOMAIN", ".edc.nam.gm.com"))

        # iDRAC / Redfish
        parser.add_argument("--idrac", action="store_true")
        parser.add_argument("--idrac-user", default=os.getenv("IDRAC_USER", ""))
        parser.add_argument("--idrac-password", default=os.getenv("IDRAC_PASSWORD", ""))
        parser.add_argument("--idrac-timeout", type=int, default=4)
        parser.add_argument("--idrac-max-workers", type=int, default=60)
        parser.add_argument("--idrac-refresh-days", type=int, default=30)
        parser.add_argument("--idrac-mode", choices=["auto", "direct"], default=os.getenv("IDRAC_MODE", "auto"))

        # OS info collection
        parser.add_argument("--os-info", action="store_true", help="Collect used_for/os_type/kernal_version via SSH to CES nodes.")
        parser.add_argument("--os-timeout", type=int, default=10)
        parser.add_argument("--os-max-workers", type=int, default=80)

    def handle(self, *args, **opts):
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        jump = os.getenv("JUMP_HOST", "")
        user = os.getenv("JUMP_USER", "")
        password = os.getenv("JUMP_PASSWORD", "")
        if not jump or not user or not password:
            raise CommandError("Missing JUMP_HOST/JUMP_USER/JUMP_PASSWORD in environment (.env).")

        timeout = opts["timeout"]
        dry = opts["dry_run"]
        disable_missing = opts["disable_missing"]
        host_domain = opts["host_domain"]

        do_idrac = opts["idrac"]
        idrac_user = opts["idrac_user"]
        idrac_password = opts["idrac_password"]
        idrac_timeout = opts["idrac_timeout"]
        idrac_workers = opts["idrac_max_workers"]
        idrac_refresh_days = opts["idrac_refresh_days"]
        idrac_mode = opts["idrac_mode"]

        do_osinfo = opts["os_info"]
        os_timeout = opts["os_timeout"]
        os_workers = opts["os_max_workers"]

        clusters_file = Path(__file__).resolve().parent / "gpfs_cluster.txt"
        if not clusters_file.exists():
            raise CommandError(f"gpfs_cluster.txt not found: {clusters_file}")

        clusters = [
            c.strip()
            for c in clusters_file.read_text().splitlines()
            if c.strip() and not c.strip().startswith("#")
        ]

        self.stdout.write(f"Clusters file: {clusters_file}")
        self.stdout.write(f"Jump: {user}@{jump}")
        self.stdout.write(f"Clusters: {', '.join(clusters)}")

        now = timezone.now()
        idrac_work: Dict[int, str] = {}
        osinfo_work: Dict[int, str] = {}

        for cluster in clusters:
            self.stdout.write(self.style.HTTP_INFO(f"\n=== GPFS Cluster: {cluster} ==="))

            check_cmd = "command -v mmces >/dev/null 2>&1 && echo MM_OK || echo MM_MISSING"
            check_out = run_on_cluster_as_root_via_jump(jump, user, password, cluster, check_cmd, timeout=timeout)
            if "SSH_ERROR" in check_out:
                self.stdout.write(self.style.ERROR(f"SSH failure while checking mmces on {cluster}: {check_out}"))
                continue
            if "MM_MISSING" in check_out or "mmces: command not found" in check_out.lower():
                self.stdout.write(self.style.ERROR(f"mmces not found on cluster {cluster} as root.\nOutput:\n{check_out.strip()}"))
                continue

            ces_out = run_on_cluster_as_root_via_jump(jump, user, password, cluster, CES_LIST_CMD, timeout=timeout)
            if "SSH_ERROR" in ces_out:
                self.stdout.write(self.style.ERROR(f"Failed to query CES on {cluster}: {ces_out}"))
                continue

            nodes = parse_ces_nodes(ces_out)
            self.stdout.write(self.style.SUCCESS(f"Found {len(nodes)} CES nodes"))

            if dry:
                for n in nodes[:10]:
                    host_fqdn = n if "." in n else (n + host_domain)
                    host_type = infer_host_type(host_fqdn)
                    self.stdout.write(f"  - {host_fqdn}  [{host_type}]")
                continue

            with transaction.atomic():
                cluster_obj, _ = HPCCluster.objects.get_or_create(name=cluster, defaults={"enabled": True})

                seen = set()
                for node in nodes:
                    host_fqdn = normalize_name(node if "." in node else (node + host_domain))
                    seen.add(host_fqdn)

                    host_type = infer_host_type(host_fqdn)
                    idrac_fqdn = idrac_from_host_fqdn(host_fqdn) if do_idrac else ""

                    self.stdout.write(f"  Upserting {host_fqdn}  type={host_type}")

                    obj, _ = Host.objects.update_or_create(
                        cluster=cluster_obj,
                        hostname=host_fqdn,
                        defaults={
                            "host_type": host_type,
                            "status": map_gpfs_to_inventory_status(),
                            "enabled": True,
                            "last_seen": now,
                            "idrac_host": idrac_fqdn or "",
                            "hw_model": "",
                        },
                    )

                    if do_idrac and idrac_fqdn:
                        # refresh iDRAC if missing any hw fields
                        if hasattr(obj, "last_hardware_refresh"):
                            needs_refresh = (
                                not obj.hw_model
                                or not obj.bios_version
                                or not obj.serialnumber
                                or not obj.asset_tag
                                or obj.last_hardware_refresh is None
                                or (now - obj.last_hardware_refresh).days >= idrac_refresh_days
                            )
                        else:
                            needs_refresh = True

                        if needs_refresh:
                            idrac_work[obj.id] = idrac_fqdn

                    if do_osinfo:
                        osinfo_work[obj.id] = host_fqdn

                if disable_missing:
                    Host.objects.filter(cluster=cluster_obj).exclude(hostname__in=seen).update(enabled=False)

        if dry:
            self.stdout.write(self.style.SUCCESS("\nDry-run complete (no DB writes)."))
            return

        # ────────────────────────────────────────────────
        # iDRAC enrichment
        # ────────────────────────────────────────────────
        if do_idrac:
            if not idrac_user or not idrac_password:
                self.stdout.write(self.style.WARNING("iDRAC requested but credentials missing. Skipping."))
            elif not idrac_work:
                self.stdout.write(self.style.SUCCESS("No CES nodes need hardware refresh."))
            else:
                items = list(idrac_work.items())
                self.stdout.write(self.style.SUCCESS(
                    f"Enriching {len(items)} CES nodes (mode={idrac_mode}, workers={idrac_workers}, timeout={idrac_timeout}s)"
                ))

                def fetch_one(item: Tuple[int, str]):
                    host_id, idrac_host = item
                    info = redfish_get_system_info_direct(
                        idrac_host=idrac_host,
                        user=idrac_user,
                        password=idrac_password,
                        timeout=idrac_timeout,
                        stdout=self.stdout,
                        style=self.style,
                    )
                    return host_id, info

                updated = 0
                failures = 0

                with ThreadPoolExecutor(max_workers=idrac_workers) as ex:
                    futures = [ex.submit(fetch_one, it) for it in items]
                    for f in as_completed(futures):
                        host_id, info = f.result()

                        if info.get("error"):
                            failures += 1
                            continue

                        update_data = {
                            "hw_model": info.get("model") or "",
                            "bios_version": info.get("bios"),
                            "serialnumber": info.get("serial"),
                            "asset_tag": info.get("asset_tag"),
                        }
                        if hasattr(Host, "last_hardware_refresh"):
                            update_data["last_hardware_refresh"] = now

                        Host.objects.filter(id=host_id).update(**update_data)
                        updated += 1

                self.stdout.write(self.style.SUCCESS(
                    f"iDRAC complete: updated={updated}, failures={failures}, skipped={len(items)-updated-failures}"
                ))

        # ────────────────────────────────────────────────
        # OS info enrichment
        # ────────────────────────────────────────────────
        if do_osinfo:
            if not osinfo_work:
                self.stdout.write(self.style.WARNING("OS info requested but no CES nodes were queued."))
            else:
                items = list(osinfo_work.items())
                self.stdout.write(self.style.SUCCESS(
                    f"Collecting OS info on {len(items)} CES nodes (workers={os_workers}, timeout={os_timeout}s)"
                ))

                def fetch_os(item: Tuple[int, str]):
                    host_id, host_fqdn = item

                    used_for_out = ssh_run(host_fqdn, user, password, "cat /etc/GMIT-HPC 2>/dev/null", timeout=os_timeout)
                    os_out = ssh_run(host_fqdn, user, password, "grep '^PRETTY_NAME' /etc/os-release 2>/dev/null", timeout=os_timeout)
                    kern_out = ssh_run(host_fqdn, user, password, "uname -r", timeout=os_timeout)

                    used_for = parse_used_for(used_for_out)
                    os_type = parse_pretty_name(os_out)
                    kernal = parse_single_line(kern_out)

                    return host_id, {"used_for": used_for, "os_type": os_type, "kernal_version": kernal}

                updated = 0
                failures = 0

                with ThreadPoolExecutor(max_workers=os_workers) as ex:
                    futures = [ex.submit(fetch_os, it) for it in items]
                    for f in as_completed(futures):
                        host_id, data = f.result()

                        update_data = {}
                        if data.get("used_for") is not None:
                            update_data["used_for"] = data["used_for"]
                        if data.get("os_type") is not None:
                            update_data["os_type"] = data["os_type"]
                        if data.get("kernal_version") is not None:
                            update_data["kernal_version"] = data["kernal_version"]

                        if not update_data:
                            failures += 1
                            continue

                        Host.objects.filter(id=host_id).update(**update_data)
                        updated += 1

                self.stdout.write(self.style.SUCCESS(
                    f"OS info complete: updated={updated}, failures={failures}, skipped={len(items)-updated-failures}"
                ))

        self.stdout.write(self.style.SUCCESS("\nGPFS CES + Redfish + OS info sync complete"))