import os
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Optional, Dict

import paramiko
import requests
from urllib3.exceptions import InsecureRequestWarning

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from inventory.models import HPCCluster, Host, HostStatus


# -----------------------------
# SSH helper (PASSWORD auth) - ROBUST TIMEOUT FIX
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
# Parsers
# -----------------------------
def parse_lsclusters(text: str) -> List[Tuple[str, str]]:
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    items: List[Tuple[str, str]] = []
    for line in lines:
        if line.startswith("CLUSTER_NAME"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 3:
            continue
        items.append((parts[0], parts[2]))
    return items


def parse_bhosts(text: str) -> List[Tuple[str, str]]:
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    items: List[Tuple[str, str]] = []
    for line in lines:
        if line.startswith("HOST_NAME"):
            continue
        parts = re.split(r"\s+", line)
        if len(parts) < 2:
            continue
        items.append((parts[0], parts[1]))
    return items


# -----------------------------
# FQDN normalization helpers
# -----------------------------
def normalize_name(name: str) -> str:
    return (name or "").strip().rstrip(".")


def normalize_master_host(master_raw: str, master_domain_suffix: str) -> str:
    m = normalize_name(master_raw)
    if not m:
        return m

    if m.endswith(".gm.com") or m.endswith(master_domain_suffix) or m.count(".") >= 2:
        return m

    if m.endswith(".edc"):
        return m + master_domain_suffix

    if "." not in m:
        return m + ".edc" + master_domain_suffix

    return m


def normalize_host_fqdn(host_raw: str, default_host_domain: str) -> str:
    h = normalize_name(host_raw)
    if not h:
        return h

    if h.endswith(".gm.com") or h.endswith(default_host_domain):
        return h

    if h.endswith(".edc"):
        suffix = default_host_domain
        if suffix.startswith(".edc"):
            suffix = suffix[len(".edc"):]
        return h + suffix

    if "." not in h:
        return h + default_host_domain

    return h


# -----------------------------
# Host classification + status mapping
# -----------------------------
def infer_host_type(hostname: str) -> str:
    h = hostname.lower()
    if "viz" in h:
        return "viz"
    if "xp" in h:
        return "infra"
    return "compute"


def map_lsf_status_to_inventory(lsf_status: str) -> str:
    s = (lsf_status or "").lower()
    if s == "ok":
        return HostStatus.AVAILABLE
    if s == "closed":
        return HostStatus.CLOSED
    return HostStatus.UNAVAILABLE


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


def sh_quote(s: str) -> str:
    if s is None:
        s = ""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def get_nested(d: dict, path: List[str]) -> Optional[object]:
    cur: object = d
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


# -----------------------------
# Redfish helpers (Dell + Supermicro compatible)
# -----------------------------
def discover_system_id_direct(sess, base: str, timeout: int, stdout, style) -> str:
    """Auto-detect System ID (Dell: System.Embedded.1, Supermicro: 1, etc.)"""
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


def extract_serial_and_asset(system_json: dict) -> Tuple[Optional[str], Optional[str]]:
    """
    Policy:
      - Dell asset_tag = Oem.Dell.DellSystem.NodeID
      - Supermicro asset_tag = SerialNumber (AssetTag is often null)
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


def redfish_get_system_info_via_ssh(
    ssh_host: str,
    ssh_user: str,
    ssh_password: str,
    idrac_host: str,
    idrac_user: str,
    idrac_password: str,
    timeout: int,
    stdout,
    style,
) -> Dict[str, Optional[str]]:
    stdout.write(f"Attempting iDRAC via SSH ({ssh_host}) → {idrac_host}")

    disc_cmd = (
        "bash -lc "
        + repr(
            f"curl -k -sS --fail --max-time {timeout} "
            f"-u {sh_quote(idrac_user)}:{sh_quote(idrac_password)} "
            f"-H 'Accept: application/json' "
            f"https://{idrac_host}/redfish/v1/Systems "
            f"| python3 -c "
            f"'import sys,json; d=json.load(sys.stdin); "
            f"m=d.get(\"Members\",[]); "
            f"oid=m[0].get(\"@odata.id\",\"\") if m else \"\"; "
            f"print(oid.split(\"/\")[-1] if oid else \"1\")'"
        )
    )
    disc_out = ssh_run(ssh_host, ssh_user, ssh_password, disc_cmd, timeout=timeout + 10)
    system_id = disc_out.strip() or "1"
    if "SSH_ERROR" in disc_out:
        stdout.write(style.WARNING(f"  → SSH discovery failed: {disc_out}"))
        return {"name": None, "model": None, "bios": None, "serial": None, "asset_tag": None, "error": disc_out}
    stdout.write(style.SUCCESS(f"  → Discovered System ID: {system_id}"))

    cmd = (
        "bash -lc "
        + repr(
            f"curl -k -sS --fail --max-time {timeout} "
            f"-u {sh_quote(idrac_user)}:{sh_quote(idrac_password)} "
            f"-H 'Accept: application/json' "
            f"https://{idrac_host}/redfish/v1/Systems/{system_id}"
        )
    )
    out = ssh_run(ssh_host, ssh_user, ssh_password, cmd, timeout=timeout)

    if "SSH_ERROR" in out:
        stdout.write(style.WARNING(f"FAILED iDRAC via SSH {idrac_host} → {out}"))
        return {"name": None, "model": None, "bios": None, "serial": None, "asset_tag": None, "error": out}

    try:
        j = json.loads(out)
        model = j.get("Model")
        bios = j.get("BiosVersion")
        name = j.get("HostName") or j.get("DNSHostName") or j.get("Name")
        serial, asset_tag = extract_serial_and_asset(j)

        stdout.write(
            style.SUCCESS(
                f"Success iDRAC via SSH {idrac_host} → model={model or '—'}, bios={bios or '—'}, "
                f"serial={serial or '—'}, asset={asset_tag or '—'}"
            )
        )
        return {"name": name, "model": model, "bios": bios, "serial": serial, "asset_tag": asset_tag, "error": None}
    except Exception:
        snippet = (out or "")[:200].replace("\n", " ")
        err_msg = f"JSON parse failed. Snippet: {snippet}"
        stdout.write(style.WARNING(f"FAILED iDRAC via SSH {idrac_host} → {err_msg}"))
        return {"name": None, "model": None, "bios": None, "serial": None, "asset_tag": None, "error": err_msg}


# -----------------------------
# OS discovery over SSH to host
# -----------------------------
def parse_pretty_name(text: str) -> Optional[str]:
    # expected: PRETTY_NAME="Rocky Linux 8.9 (Green Obsidian)"
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
    # /etc/GMIT-HPC may have multiple lines; store first non-empty line
    if not text or text.startswith("SSH_ERROR"):
        return None
    for line in text.splitlines():
        v = line.strip()
        if v:
            return v
    return None


class Command(BaseCommand):
    help = (
        "Sync HPC clusters+hosts from LSF; optionally enrich with iDRAC/Redfish model/BIOS + serialnumber/asset_tag "
        "(Dell NodeID, Supermicro SerialNumber). Also collects used_for/os_type/kernal_version via SSH to hosts."
    )

    def add_arguments(self, parser):
        parser.add_argument("--jump", required=True)
        parser.add_argument("--user", required=True)
        parser.add_argument("--password", required=True)
        parser.add_argument("--timeout", type=int, default=30)
        parser.add_argument("--dry-run", action="store_true")
        parser.add_argument("--disable-missing", action="store_true")
        parser.add_argument("--use-login-shell", action="store_true", default=True)

        parser.add_argument("--master-domain", default=os.getenv("LSF_MASTER_DOMAIN", ".nam.gm.com"))
        parser.add_argument("--host-domain", default=os.getenv("LSF_HOST_DOMAIN", ".edc.nam.gm.com"))

        # iDRAC / Redfish
        parser.add_argument("--idrac", action="store_true")
        parser.add_argument("--idrac-user", default=os.getenv("IDRAC_USER", ""))
        parser.add_argument("--idrac-password", default=os.getenv("IDRAC_PASSWORD", ""))
        parser.add_argument("--idrac-timeout", type=int, default=4)
        parser.add_argument("--idrac-max-workers", type=int, default=60)
        parser.add_argument("--idrac-refresh-days", type=int, default=30)
        parser.add_argument("--idrac-mode", choices=["auto", "direct", "ssh"], default=os.getenv("IDRAC_MODE", "auto"))

        # OS info collection
        parser.add_argument("--os-info", action="store_true", help="Collect used_for/os_type/kernal_version via SSH to hosts.")
        parser.add_argument("--os-timeout", type=int, default=10)
        parser.add_argument("--os-max-workers", type=int, default=120)

    def handle(self, *args, **opts):
        # Silence insecure warnings (verify=False)
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        jump = opts["jump"]
        user = opts["user"]
        password = opts["password"]
        timeout = opts["timeout"]
        dry = opts["dry_run"]
        disable_missing = opts["disable_missing"]
        use_login_shell = opts["use_login_shell"]
        master_domain = opts["master_domain"]
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

        def wrap(cmd: str) -> str:
            return f"bash -lc '{cmd}'" if use_login_shell else cmd

        self.stdout.write(f"Connecting to jump host: {jump} as {user}")

        raw_clusters = ssh_run(jump, user, password, wrap("lsclusters"), timeout=timeout)
        clusters = parse_lsclusters(raw_clusters)
        self.stdout.write(self.style.SUCCESS(f"Found {len(clusters)} clusters"))

        # host_id -> (idrac_fqdn, master)
        idrac_work: Dict[int, Tuple[str, str]] = {}

        # host_id -> host_fqdn (for OS info)
        osinfo_work: Dict[int, str] = {}

        now = timezone.now()
        warned_about_missing_field = False

        for cluster_name, master_raw in clusters:
            master = normalize_master_host(master_raw, master_domain)
            self.stdout.write(f"\nCluster={cluster_name} master={master} (raw={master_raw})")

            raw_hosts = ssh_run(master, user, password, wrap("bhosts"), timeout=timeout)
            if "SSH_ERROR" in raw_hosts:
                self.stdout.write(self.style.WARNING(f"  SKIP: cannot SSH to master {master}: {raw_hosts}"))
                continue

            host_rows = parse_bhosts(raw_hosts)
            self.stdout.write(f"  Hosts returned: {len(host_rows)}")

            if dry:
                if host_rows:
                    sample_raw = host_rows[0][0]
                    sample_fqdn = normalize_host_fqdn(sample_raw, host_domain)
                    self.stdout.write(f"  Sample FQDN: {sample_raw} → {sample_fqdn}")
                    self.stdout.write(f"  Sample iDRAC: {idrac_from_host_fqdn(sample_fqdn)}")
                continue

            with transaction.atomic():
                cluster_obj, _ = HPCCluster.objects.get_or_create(
                    name=cluster_name,
                    defaults={"enabled": True},
                )

                seen = set()
                for host_raw, lsf_status in host_rows:
                    host_fqdn = normalize_host_fqdn(host_raw, host_domain)
                    seen.add(host_fqdn)

                    host_type = infer_host_type(host_fqdn)
                    status = map_lsf_status_to_inventory(lsf_status)

                    idrac_fqdn = idrac_from_host_fqdn(host_fqdn) if do_idrac else ""

                    # NOTE: your Host model has required fields; set safe defaults
                    obj, _ = Host.objects.update_or_create(
                        cluster=cluster_obj,
                        hostname=host_fqdn,
                        defaults={
                            "host_type": host_type,
                            "status": status,
                            "enabled": True,
                            "last_seen": now,
                            "idrac_host": idrac_fqdn or "",
                            "hw_model": "",  # filled by iDRAC
                        },
                    )

                    if do_idrac and idrac_fqdn:
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
                            if not warned_about_missing_field:
                                self.stdout.write(self.style.WARNING(
                                    "⚠️  last_hardware_refresh field not found in Host model. "
                                    "Refreshing ALL iDRAC data this run (add the field + migrate for smart caching)."
                                ))
                                warned_about_missing_field = True

                        if needs_refresh:
                            idrac_work[obj.id] = (idrac_fqdn, master)

                    if do_osinfo:
                        # Always attempt OS info collection; it will skip if SSH fails
                        osinfo_work[obj.id] = host_fqdn

                if disable_missing:
                    Host.objects.filter(cluster=cluster_obj).exclude(hostname__in=seen).update(enabled=False)

        if dry:
            self.stdout.write(self.style.SUCCESS("\nDry-run complete (no DB writes)."))
            return

        # ────────────────────────────────────────────────
        # iDRAC / Redfish enrichment
        # ────────────────────────────────────────────────
        if do_idrac:
            if not idrac_user or not idrac_password:
                self.stdout.write(self.style.WARNING("iDRAC requested but credentials missing. Skipping."))
            elif not idrac_work:
                self.stdout.write(self.style.SUCCESS("No hosts need hardware refresh (all recent)."))
            else:
                work_items = [(hid, vals[0], vals[1]) for hid, vals in idrac_work.items()]
                self.stdout.write(self.style.SUCCESS(
                    f"Enriching {len(work_items)} hosts (mode={idrac_mode}, workers={idrac_workers}, timeout={idrac_timeout}s)"
                ))

                def fetch_one(item: Tuple[int, str, str]):
                    host_id, idrac_host, master = item

                    if idrac_mode in ("direct", "auto"):
                        info = redfish_get_system_info_direct(
                            idrac_host=idrac_host,
                            user=idrac_user,
                            password=idrac_password,
                            timeout=idrac_timeout,
                            stdout=self.stdout,
                            style=self.style,
                        )
                        if info.get("error") is None:
                            return host_id, idrac_host, info

                    if idrac_mode in ("ssh", "auto"):
                        info = redfish_get_system_info_via_ssh(
                            ssh_host=master,
                            ssh_user=user,
                            ssh_password=password,
                            idrac_host=idrac_host,
                            idrac_user=idrac_user,
                            idrac_password=idrac_password,
                            timeout=idrac_timeout,
                            stdout=self.stdout,
                            style=self.style,
                        )
                        return host_id, idrac_host, info

                    return host_id, idrac_host, {"error": "no valid fetch mode succeeded"}

                updated = 0
                failures = 0

                with ThreadPoolExecutor(max_workers=idrac_workers) as ex:
                    futures = [ex.submit(fetch_one, it) for it in work_items]
                    for f in as_completed(futures):
                        host_id, idrac_host, info = f.result()

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
                    f"iDRAC complete: updated={updated}, failures={failures}, skipped={len(work_items)-updated-failures}"
                ))

        # ────────────────────────────────────────────────
        # OS info enrichment (used_for / os_type / kernal_version)
        # ────────────────────────────────────────────────
        if do_osinfo:
            if not osinfo_work:
                self.stdout.write(self.style.WARNING("OS info requested but no hosts were queued."))
            else:
                items = list(osinfo_work.items())
                self.stdout.write(self.style.SUCCESS(
                    f"Collecting OS info on {len(items)} hosts (workers={os_workers}, timeout={os_timeout}s)"
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

                        # Only update fields we successfully got (avoid overwriting with None)
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

        self.stdout.write(self.style.SUCCESS("\nLSF + Redfish + OS info sync complete"))
