# inventory/management/commands/sync_hosts_from_file.py
"""
Sync hosts from a plain-text file into the inventory DB, then optionally
enrich each host with hardware info (via Redfish/iDRAC) and/or OS info
(via direct SSH).

File format – one entry per line, everything after '#' is a comment:

    # optional comment
    hostname-or-fqdn [host_type]

    dcwipphces01.edc.nam.gm.com  ces
    dcwixphhpc01.edc.nam.gm.com  storage-infra
    somehost                      # type will be inferred if omitted

Usage examples
--------------
    # basic upsert only
    python manage.py sync_hosts_from_file --hosts-file hosts.txt

    # upsert + iDRAC hardware enrichment
    python manage.py sync_hosts_from_file --hosts-file hosts.txt --idrac

    # force re-query iDRAC even when data already exists
    python manage.py sync_hosts_from_file --hosts-file hosts.txt --idrac --force-idrac

    # upsert + OS info via SSH
    python manage.py sync_hosts_from_file --hosts-file hosts.txt --os-info

    # everything, dry-run (shows iDRAC addresses without writing to DB)
    python manage.py sync_hosts_from_file --hosts-file hosts.txt --idrac --os-info --dry-run

Environment variables
---------------------
    JUMP_HOST               – jump / bastion hostname
    JUMP_USER / JUMP_PASSWORD   – SSH credentials (used for all hops)
    IDRAC_USER / IDRAC_PASSWORD – Redfish credentials
    GPFS_HOST_DOMAIN            – default domain appended to bare hostnames
    EPG_GATEWAY             – intermediate gateway used for .epg.nam.gm.com hosts
                              (default: dcmixphhpc009.epg.nam.gm.com)
    EPG_DOMAIN              – domain suffix that triggers gateway routing
                              (default: .epg.nam.gm.com)
"""

import os
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

import json
import logging
import threading

import paramiko
import requests
from urllib3.exceptions import InsecureRequestWarning

# Silence paramiko's internal transport-level noise (banner errors, etc.)
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from inventory.models import HPCCluster, Host, HostStatus


# ---------------------------------------------------------------------------
# SSH helpers
# ---------------------------------------------------------------------------

def ssh_run(host: str, username: str, password: str, cmd: str, timeout: int = 60) -> str:
    """Direct SSH: execute *cmd* on *host* and return combined stdout+stderr."""
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
    except Exception as exc:
        try:
            client.close()
        except Exception:
            pass
        return f"SSH_ERROR: {type(exc).__name__}: {exc}"


def _sh_quote(s: str) -> str:
    """Shell-safe single-quote a string."""
    return "'" + (s or "").replace("'", "'\"'\"'") + "'"


def ssh_run_via_gateway(
    jump_host: str,
    username: str,
    password: str,
    gateway: str,
    target: str,
    cmd: str,
    timeout: int = 60,
) -> str:
    """
    Three-hop execution for .epg.nam.gm.com hosts:

        local  --SSH-->  jump_host  --sudo su / SSH-->  gateway  --SSH-->  target

    Steps:
      1. SSH to jump_host as *username*
      2. sudo to root on jump_host
      3. SSH from jump_host to *gateway* (no host-key checking)
      4. SSH from *gateway* to *target* and run *cmd*
    """
    # Build the innermost command: ssh from gateway to target
    inner = (
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o ConnectTimeout={timeout} "
        f"{username}@{target} {_sh_quote(cmd)}"
    )
    # Wrap it to run on the gateway via ssh
    via_gateway = (
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o ConnectTimeout={timeout} "
        f"root@{gateway} {_sh_quote(inner)}"
    )
    # Wrap with sudo on the jump host
    jump_side = f"sudo -S -p '' {via_gateway}"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=jump_host,
            username=username,
            password=password,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        stdin, stdout, stderr = client.exec_command(jump_side, timeout=timeout, get_pty=True)
        # Feed sudo password
        stdin.write(password + "\n")
        stdin.flush()
        stdout.channel.settimeout(timeout)
        stderr.channel.settimeout(timeout)
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        client.close()
        if err.strip():
            out = out + "\n" + err
        return out
    except Exception as exc:
        try:
            client.close()
        except Exception:
            pass
        return f"SSH_ERROR: {type(exc).__name__}: {exc}"


def ssh_run_for_host(
    host_fqdn: str,
    username: str,
    password: str,
    cmd: str,
    timeout: int = 60,
    jump_host: str = "",
    epg_gateway: str = "",
    epg_domain: str = ".epg.nam.gm.com",
) -> str:
    """
    Route SSH to the correct path based on the host's domain:

    - *.epg.nam.gm.com  →  jump_host → (sudo root) → epg_gateway → host
    - everything else   →  direct SSH to host
    """
    if host_fqdn.lower().endswith(epg_domain.lower()) and jump_host and epg_gateway:
        return ssh_run_via_gateway(
            jump_host=jump_host,
            username=username,
            password=password,
            gateway=epg_gateway,
            target=host_fqdn,
            cmd=cmd,
            timeout=timeout,
        )
    return ssh_run(host_fqdn, username, password, cmd, timeout=timeout)


# ---------------------------------------------------------------------------
# Gateway-tunnelled iDRAC helpers (for .epg.nam.gm.com)
# ---------------------------------------------------------------------------

def _open_gateway_client(
    jump_host: str,
    username: str,
    password: str,
    gateway: str,
    timeout: int,
) -> paramiko.SSHClient:
    """
    Open ONE persistent SSH connection:
        local -> jump_host (sudo -S) -> gateway

    Returns a live paramiko SSHClient connected to the gateway.
    Caller is responsible for calling .close() when done.

    All curl calls for one iDRAC host reuse this single connection,
    avoiding the MaxStartups / connection-reset problem caused by
    opening a new connection for every request.
    """
    # Build: sudo ssh jump -> gateway, staying open as a tunnel
    jump_cmd = (
        "sudo -S -p '' "
        "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-o ConnectTimeout={timeout} "
        f"root@{gateway}"
    )

    # Step 1: connect to jump host
    jump_client = paramiko.SSHClient()
    jump_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    jump_client.connect(
        hostname=jump_host,
        username=username,
        password=password,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )

    # Step 2: open a direct-tcpip channel from jump to gateway port 22
    transport = jump_client.get_transport()
    gw_channel = transport.open_channel(
        "direct-tcpip",
        (gateway, 22),
        ("127.0.0.1", 0),
        timeout=timeout,
    )

    # Step 3: connect a second client over that channel (lands on gateway)
    gw_client = paramiko.SSHClient()
    gw_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    gw_client.connect(
        hostname=gateway,
        username="root",
        password=password,
        sock=gw_channel,
        timeout=timeout,
        banner_timeout=timeout,
        auth_timeout=timeout,
        look_for_keys=False,
        allow_agent=False,
    )

    # Attach jump_client so the caller can close both
    gw_client._jump_client = jump_client  # type: ignore[attr-defined]
    return gw_client


def _exec_on_client(client: paramiko.SSHClient, cmd: str, timeout: int) -> str:
    """Run *cmd* on an already-connected paramiko client; return combined output."""
    stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    stdout.channel.settimeout(timeout)
    stderr.channel.settimeout(timeout)
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    if err.strip():
        out = out + "\n" + err
    return out


def _close_gateway_client(client: paramiko.SSHClient) -> None:
    """Close gateway client and its underlying jump connection."""
    try:
        client.close()
    except Exception:
        pass
    jump = getattr(client, "_jump_client", None)
    if jump:
        try:
            jump.close()
        except Exception:
            pass


def _parse_curl_json(raw: str, idrac_host: str, path: str, warn) -> Optional[dict]:
    """
    Extract JSON from curl output, skipping any SSH banner lines.
    Handles HTTP->HTTPS redirect pages (XML/HTML) gracefully.
    """
    if not raw or raw.startswith("SSH_ERROR"):
        warn(f"[iDRAC] SSH error for {idrac_host}{path}: {raw[:120]}")
        return None

    # Walk lines looking for a JSON object (skips sudo password echo, banners)
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                pass

    # Try the whole output as one JSON blob
    stripped = raw.strip()
    if stripped.startswith("{"):
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass

    # HTML/XML redirect page — not an error worth logging verbosely
    if stripped.startswith("<"):
        warn(f"[iDRAC] {idrac_host}{path} returned HTML/XML (possible HTTP redirect or auth page)")
        return None

    if stripped:
        warn(f"[iDRAC] Unexpected response from {idrac_host}{path}: {stripped[:120]}")
    return None


def redfish_get_system_info_via_gateway(
    idrac_host: str,
    idrac_user: str,
    idrac_password: str,
    timeout: int,
    jump_host: str,
    gateway: str,
    ssh_user: str,
    ssh_password: str,
    log,
    warn,
    ok,
    sem: Optional[threading.Semaphore] = None,
) -> Dict[str, Optional[str]]:
    """
    Query Redfish by running curl ON the gateway over ONE persistent SSH connection.

    Path:  local --paramiko--> jump_host --tcpip-channel--> gateway --curl--> idrac_host

    ONE connection is opened for the entire iDRAC host query (all endpoints).
    *sem* is a threading.Semaphore that caps how many connections go through the
    jump host simultaneously, preventing MaxStartups rejections.
    """
    log(f"[iDRAC] Connecting via gateway {gateway} -> {idrac_host}")

    # Acquire semaphore before opening the SSH connection (released in finally)
    if sem is not None:
        sem.acquire()

    # Open a single persistent connection to the gateway for this host
    try:
        gw_client = _open_gateway_client(jump_host, ssh_user, ssh_password, gateway, timeout + 15)
    except Exception as exc:
        if sem is not None:
            sem.release()
        warn(f"[iDRAC] Cannot open gateway connection for {idrac_host}: {exc}")
        return {"name": None, "model": None, "bios": None,
                "serial": None, "asset_tag": None, "error": str(exc)}

    try:
        def _curl(path: str) -> Optional[dict]:
            """Run curl on the gateway (reusing existing connection) and parse JSON."""
            curl_cmd = (
                f"curl -skL --max-time {timeout} "   # -L follows HTTP->HTTPS redirects
                f"-u {_sh_quote(idrac_user + ':' + idrac_password)} "
                f"-H 'Accept: application/json' "
                f"https://{idrac_host}{path}"
            )
            raw = _exec_on_client(gw_client, curl_cmd, timeout=timeout + 5)
            return _parse_curl_json(raw, idrac_host, path, warn)

        # Discover system ID via /redfish/v1/Systems
        systems_data = _curl("/redfish/v1/Systems")
        system_id = "System.Embedded.1"
        if systems_data:
            members = systems_data.get("Members", [])
            if members:
                sid = (members[0].get("@odata.id", "") or "").split("/")[-1]
                if sid:
                    log(f"  -> Discovered System ID: {sid}")
                    system_id = sid
                else:
                    log("  -> Falling back to System.Embedded.1")
        else:
            log("  -> Systems endpoint failed, falling back to System.Embedded.1")

        candidates = list(dict.fromkeys([
            f"/redfish/v1/Systems/{system_id}",
            "/redfish/v1/Systems/System.Embedded.1",
            "/redfish/v1/Systems/System.1",
            "/redfish/v1/Systems/1",
        ]))

        system_json = None
        for path in candidates:
            data = _curl(path)
            if not data:
                continue
            # Detect embedded 401
            error_code = str((data.get("error") or {}).get("code", ""))
            if "401" in error_code or "Unauthorized" in error_code:
                warn(f"[iDRAC] AUTH FAILED {idrac_host} -- check IDRAC_USER / IDRAC_PASSWORD")
                return {"name": None, "model": None, "bios": None,
                        "serial": None, "asset_tag": None, "error": "HTTP 401 Unauthorized"}
            if "Model" in data or "SerialNumber" in data:
                system_json = data
                log(f"  -> OK  endpoint={path}")
                break

        if not system_json:
            warn(f"[iDRAC] FAILED {idrac_host} -> no valid system data from any endpoint")
            return {"name": None, "model": None, "bios": None,
                    "serial": None, "asset_tag": None, "error": "No valid system data"}

        model = system_json.get("Model")
        name = (
            system_json.get("HostName")
            or system_json.get("DNSHostName")
            or system_json.get("Name")
        )
        bios = system_json.get("BiosVersion")

        if not bios:
            bios_link = (system_json.get("Bios") or {}).get("@odata.id")
            if bios_link:
                bios_data = _curl(bios_link)
                if bios_data:
                    bios = bios_data.get("Version") or bios_data.get("Name")

        serial, asset_tag = extract_serial_and_asset(system_json)

        ok(
            f"[iDRAC] SUCCESS {idrac_host} -> "
            f"model={model or '-'}, bios={bios or '-'}, "
            f"serial={serial or '-'}, asset={asset_tag or '-'}"
        )
        return {
            "name": name, "model": model, "bios": bios,
            "serial": serial, "asset_tag": asset_tag, "error": None,
        }

    finally:
        _close_gateway_client(gw_client)
        if sem is not None:
            sem.release()


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def normalize_name(name: str) -> str:
    return (name or "").strip().rstrip(".")


def infer_host_type(hostname: str) -> str:
    name = (hostname or "").lower()
    if "ces" in name:
        return "ces"
    if "xphhpc" in name:
        return "storage-infra"
    return "unknown"


def idrac_from_host_fqdn(host_fqdn: str) -> str:
    """Derive the iDRAC FQDN from the OS hostname by substituting ph -> rm."""
    hf = normalize_name(host_fqdn)
    if "." in hf:
        short, domain = hf.split(".", 1)
        return f"{short.replace('ph', 'rm')}.{domain}"
    return hf.replace("ph", "rm")


def host_needs_hw_refresh(obj, now, refresh_days: int) -> bool:
    """
    Decide whether to query iDRAC based on the host's CURRENT DB values.
    Returns True when any hardware field is empty or data is stale.
    """
    missing_any = (
        not getattr(obj, "hw_model", None)
        or not getattr(obj, "bios_version", None)
        or not getattr(obj, "serialnumber", None)
        or not getattr(obj, "asset_tag", None)
    )
    if missing_any:
        return True

    last_refresh = getattr(obj, "last_hardware_refresh", None)
    if last_refresh is None:
        return True

    return (now - last_refresh).days >= refresh_days


# ---------------------------------------------------------------------------
# Host-file parser
# ---------------------------------------------------------------------------

def parse_hosts_file(path: Path, default_domain: str) -> List[Dict[str, str]]:
    """
    Returns a list of dicts: {"fqdn": str, "host_type": str}

    Accepted line formats:
        hostname
        hostname  host_type
        hostname.domain.com
        hostname.domain.com  host_type
        # comment lines and blank lines are skipped
    """
    entries: List[Dict[str, str]] = []
    seen: set = set()

    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue

        parts = line.split()
        raw_host = normalize_name(parts[0])
        explicit_type = parts[1].strip() if len(parts) >= 2 else None

        fqdn = raw_host if "." in raw_host else (raw_host + default_domain)

        if fqdn in seen:
            continue
        seen.add(fqdn)

        host_type = explicit_type or infer_host_type(fqdn)
        entries.append({"fqdn": fqdn, "host_type": host_type})

    return entries


# ---------------------------------------------------------------------------
# Redfish / iDRAC
# ---------------------------------------------------------------------------

def get_nested(d: dict, path: List[str]) -> Optional[object]:
    cur: object = d
    for key in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(key)
    return cur


def extract_serial_and_asset(system_json: dict) -> Tuple[Optional[str], Optional[str]]:
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


def _discover_system_id(sess, base: str, timeout: int, log) -> str:
    try:
        r = sess.get(
            f"{base}/redfish/v1/Systems",
            timeout=timeout,
            headers={"Accept": "application/json"},
        )
        if r.status_code == 200:
            members = r.json().get("Members", [])
            if members:
                sid = (members[0].get("@odata.id", "") or "").split("/")[-1]
                if sid:
                    log(f"  -> Discovered System ID: {sid}")
                    return sid
    except Exception as exc:
        log(f"  -> System ID discovery error: {exc}")
    log("  -> Falling back to System.Embedded.1")
    return "System.Embedded.1"


def redfish_get_system_info(
    idrac_host: str,
    user: str,
    password: str,
    timeout: int,
    stdout,
    style,
) -> Dict[str, Optional[str]]:
    """
    Query the Redfish API on *idrac_host*.
    Returns dict with keys: name, model, bios, serial, asset_tag, error
    Signature matches sync_gpfs_ces_inventory for consistency.
    """
    log  = stdout.write
    warn = lambda m: stdout.write(style.WARNING(m))
    ok   = lambda m: stdout.write(style.SUCCESS(m))

    base = f"https://{idrac_host}"
    sess = requests.Session()
    sess.auth = (user, password)
    sess.verify = False
    sess.headers.update({"Accept": "application/json"})

    stdout.write(f"Attempting iDRAC direct -> {idrac_host}")

    system_id = _discover_system_id(sess, base, timeout, log)

    # Try discovered ID first, then common fallbacks
    candidates = list(dict.fromkeys([
        f"/redfish/v1/Systems/{system_id}",
        "/redfish/v1/Systems/System.Embedded.1",
        "/redfish/v1/Systems/System.1",
        "/redfish/v1/Systems/1",
    ]))

    system_json = None
    last_err = None
    for path in candidates:
        try:
            r = sess.get(
                base + path,
                timeout=timeout,
                headers={"Accept": "application/json"},
            )
            if r.status_code == 200:
                system_json = r.json()
                log(f"  -> OK  endpoint={path}")
                break
            elif r.status_code == 401:
                warn(f"[iDRAC] AUTH FAILED {idrac_host} -- check IDRAC_USER / IDRAC_PASSWORD")
                return {
                    "name": None, "model": None, "bios": None,
                    "serial": None, "asset_tag": None,
                    "error": "HTTP 401 Unauthorized",
                }
            else:
                last_err = f"HTTP {r.status_code} on {path}"
        except requests.exceptions.ConnectTimeout:
            last_err = f"Connection timed out after {timeout}s"
            break
        except requests.exceptions.ConnectionError as exc:
            last_err = f"Connection error: {exc}"
            break
        except Exception as exc:
            last_err = str(exc)

    if not system_json:
        warn(f"[iDRAC] FAILED {idrac_host} -> {last_err}")
        return {
            "name": None, "model": None, "bios": None,
            "serial": None, "asset_tag": None,
            "error": last_err,
        }

    model = system_json.get("Model")
    name = (
        system_json.get("HostName")
        or system_json.get("DNSHostName")
        or system_json.get("Name")
    )
    bios = system_json.get("BiosVersion")

    if not bios:
        bios_link = (system_json.get("Bios") or {}).get("@odata.id")
        if bios_link:
            try:
                rb = sess.get(
                    base + bios_link, timeout=timeout,
                    headers={"Accept": "application/json"},
                )
                if rb.status_code == 200:
                    bj = rb.json()
                    bios = bj.get("Version") or bj.get("Name")
            except Exception:
                pass

    serial, asset_tag = extract_serial_and_asset(system_json)

    ok(
        f"Success iDRAC direct {idrac_host} -> "
        f"model={model or '-'}, bios={bios or '-'}, "
        f"serial={serial or '-'}, asset={asset_tag or '-'}"
    )
    return {
        "name": name,
        "model": model,
        "bios": bios,
        "serial": serial,
        "asset_tag": asset_tag,
        "error": None,
    }


# ---------------------------------------------------------------------------
# OS info via SSH
# ---------------------------------------------------------------------------

def parse_pretty_name(text: str) -> Optional[str]:
    m = re.search(r'^PRETTY_NAME\s*=\s*"(.*)"\s*$', (text or "").strip(), flags=re.M)
    if m:
        return m.group(1).strip() or None
    m2 = re.search(r"^PRETTY_NAME\s*=\s*(.*)\s*$", (text or "").strip(), flags=re.M)
    if m2:
        return m2.group(1).strip().strip('"') or None
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


# ---------------------------------------------------------------------------
# Management command
# ---------------------------------------------------------------------------

class Command(BaseCommand):
    help = (
        "Upsert hosts from a flat file into the inventory DB, then optionally "
        "enrich with iDRAC hardware info (--idrac) and/or OS info (--os-info)."
    )

    # Default hosts file sits next to this management command, like gpfs_cluster.txt
    DEFAULT_HOSTS_FILE = Path(__file__).resolve().parent / "hosts.txt"

    def add_arguments(self, parser):
        parser.add_argument(
            "--hosts-file",
            default=str(self.DEFAULT_HOSTS_FILE),
            help=(
                "Path to the hosts file (one hostname/FQDN per line, optional host_type "
                "as second column). Defaults to the hosts.txt next to this command."
            ),
        )
        parser.add_argument(
            "--cluster",
            default=os.getenv("HOSTS_CLUSTER", "not-in-cluster"),
            help="HPCCluster name to associate hosts with (default: 'not-in-cluster').",
        )
        parser.add_argument(
            "--host-domain",
            default=os.getenv("GPFS_HOST_DOMAIN", ".edc.nam.gm.com"),
            help="Domain appended to bare hostnames that contain no dot.",
        )
        parser.add_argument("--timeout", type=int, default=30)
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Print what would happen without writing to the DB.",
        )
        parser.add_argument(
            "--disable-missing", action="store_true",
            help="Disable DB hosts in this cluster that are NOT in the file.",
        )

        # -- iDRAC ---------------------------------------------------------------
        idrac = parser.add_argument_group("iDRAC / Redfish hardware enrichment")
        idrac.add_argument(
            "--idrac", action="store_true",
            help="Query Redfish API to collect hw_model, bios_version, serialnumber, asset_tag.",
        )
        idrac.add_argument("--idrac-user",      default=os.getenv("IDRAC_USER", ""))
        idrac.add_argument("--idrac-password",   default=os.getenv("IDRAC_PASSWORD", ""))
        idrac.add_argument(
            "--idrac-timeout", type=int, default=4,
            help="Per-request HTTP timeout in seconds (default 4, matching original).",
        )
        idrac.add_argument("--idrac-max-workers", type=int, default=60)
        idrac.add_argument(
            "--idrac-refresh-days", type=int, default=30,
            help="Re-query iDRAC only when last_hardware_refresh is older than N days (default 30).",
        )
        idrac.add_argument(
            "--force-idrac", action="store_true",
            help="Query iDRAC for every host regardless of existing data or refresh age.",
        )

        # -- OS info -------------------------------------------------------------
        osinfo = parser.add_argument_group("OS info collection via direct SSH")
        osinfo.add_argument(
            "--os-info", action="store_true",
            help="Collect used_for / os_type / kernel_version via SSH.",
        )
        osinfo.add_argument("--os-timeout",      type=int, default=10)
        osinfo.add_argument("--os-max-workers",  type=int, default=80)

        # -- EPG routing ---------------------------------------------------------
        epg = parser.add_argument_group("EPG domain routing (.epg.nam.gm.com)")
        epg.add_argument(
            "--epg-gateway",
            default=os.getenv("EPG_GATEWAY", "dcmixphhpc009.epg.nam.gm.com"),
            help=(
                "Intermediate gateway SSH'd to from the jump host before reaching "
                ".epg.nam.gm.com targets. (default: dcmixphhpc009.epg.nam.gm.com)"
            ),
        )
        epg.add_argument(
            "--epg-domain",
            default=os.getenv("EPG_DOMAIN", ".epg.nam.gm.com"),
            help="Domain suffix that triggers the gateway routing (default: .epg.nam.gm.com).",
        )
        epg.add_argument(
            "--epg-idrac-workers",
            type=int,
            default=int(os.getenv("EPG_IDRAC_WORKERS", "3")),
            help=(
                "Max concurrent iDRAC gateway connections for EPG hosts. "
                "Keep low (3-5) to avoid hitting the jump host MaxStartups limit. "
                "(default: 3)"
            ),
        )

    # -------------------------------------------------------------------------

    def handle(self, *args, **opts):
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

        # -- Resolve hosts file --------------------------------------------------
        hosts_file = Path(opts["hosts_file"])
        if not hosts_file.is_absolute() and not hosts_file.exists():
            sibling = Path(__file__).resolve().parent / hosts_file
            if sibling.exists():
                hosts_file = sibling
        if not hosts_file.exists():
            raise CommandError(
                f"Hosts file not found: {hosts_file}\n"
                f"Tip: place hosts.txt next to this command at "
                f"{Path(__file__).resolve().parent / 'hosts.txt'}"
            )

        cluster_name    = opts["cluster"]
        host_domain     = opts["host_domain"]
        dry             = opts["dry_run"]
        disable_missing = opts["disable_missing"]

        do_idrac       = opts["idrac"]
        idrac_user     = opts["idrac_user"]
        idrac_password = opts["idrac_password"]
        idrac_timeout  = opts["idrac_timeout"]
        idrac_workers  = opts["idrac_max_workers"]
        idrac_refresh  = opts["idrac_refresh_days"]
        force_idrac    = opts["force_idrac"]

        do_osinfo  = opts["os_info"]
        os_timeout = opts["os_timeout"]
        os_workers = opts["os_max_workers"]

        jump_host        = os.getenv("JUMP_HOST", "")
        epg_gateway      = opts["epg_gateway"]
        epg_domain       = opts["epg_domain"]
        epg_idrac_workers = opts["epg_idrac_workers"]

        # Semaphore to cap concurrent SSH connections through the jump host
        # for EPG iDRAC queries. Prevents MaxStartups rejections.
        _epg_idrac_sem = threading.Semaphore(epg_idrac_workers)

        # -- Validate credentials UPFRONT so we fail fast -----------------------
        if do_idrac and not dry and not (idrac_user and idrac_password):
            raise CommandError(
                "--idrac requires credentials.\n"
                "Set IDRAC_USER and IDRAC_PASSWORD env vars, "
                "or pass --idrac-user / --idrac-password on the command line."
            )

        user     = os.getenv("JUMP_USER", "")
        password = os.getenv("JUMP_PASSWORD", "")
        if do_osinfo and not dry and not (user and password):
            raise CommandError(
                "--os-info requires SSH credentials.\n"
                "Set JUMP_USER and JUMP_PASSWORD env vars."
            )

        # -- Parse file ----------------------------------------------------------
        entries = parse_hosts_file(hosts_file, host_domain)
        if not entries:
            raise CommandError(f"No valid host entries found in {hosts_file}")

        self.stdout.write(f"Hosts file   : {hosts_file}  ({len(entries)} entries)")
        self.stdout.write(f"Cluster      : {cluster_name}")
        self.stdout.write(f"Dry-run      : {dry}")
        self.stdout.write(f"EPG gateway  : {epg_gateway}  (domain: {epg_domain})")
        self.stdout.write(f"EPG iDRAC workers: {epg_idrac_workers} (max concurrent gateway connections)")
        if do_idrac:
            self.stdout.write(f"iDRAC user   : {idrac_user}")
            self.stdout.write(f"iDRAC timeout: {idrac_timeout}s")
            self.stdout.write(f"Force iDRAC  : {force_idrac}")

        now = timezone.now()
        idrac_work:  Dict[int, str] = {}   # host_id -> idrac_fqdn
        osinfo_work: Dict[int, str] = {}   # host_id -> host_fqdn

        # -- Dry-run preview -----------------------------------------------------
        if dry:
            self.stdout.write(self.style.HTTP_INFO("\n[DRY-RUN] Hosts that would be upserted:"))
            for e in entries:
                idrac_fqdn = idrac_from_host_fqdn(e["fqdn"]) if do_idrac else "-"
                self.stdout.write(
                    f"  {e['fqdn']:<55} type={e['host_type']:<20} idrac={idrac_fqdn}"
                )
            self.stdout.write(self.style.SUCCESS(
                f"\nDry-run complete -- {len(entries)} host(s) listed, no DB writes."
            ))
            return

        # -- Upsert hosts --------------------------------------------------------
        #
        # KEY DESIGN DECISIONS:
        #   1. Fetch the existing record BEFORE saving so we read real hw field
        #      values for the iDRAC refresh decision, not the post-update state.
        #   2. Never include hw_model/bios_version/serialnumber/asset_tag in the
        #      sync update -- those fields are owned exclusively by the iDRAC step.
        #
        with transaction.atomic():
            cluster_obj, created = HPCCluster.objects.get_or_create(
                name=cluster_name,
                defaults={"enabled": True},
            )
            if created:
                self.stdout.write(self.style.SUCCESS(f"Created new cluster: {cluster_name}"))

            seen_fqdns: set = set()

            # Pre-fetch ALL existing FQDNs across every cluster in one query.
            # The unique constraint on hostname is global (not per-cluster),
            # so we must check the entire table to avoid IntegrityError.
            existing_fqdns: set = set(
                Host.objects.values_list("hostname", flat=True)
            )

            skipped_existing = 0
            for e in entries:
                fqdn      = e["fqdn"]
                host_type = e["host_type"]
                seen_fqdns.add(fqdn)

                # Skip hosts that already exist in the DB (match on full FQDN)
                if fqdn in existing_fqdns:
                    self.stdout.write(f"  Skipped  {fqdn}  (already exists in DB)")
                    skipped_existing += 1

                    # Still queue existing hosts for iDRAC / OS enrichment if requested
                    existing_obj = Host.objects.filter(cluster=cluster_obj, hostname=fqdn).first()
                    if existing_obj:
                        if do_idrac:
                            idrac_fqdn = idrac_from_host_fqdn(fqdn)
                            if idrac_fqdn:
                                if force_idrac:
                                    needs_refresh = True
                                else:
                                    needs_refresh = host_needs_hw_refresh(existing_obj, now, idrac_refresh)
                                if needs_refresh:
                                    idrac_work[existing_obj.id] = idrac_fqdn
                        if do_osinfo:
                            osinfo_work[existing_obj.id] = fqdn
                    continue

                idrac_fqdn = idrac_from_host_fqdn(fqdn) if do_idrac else ""

                # Create new host
                obj = Host.objects.create(
                    cluster=cluster_obj,
                    hostname=fqdn,
                    hw_model="",
                    host_type=host_type,
                    status=HostStatus.AVAILABLE,
                    enabled=True,
                    last_seen=now,
                    idrac_host=idrac_fqdn or "",
                )
                self.stdout.write(self.style.SUCCESS(f"  Created  {fqdn}  type={host_type}"))

                # Queue new host for iDRAC enrichment
                if do_idrac and idrac_fqdn:
                    if force_idrac:
                        needs_refresh = True
                    else:
                        needs_refresh = host_needs_hw_refresh(obj, now, idrac_refresh)

                    if needs_refresh:
                        idrac_work[obj.id] = idrac_fqdn
                        self.stdout.write(f"    -> queued iDRAC: {idrac_fqdn}")
                    else:
                        self.stdout.write(
                            "    -> iDRAC skipped (data current). "
                            "Pass --force-idrac to re-query."
                        )

                if do_osinfo:
                    osinfo_work[obj.id] = fqdn

            if skipped_existing:
                self.stdout.write(self.style.WARNING(
                    f"Skipped {skipped_existing} host(s) already in DB "
                    f"(matched by FQDN). Use --disable-missing to audit removals."
                ))

            if disable_missing:
                disabled = (
                    Host.objects
                    .filter(cluster=cluster_obj)
                    .exclude(hostname__in=seen_fqdns)
                    .update(enabled=False)
                )
                self.stdout.write(self.style.WARNING(
                    f"Disabled {disabled} host(s) not present in the file."
                ))

        self.stdout.write(self.style.SUCCESS(
            f"\nUpserted {len(entries)} host(s) into cluster '{cluster_name}'."
        ))

        # -- iDRAC enrichment ----------------------------------------------------
        if do_idrac:
            if not idrac_work:
                self.stdout.write(self.style.WARNING(
                    "No hosts queued for iDRAC. "
                    "All data is current -- pass --force-idrac to re-query."
                ))
            else:
                self.stdout.write(self.style.HTTP_INFO(
                    f"\niDRAC enrichment: {len(idrac_work)} host(s), "
                    f"workers={idrac_workers}, timeout={idrac_timeout}s"
                ))

                def fetch_idrac(item: Tuple[int, str]):
                    host_id, idrac_host = item

                    _log  = self.stdout.write
                    _warn = lambda m: self.stdout.write(self.style.WARNING(m))
                    _ok   = lambda m: self.stdout.write(self.style.SUCCESS(m))

                    # EPG iDRAC hosts are not directly reachable; curl via gateway
                    if idrac_host.lower().endswith(epg_domain.lower()) and jump_host and epg_gateway:
                        info = redfish_get_system_info_via_gateway(
                            idrac_host=idrac_host,
                            idrac_user=idrac_user,
                            idrac_password=idrac_password,
                            timeout=idrac_timeout,
                            jump_host=jump_host,
                            gateway=epg_gateway,
                            ssh_user=user,
                            ssh_password=password,
                            log=_log,
                            warn=_warn,
                            ok=_ok,
                            sem=_epg_idrac_sem,
                        )
                    else:
                        info = redfish_get_system_info(
                            idrac_host=idrac_host,
                            user=idrac_user,
                            password=idrac_password,
                            timeout=idrac_timeout,
                            stdout=self.stdout,
                            style=self.style,
                        )
                    return host_id, info

                updated = failures = 0
                with ThreadPoolExecutor(max_workers=idrac_workers) as ex:
                    futures = [ex.submit(fetch_idrac, it) for it in idrac_work.items()]
                    for fut in as_completed(futures):
                        host_id, info = fut.result()
                        if info.get("error"):
                            failures += 1
                            continue

                        # Only write fields that came back with an actual value
                        update_data: Dict = {}
                        if info.get("model"):
                            update_data["hw_model"] = info["model"]
                        if info.get("bios"):
                            update_data["bios_version"] = info["bios"]
                        if info.get("serial"):
                            update_data["serialnumber"] = info["serial"]
                        if info.get("asset_tag"):
                            update_data["asset_tag"] = info["asset_tag"]
                        if hasattr(Host, "last_hardware_refresh"):
                            update_data["last_hardware_refresh"] = now

                        if update_data:
                            Host.objects.filter(id=host_id).update(**update_data)
                            updated += 1
                        else:
                            self.stdout.write(self.style.WARNING(
                                f"[iDRAC] host_id={host_id} -- Redfish responded but all fields empty"
                            ))
                            failures += 1

                skipped = len(idrac_work) - updated - failures
                self.stdout.write(self.style.SUCCESS(
                    f"iDRAC done: updated={updated}, failures={failures}, skipped={skipped}"
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

                    def _run(cmd):
                        return ssh_run_for_host(
                            host_fqdn, user, password, cmd,
                            timeout=os_timeout,
                            jump_host=jump_host,
                            epg_gateway=epg_gateway,
                            epg_domain=epg_domain,
                        )

                    used_for_out = _run("cat /etc/GMIT-HPC 2>/dev/null")
                    os_out       = _run("grep '^PRETTY_NAME' /etc/os-release 2>/dev/null")
                    kern_out     = _run("uname -r")

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

        self.stdout.write(self.style.SUCCESS("\nSync complete."))
