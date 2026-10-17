"""Issue #27 — HA/VIP (Keepalived) management (v1.7.0).

Standalone, DB-free renderer for a node's /etc/keepalived/keepalived.conf and the
HAProxy health-check script, plus Fernet at-rest encryption for the VRRP secret.

The router fetches DB rows and calls these pure functions; nothing here touches the
database or logs secrets. Trivially unit-testable (see tests/test_keepalived_config.py).
"""
from __future__ import annotations

import base64
import logging
import os
import re
from typing import List, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import SECRET_KEY

logger = logging.getLogger(__name__)

# Written into every file we manage so the agent can tell "ours" from a
# hand-maintained keepalived setup (ownership guard, B-3/T-2). Must match the
# string the agent greps for in linux_install.sh.
OWNERSHIP_MARKER = "# Managed by HAProxy OpenManager"
CHECK_SCRIPT_PATH = "/etc/keepalived/check_haproxy.sh"


# ---------------------------------------------------------------------------
# VRRP secret at rest (mirrors backend/services/mfa_service.py)
# ---------------------------------------------------------------------------
_fernet_instance: Optional[Fernet] = None


def _resolve_fernet_key() -> bytes:
    """Prefer an explicit VIP_ENCRYPTION_KEY; else derive from SECRET_KEY via HKDF
    with a versioned info string (so the secret survives restarts, like MFA)."""
    explicit = os.getenv("VIP_ENCRYPTION_KEY", "").strip()
    if explicit:
        try:
            Fernet(explicit.encode())
            return explicit.encode()
        except Exception as exc:  # noqa: BLE001
            logger.error("VIP_ENCRYPTION_KEY env var present but invalid: %s", exc)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"vip-vrrp-secret-v1")
    derived = hkdf.derive(SECRET_KEY.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        _fernet_instance = Fernet(_resolve_fernet_key())
    return _fernet_instance


def reset_fernet_for_tests() -> None:
    """Test-only hook to force re-resolution after env mutation."""
    global _fernet_instance
    _fernet_instance = None


def encrypt_vrrp_secret(secret_plain: str) -> str:
    return _get_fernet().encrypt(secret_plain.encode("utf-8")).decode("utf-8")


def decrypt_vrrp_secret(secret_encrypted: str) -> Optional[str]:
    try:
        return _get_fernet().decrypt(secret_encrypted.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.warning("Failed to decrypt VRRP secret (invalid Fernet token)")
        return None
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error decrypting VRRP secret: %s", exc)
        return None


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def build_haproxy_check_script(*, bin_path: Optional[str] = None,
                               config_path: Optional[str] = None) -> str:
    """Render the health-check the agent writes to CHECK_SCRIPT_PATH.

    Derives the process name from the HAProxy binary basename (B-4) rather than a
    blind hardcoded 'haproxy'. Returns non-zero when HAProxy isn't running so the
    VRRP track_script lowers this node's priority and the VIP fails over.
    """
    proc = "haproxy"
    if bin_path:
        base = os.path.basename(bin_path.strip())
        if re.match(r'^[A-Za-z0-9._-]{1,64}$', base):
            proc = base
    return (
        "#!/bin/sh\n"
        f"{OWNERSHIP_MARKER} — DO NOT EDIT\n"
        "# Exits 0 while HAProxy is up; non-zero triggers VRRP failover.\n"
        f"pidof {proc} >/dev/null 2>&1 || exit 1\n"
        "exit 0\n"
    )


def _vrrp_instance_name(vip_id: int) -> str:
    return f"VI_{int(vip_id)}"


def _failover_weight(members: List[dict]) -> int:
    """Negative weight so a failed MASTER drops strictly below every healthy BACKUP
    (B-6). master_priority + weight < min(backup_priority)."""
    master = next((m for m in members if str(m.get("role", "")).upper() == "MASTER"), None)
    backups = [int(m["priority"]) for m in members if str(m.get("role", "")).upper() != "MASTER"]
    if not master or not backups:
        return -20
    return -((int(master["priority"]) - min(backups)) + 1)


def render_keepalived_conf(*, vip: dict, members: List[dict], this_agent: dict,
                           peer_ips: List[str], auth_pass_plain: Optional[str]) -> str:
    """Render one node's keepalived.conf from the VIP + member rows.

    `vip` keys: id, name, virtual_ip, prefix_length, virtual_router_id, advert_int,
                use_unicast, track_haproxy.
    `this_agent` keys: role, priority, network_interface, ip_address (str).
    `peer_ips`: the OTHER members' ip_address strings (already str()'d by the caller).
    Caller must never log the returned string (it may contain auth_pass).
    """
    role = str(this_agent["role"]).upper()
    iface = this_agent["network_interface"]
    prio = int(this_agent["priority"])
    track = bool(vip.get("track_haproxy", True))
    use_unicast = bool(vip.get("use_unicast", True))
    vrid = int(vip["virtual_router_id"])
    advert = int(vip.get("advert_int", 1))
    name = str(vip.get("name", ""))
    inst = _vrrp_instance_name(vip["id"])

    lines: List[str] = []
    lines.append(f"{OWNERSHIP_MARKER} — DO NOT EDIT")
    lines.append(f'# VIP "{name}" (id={vip["id"]}) — role {role}')
    lines.append("global_defs {")
    lines.append("    enable_script_security")
    lines.append("    script_user root")
    lines.append("}")
    lines.append("")

    if track:
        weight = _failover_weight(members)
        lines.append("vrrp_script chk_haproxy {")
        lines.append(f'    script "{CHECK_SCRIPT_PATH}"')
        lines.append("    interval 2")
        lines.append("    fall 2")
        lines.append("    rise 2")
        lines.append(f"    weight {weight}")
        lines.append("}")
        lines.append("")

    lines.append(f"vrrp_instance {inst} {{")
    lines.append(f"    state {role}")
    lines.append(f"    interface {iface}")
    lines.append(f"    virtual_router_id {vrid}")
    lines.append(f"    priority {prio}")
    lines.append(f"    advert_int {advert}")
    if auth_pass_plain:
        lines.append("    authentication {")
        lines.append("        auth_type PASS")
        lines.append(f"        auth_pass {auth_pass_plain}")
        lines.append("    }")
    # Unicast only makes sense with at least one peer. For a single-node VIP (no peers)
    # we deliberately omit the unicast block: keepalived treats a bare `unicast_src_ip`
    # with no `unicast_peer` as deprecated, warns, and silently falls back to multicast —
    # and `keepalived -t` flags it. Omitting it yields a clean multicast config that holds
    # the VIP with no peer to talk to. Multi-node behaviour (peers present) is unchanged.
    if use_unicast and peer_ips:
        src = this_agent.get("ip_address")
        if src:
            lines.append(f"    unicast_src_ip {src}")
        lines.append("    unicast_peer {")
        for p in peer_ips:
            lines.append(f"        {p}")
        lines.append("    }")
    lines.append("    virtual_ipaddress {")
    lines.append(f'        {vip["virtual_ip"]}/{int(vip.get("prefix_length", 24))} dev {iface}')
    for extra in vip.get("additional_ips") or []:
        lines.append(f'        {extra["address"]}/{int(extra["prefix_length"])} dev {iface}')
    lines.append("    }")
    if track:
        lines.append("    track_script {")
        lines.append("        chk_haproxy")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Issue #73 — several VIPs on one node
# ---------------------------------------------------------------------------
# A node deploys ONE keepalived.conf, and each member row stores the full single-VIP file
# render_keepalived_conf produced at apply time. A node that belongs to several VIPs gets
# those applied files merged into one: global_defs once, then every VIP's vrrp_script and
# vrrp_instance. The health-check script is renamed per VIP (chk_haproxy_<id>) because each
# VIP's failover weight is derived from its own priorities, and keepalived needs unique
# script names. A node with a single VIP is served its applied file unchanged.
class KeepalivedComposeError(ValueError):
    """An applied snapshot is not in the shape render_keepalived_conf produces."""


def _top_level_blocks(conf: str) -> List[tuple]:
    """Split our own render into (name, lines) top-level blocks; comment lines are skipped."""
    blocks: List[tuple] = []
    current: Optional[List[str]] = None
    depth = 0
    for line in conf.split("\n"):
        stripped = line.strip()
        if current is None:
            if not stripped or stripped.startswith("#"):
                continue
            if not stripped.endswith("{"):
                raise KeepalivedComposeError(f"unexpected top-level line: {stripped[:60]}")
            current = [line]
            depth = 1
            continue
        current.append(line)
        if stripped.startswith("auth_pass "):
            continue  # the secret may contain braces; it is a single token, never a block
        depth += stripped.count("{") - stripped.count("}")
        if depth == 0:
            blocks.append((" ".join(current[0].strip().rstrip("{").split()), current))
            current = None
        elif depth < 0:
            raise KeepalivedComposeError("unbalanced braces")
    if current is not None:
        raise KeepalivedComposeError("unterminated block")
    return blocks


def compose_node_keepalived_conf(applied: List[tuple]) -> str:
    """Merge the applied single-VIP files of one node into the file the node deploys.

    `applied` is [(vip_id, applied_config_content), ...]. One entry is returned unchanged,
    so nodes with a single VIP keep the exact bytes (and hash) they already run. Raises
    KeepalivedComposeError when a snapshot does not have the expected shape; the caller
    must then leave the node alone rather than deploy a partial file.
    """
    if not applied:
        raise KeepalivedComposeError("nothing to compose")
    if len(applied) == 1:
        return applied[0][1]

    header: List[str] = [f"{OWNERSHIP_MARKER} — DO NOT EDIT"]
    global_defs: Optional[List[str]] = None
    scripts: List[str] = []
    instances: List[str] = []
    for vip_id, conf in sorted(applied, key=lambda item: int(item[0])):
        vip_id = int(vip_id)
        for line in (conf or "").split("\n"):
            if line.startswith("# VIP "):
                header.append(line)
        blocks = _top_level_blocks(conf or "")
        names = [name for name, _ in blocks]
        if names.count("global_defs") != 1 or names.count(f"vrrp_instance {_vrrp_instance_name(vip_id)}") != 1:
            raise KeepalivedComposeError(f"VIP {vip_id}: applied config has an unexpected layout")
        if any(n not in ("global_defs", "vrrp_script chk_haproxy", f"vrrp_instance {_vrrp_instance_name(vip_id)}")
               for n in names):
            raise KeepalivedComposeError(f"VIP {vip_id}: applied config has an unexpected block")
        script_name = f"chk_haproxy_{vip_id}"
        for name, body in blocks:
            if name == "global_defs":
                if global_defs is None:
                    global_defs = body
            elif name == "vrrp_script chk_haproxy":
                scripts.append("\n".join([f"vrrp_script {script_name} {{"] + body[1:]))
            else:
                renamed, in_track = [], False
                for line in body:
                    s = line.strip()
                    if s == "track_script {":
                        in_track = True
                    elif in_track and s == "}":
                        in_track = False
                    elif in_track and s == "chk_haproxy":
                        line = line.replace("chk_haproxy", script_name)
                    renamed.append(line)
                instances.append("\n".join(renamed))

    out: List[str] = header + global_defs + [""]
    for block in scripts:
        out.extend([block, ""])
    out.append("\n\n".join(instances))
    return "\n".join(out) + "\n"
