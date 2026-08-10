"""Issue #27 follow-up — parse an EXISTING keepalived.conf so a hand-maintained VIP can be
adopted into OpenManager's model (v1.10.4).

Standalone and DB-free, like keepalived_config.py: the agent reports the file it found on a
node, this module turns it into the fields `vip_instances` / `vip_members` need, and the
adoption endpoint decides whether taking ownership is safe.

WHY A PARSER AND NOT THE HEARTBEAT. The heartbeat carries two keepalived facts —
`keepalive_state` (MASTER/BACKUP, best-effort from logs) and `keepalive_ip` (the first
address grepped out of `virtual_ipaddress`). Rendering a node's config needs eleven:
virtual_router_id, auth_pass, interface, priority, prefix_length, advert_int, unicast
peers, track_haproxy, role and the address itself. Guessing the missing ones is not a
cosmetic risk — a wrong VRID puts the nodes in two separate VRRP domains and a wrong
auth_pass makes them reject each other, and either way both nodes claim the VIP.

THE SAFETY CONTRACT. Adoption REPLACES the operator's file with our render, so anything in
their file that `render_keepalived_conf` cannot reproduce would be silently destroyed on
takeover — a `notify_master` failover hook, an LVS `virtual_server` section, a second
address in one instance, a sync group. Extracting the fields is the easy half; the half
that matters is `unsupported`, the list of directives we would drop. The caller must treat
a non-empty `unsupported` as a refusal to adopt, not a warning to log.

Secrets: a parsed instance carries `auth_pass` in cleartext because that is the only way to
re-render an identical config. NEVER log a parse result. Callers persist it through
`encrypt_vrrp_secret` and mask it in anything UI-facing, exactly as the VIP router already
does for `auth_pass` in version diffs.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Optional, Tuple

# Directives `render_keepalived_conf` emits, and therefore the only ones a takeover can
# reproduce. Anything else found in a vrrp_instance is reported in `unsupported`.
_SUPPORTED_INSTANCE_KEYS = {
    "state", "interface", "virtual_router_id", "priority", "advert_int",
    "authentication", "unicast_src_ip", "unicast_peer", "virtual_ipaddress", "track_script",
}
# Top-level blocks we can account for. `vrrp_script` is reproduced only when it is the
# check script we generate ourselves (see _classify_script).
_SUPPORTED_TOP_KEYS = {"global_defs", "vrrp_script", "vrrp_instance"}

# global_defs entries our render emits. An operator's file usually carries more (notification
# email, router_id, ...) and losing those is a real change, so they are reported too.
_SUPPORTED_GLOBAL_KEYS = {"enable_script_security", "script_user"}

_IDENT_RE = re.compile(r"^[A-Za-z0-9._:-]+$")


class KeepalivedParseError(ValueError):
    """The text is not a keepalived.conf we can reason about (unbalanced braces etc.)."""


# ---------------------------------------------------------------------------
# Tokenizer / block reader
# ---------------------------------------------------------------------------
def _strip_comment(line: str) -> str:
    """Drop a trailing comment. keepalived treats BOTH `#` and `!` as comment starters, and
    neither is meaningful inside the quoted script paths we care about, so a quote-aware
    scan is enough (a `#` inside quotes stays)."""
    out: List[str] = []
    quote: Optional[str] = None
    for ch in line:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            out.append(ch)
            continue
        if ch in ("#", "!"):
            break
        out.append(ch)
    return "".join(out)


def _split_tokens(line: str) -> List[str]:
    """Whitespace split that keeps quoted strings whole and isolates braces, so
    `virtual_ipaddress { 10.0.0.1/24 dev eth0 }` tokenizes the same as its multi-line form."""
    tokens: List[str] = []
    buf: List[str] = []
    quote: Optional[str] = None

    def flush() -> None:
        if buf:
            tokens.append("".join(buf))
            buf.clear()

    for ch in line:
        if quote:
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
            continue
        if ch in ('"', "'"):
            quote = ch
            continue
        if ch.isspace():
            flush()
        elif ch in ("{", "}"):
            flush()
            tokens.append(ch)
        else:
            buf.append(ch)
    flush()
    return tokens


def _read_blocks(text: str) -> List[Dict[str, Any]]:
    """Parse the file into nested entries.

    Each entry is either
      {"kind": "block", "name": str, "args": [str], "body": [entries], "line": int}
      {"kind": "line",  "tokens": [str], "line": int}

    Line boundaries matter: inside `virtual_ipaddress` and `unicast_peer` each line is one
    bare value, so a flat token stream could not tell two addresses apart.
    """
    root: List[Dict[str, Any]] = []
    stack: List[List[Dict[str, Any]]] = [root]
    # Blocks whose opening `{` we have seen, so a stray `}` can be reported with context.
    open_blocks: List[str] = []

    for lineno, raw in enumerate(text.splitlines(), start=1):
        pending: List[str] = []
        for tok in _split_tokens(_strip_comment(raw)):
            if tok == "{":
                name = pending[0] if pending else ""
                args = pending[1:]
                block = {"kind": "block", "name": name, "args": args, "body": [], "line": lineno}
                stack[-1].append(block)
                stack.append(block["body"])
                open_blocks.append(name)
                pending = []
            elif tok == "}":
                if pending:
                    stack[-1].append({"kind": "line", "tokens": pending, "line": lineno})
                    pending = []
                if len(stack) == 1:
                    raise KeepalivedParseError(f"unbalanced '}}' on line {lineno}")
                stack.pop()
                open_blocks.pop()
            else:
                pending.append(tok)
        if pending:
            stack[-1].append({"kind": "line", "tokens": pending, "line": lineno})

    if len(stack) != 1:
        raise KeepalivedParseError(f"unclosed block '{open_blocks[-1] or '?'}' at end of file")
    return root


# ---------------------------------------------------------------------------
# Interpretation
# ---------------------------------------------------------------------------
def _as_int(tokens: List[str]) -> Optional[int]:
    if len(tokens) < 2:
        return None
    try:
        return int(tokens[1])
    except (TypeError, ValueError):
        return None


def _parse_vip_entry(tokens: List[str]) -> Optional[Dict[str, Any]]:
    """One `virtual_ipaddress` line: `<addr>[/<prefix>] [dev <iface>] [label ...]`.

    Returns None when the first token is not an address — a shape we do not understand must
    surface as unsupported rather than be silently dropped.
    """
    spec = tokens[0]
    addr, _, prefix = spec.partition("/")
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return None
    entry: Dict[str, Any] = {
        "address": str(ip),
        "prefix_length": None,
        "dev": None,
        "extra": [],
    }
    if prefix:
        try:
            entry["prefix_length"] = int(prefix)
        except ValueError:
            return None
    rest = tokens[1:]
    i = 0
    while i < len(rest):
        if rest[i] == "dev" and i + 1 < len(rest):
            entry["dev"] = rest[i + 1]
            i += 2
            continue
        # `label`, `scope`, `brd`, ... — all real directives we do not render.
        entry["extra"].append(rest[i])
        i += 1
    return entry


def _classify_script(block: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """Return (name, script_path) for a vrrp_script block."""
    name = block["args"][0] if block["args"] else (block["name"] or "")
    path = None
    for entry in block["body"]:
        if entry["kind"] == "line" and entry["tokens"] and entry["tokens"][0] == "script":
            path = " ".join(entry["tokens"][1:]) or None
    return name, path


def _parse_instance(block: Dict[str, Any]) -> Dict[str, Any]:
    """Interpret one `vrrp_instance` block into VIP-model fields plus its own unsupported list."""
    inst: Dict[str, Any] = {
        "instance_name": block["args"][0] if block["args"] else "",
        "state": None,
        "interface": None,
        "virtual_router_id": None,
        "priority": None,
        "advert_int": None,
        "auth_type": None,
        "auth_pass": None,
        "unicast_src_ip": None,
        "unicast_peers": [],
        "virtual_ips": [],
        "track_scripts": [],
        "unsupported": [],
        "line": block["line"],
    }

    def unsupported(what: str, lineno: int) -> None:
        inst["unsupported"].append({"directive": what, "line": lineno})

    for entry in block["body"]:
        if entry["kind"] == "line":
            tokens = entry["tokens"]
            key = tokens[0]
            if key == "state":
                inst["state"] = (tokens[1].upper() if len(tokens) > 1 else None)
            elif key == "interface":
                inst["interface"] = tokens[1] if len(tokens) > 1 else None
            elif key == "virtual_router_id":
                inst["virtual_router_id"] = _as_int(tokens)
            elif key == "priority":
                inst["priority"] = _as_int(tokens)
            elif key == "advert_int":
                # keepalived accepts sub-second floats; our model column is an integer.
                raw = tokens[1] if len(tokens) > 1 else ""
                try:
                    val = float(raw)
                except (TypeError, ValueError):
                    val = None
                if val is None:
                    unsupported(f"advert_int {raw}", entry["line"])
                elif val != int(val):
                    # Rounding would change VRRP timing, so refuse rather than adopt-and-alter.
                    unsupported(f"advert_int {raw} (fractional; model stores whole seconds)",
                                entry["line"])
                else:
                    inst["advert_int"] = int(val)
            elif key == "unicast_src_ip":
                inst["unicast_src_ip"] = tokens[1] if len(tokens) > 1 else None
            else:
                unsupported(" ".join(tokens), entry["line"])
            continue

        name = entry["name"]
        if name == "authentication":
            for sub in entry["body"]:
                if sub["kind"] != "line" or not sub["tokens"]:
                    continue
                k = sub["tokens"][0]
                if k == "auth_type":
                    inst["auth_type"] = (sub["tokens"][1].upper() if len(sub["tokens"]) > 1 else None)
                elif k == "auth_pass":
                    # Everything after the keyword: a VRRP password may contain spaces.
                    inst["auth_pass"] = " ".join(sub["tokens"][1:]) or None
                else:
                    unsupported(f"authentication/{' '.join(sub['tokens'])}", sub["line"])
        elif name == "unicast_peer":
            for sub in entry["body"]:
                if sub["kind"] == "line" and sub["tokens"]:
                    inst["unicast_peers"].append(sub["tokens"][0])
                else:
                    unsupported("unicast_peer/<block>", entry["line"])
        elif name == "virtual_ipaddress":
            for sub in entry["body"]:
                if sub["kind"] != "line" or not sub["tokens"]:
                    unsupported("virtual_ipaddress/<block>", entry["line"])
                    continue
                parsed = _parse_vip_entry(sub["tokens"])
                if parsed is None:
                    unsupported(f"virtual_ipaddress/{' '.join(sub['tokens'])}", sub["line"])
                else:
                    if parsed["extra"]:
                        unsupported(
                            f"virtual_ipaddress/{parsed['address']} "
                            f"({' '.join(parsed['extra'])})", sub["line"])
                    inst["virtual_ips"].append(parsed)
        elif name == "track_script":
            for sub in entry["body"]:
                if sub["kind"] == "line" and sub["tokens"]:
                    inst["track_scripts"].append(sub["tokens"][0])
        else:
            unsupported(f"{name} {{...}}", entry["line"])

    return inst


def parse_keepalived_conf(text: str) -> Dict[str, Any]:
    """Parse a keepalived.conf into VIP-model fields plus everything we could not model.

    Raises KeepalivedParseError on structurally broken input. Never log the result: parsed
    instances carry `auth_pass` in cleartext.
    """
    root = _read_blocks(text or "")
    result: Dict[str, Any] = {
        "instances": [],
        "scripts": {},
        "global_defs": {},
        "unsupported": [],   # top-level directives our render would drop
        "sync_groups": [],
    }

    for entry in root:
        if entry["kind"] == "line":
            # A bare top-level directive (e.g. `include /etc/keepalived/conf.d/*.conf`).
            result["unsupported"].append(
                {"directive": " ".join(entry["tokens"]), "line": entry["line"]})
            continue
        name = entry["name"]
        if name == "global_defs":
            for sub in entry["body"]:
                if sub["kind"] == "line" and sub["tokens"]:
                    key = sub["tokens"][0]
                    result["global_defs"][key] = " ".join(sub["tokens"][1:])
                    if key not in _SUPPORTED_GLOBAL_KEYS:
                        result["unsupported"].append(
                            {"directive": f"global_defs/{' '.join(sub['tokens'])}",
                             "line": sub["line"]})
                else:
                    result["unsupported"].append(
                        {"directive": f"global_defs/{sub.get('name', '?')} {{...}}",
                         "line": sub["line"]})
        elif name == "vrrp_script":
            script_name, path = _classify_script(entry)
            result["scripts"][script_name] = {"script": path, "line": entry["line"]}
        elif name == "vrrp_instance":
            result["instances"].append(_parse_instance(entry))
        elif name == "vrrp_sync_group":
            # A sync group ties instances together so they fail over as a unit. Our render has
            # no equivalent, and dropping it changes failover semantics — never adopt silently.
            group = entry["args"][0] if entry["args"] else ""
            result["sync_groups"].append({"name": group, "line": entry["line"]})
            result["unsupported"].append(
                {"directive": f"vrrp_sync_group {group}", "line": entry["line"]})
        else:
            # virtual_server (LVS), static_routes, bfd_instance, ...
            args = " ".join(entry["args"])
            result["unsupported"].append(
                {"directive": f"{name} {args} {{...}}".replace("  ", " "), "line": entry["line"]})

    return result


# ---------------------------------------------------------------------------
# Mapping to the VIP model + the adoption gate
# ---------------------------------------------------------------------------
# keepalived defaults we are willing to apply when a directive is absent, because the value
# is unambiguous and re-rendering it changes nothing on the wire.
_DEFAULT_ADVERT_INT = 1
_DEFAULT_PRIORITY = 100
_DEFAULT_STATE = "BACKUP"

# The only track_script our renderer emits (keepalived_config.build_haproxy_check_script).
OUR_CHECK_SCRIPT_NAME = "chk_haproxy"


def build_adoption_candidate(parsed: Dict[str, Any], instance: Dict[str, Any]) -> Dict[str, Any]:
    """Map one parsed `vrrp_instance` onto vip_instances / vip_members fields.

    Returns `adoptable` plus `blockers`. A blocker means taking ownership would change what
    is running — either because our render cannot reproduce something in the file, or because
    a value we must write is not knowable from the file. Adoption REPLACES the operator's
    config, so "we could not read it" and "we would change it" are the same hazard, and both
    have to stop the flow rather than be logged.

    Never log the return value: `vip.auth_pass` is cleartext.
    """
    blockers: List[str] = []

    # Directives we would drop. Report the file's own line numbers so the operator can look.
    dropped = list(parsed.get("unsupported") or []) + list(instance.get("unsupported") or [])
    for d in dropped:
        blockers.append(
            f"line {d['line']}: `{d['directive']}` — OpenManager's renderer cannot reproduce "
            f"this, so adopting would delete it")

    vips = instance.get("virtual_ips") or []
    if len(vips) == 0:
        blockers.append("the instance declares no virtual_ipaddress — nothing to adopt")
    elif len(vips) > 1:
        addrs = ", ".join(v["address"] for v in vips)
        blockers.append(
            f"the instance carries {len(vips)} addresses ({addrs}); a managed VIP holds exactly "
            f"one, so adopting would drop all but the first")

    vip_entry = vips[0] if vips else None

    if instance.get("virtual_router_id") is None:
        blockers.append("no virtual_router_id — it cannot be guessed: a wrong VRID puts the "
                        "nodes in separate VRRP domains and both would claim the VIP")
    if not instance.get("interface"):
        blockers.append("no interface — required to render the instance and the address")

    # An explicit prefix is required. Our renderer ALWAYS writes `<addr>/<prefix>`, the model
    # column defaults to 24, and keepalived's own default for a bare address is a host route.
    # Picking either one for the operator would silently change the VIP's netmask, so ask.
    if vip_entry is not None and vip_entry.get("prefix_length") is None:
        blockers.append(
            f"`{vip_entry['address']}` has no explicit prefix length; state it during adoption "
            f"so the netmask cannot change on takeover")

    # The address must live on the instance's interface — that is the only `dev` we can render.
    if vip_entry is not None and vip_entry.get("dev") and instance.get("interface") \
            and vip_entry["dev"] != instance["interface"]:
        blockers.append(
            f"the address is bound to `dev {vip_entry['dev']}` but the instance uses "
            f"`interface {instance['interface']}`; the render always uses the instance interface")

    auth_type = instance.get("auth_type")
    if auth_type not in (None, "PASS"):
        blockers.append(f"auth_type {auth_type} is not supported (only PASS is rendered)")

    # A tracked script that is not ours would be replaced by our HAProxy check.
    tracked = [t for t in (instance.get("track_scripts") or [])]
    foreign = [t for t in tracked if t != OUR_CHECK_SCRIPT_NAME]
    if foreign:
        blockers.append(
            f"track_script {', '.join(foreign)} would be replaced by OpenManager's HAProxy "
            f"health check")

    state = instance.get("state") or _DEFAULT_STATE
    if state not in ("MASTER", "BACKUP"):
        blockers.append(f"state {state} is not MASTER or BACKUP")

    peers = list(instance.get("unicast_peers") or [])
    src = instance.get("unicast_src_ip")
    # Our renderer emits unicast_src_ip and unicast_peer together, or neither.
    if bool(src) != bool(peers):
        which = "unicast_src_ip without unicast_peer" if src else "unicast_peer without unicast_src_ip"
        blockers.append(f"{which} — the render emits both or neither")

    candidate: Dict[str, Any] = {
        "instance_name": instance.get("instance_name") or "",
        "adoptable": not blockers,
        "blockers": blockers,
        "dropped_directives": dropped,
        "vip": {
            "virtual_ip": vip_entry["address"] if vip_entry else None,
            "prefix_length": vip_entry.get("prefix_length") if vip_entry else None,
            "virtual_router_id": instance.get("virtual_router_id"),
            "advert_int": instance.get("advert_int") if instance.get("advert_int") is not None
            else _DEFAULT_ADVERT_INT,
            "use_unicast": bool(peers),
            "track_haproxy": OUR_CHECK_SCRIPT_NAME in tracked,
            "auth_pass": instance.get("auth_pass"),
        },
        "member": {
            "network_interface": instance.get("interface"),
            "role": state,
            "priority": instance.get("priority") if instance.get("priority") is not None
            else _DEFAULT_PRIORITY,
        },
        "peers": peers,
        "unicast_src_ip": src,
        # Which values came from a keepalived default rather than the file, so the UI can say so.
        "defaulted": [
            k for k, present in (
                ("advert_int", instance.get("advert_int") is not None),
                ("priority", instance.get("priority") is not None),
                ("state", instance.get("state") is not None),
            ) if not present
        ],
    }
    return candidate


# Substrings that identify the two blocker classes an operator is allowed to resolve. They are
# matched rather than typed because the blocker text is what the UI shows; keeping the marker in
# the sentence means the message and the rule cannot drift apart.
_LOSS_MARKER = "would delete it"
_PREFIX_MARKER = "no explicit prefix length"


def remaining_blockers(blockers: List[str], *, prefix_supplied: bool = False,
                       accept_data_loss: bool = False) -> List[str]:
    """Blockers that survive what the operator is permitted to resolve.

    Exactly two classes are resolvable, and the distinction is the whole safety argument:

      * a missing prefix length is *unknown*, and the operator can supply it — we refuse to pick
        a netmask for a live VIP ourselves;
      * "our renderer cannot reproduce this, so adopting would delete it" is a *loss*, and losing
        it can be an informed choice.

    Everything else — an unknown virtual_router_id, a fractional advert_int, an unsupported
    auth_type, an address on a different interface — is neither unknown nor a loss but an
    impossibility, and no flag may wave it through. This is the single source of truth for that
    rule; the endpoint and the UI both derive from it.
    """
    out: List[str] = []
    for b in blockers or []:
        if prefix_supplied and _PREFIX_MARKER in b:
            continue
        if accept_data_loss and _LOSS_MARKER in b:
            continue
        out.append(b)
    return out


def analyse_keepalived_conf(text: str) -> Dict[str, Any]:
    """Parse + map in one call: the shape the discovery endpoint stores and the UI renders."""
    parsed = parse_keepalived_conf(text)
    return {
        "instance_count": len(parsed["instances"]),
        "sync_groups": parsed["sync_groups"],
        "global_defs": parsed["global_defs"],
        "candidates": [build_adoption_candidate(parsed, inst) for inst in parsed["instances"]],
    }
