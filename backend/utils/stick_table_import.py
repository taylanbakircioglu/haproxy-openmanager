"""
Issue #72 — Config Import policy for stick-table / stick rules and the rate-limit
lines the config generator injects.

Pure functions (no DB) so the import endpoint stays thin and the policy is unit
testable. "Platform regenerates" means the generator will itself emit the
rate-limit table/tracker/deny lines for a frontend: its `rate_limit` field is set
or an active `rate_limit` WAF rule applies to it (see services/haproxy_config.py).
"""

import re
from typing import Iterable, List, Optional, Tuple

# The only stick-table forms the generator emits (services/haproxy_config.py:
# frontend rate_limit, stick-table auto-inject, WAF rate_limit rule).
PLATFORM_STICK_TABLE_RE = re.compile(
    r'^stick-table\s+type\s+ip\s+size\s+100k\s+expire\s+(\d+)s\s+store\s+http_req_rate\(10s\)$'
)
AUTO_INJECT_EXPIRE_SECONDS = 30

# Exact forms of the rate-limit request lines the generator emits.
_PLATFORM_RATE_LIMIT_HEADER_RES = (
    re.compile(r'^http-request\s+track-sc0\s+src$'),
    re.compile(r'^http-request\s+deny\s+if\s+\{\s*sc_http_req_rate\(0\)\s+gt\s+\d+\s*\}$'),
    re.compile(
        r'^http-request\s+capture\s+req\.hdr\(User-Agent\)\s+len\s+64\s+if\s+'
        r'\{\s*sc_http_req_rate\(0\)\s+gt\s+\d+\s*\}$'
    ),
)

_STICK_RULE_RE = re.compile(r'^stick\s+(on|match|store-request|store-response)\s')
_TABLE_ARG_RE = re.compile(r'(?:^|\s)table\s+\S+')
_PEERS_ARG_RE = re.compile(r'(?:^|\s)peers\s+(\S+)')


def _lines(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return [l.strip() for l in text.split('\n') if l.strip()]


def is_stick_line(line: str) -> bool:
    s = line.strip()
    return s.startswith('stick-table') or s.startswith('stick ')


def is_stick_table_line(line: str) -> bool:
    return line.strip().startswith('stick-table')


def uses_stick_counter(line: str) -> bool:
    """Same test the renderer uses to decide a frontend needs a stick-table
    (services/haproxy_config.py `_emit_fe`)."""
    s = line.strip()
    return "track-sc" in s or ("sc_" in s and "_rate(" in s)


def is_platform_rate_limit_header(line: str) -> bool:
    s = line.strip()
    return any(r.match(s) for r in _PLATFORM_RATE_LIMIT_HEADER_RES)


def is_always_auto_header(line: str) -> bool:
    """ACME and WAF lines are generator-only: stripped regardless of context."""
    s = line.strip()
    if "is_acme_challenge" in s:
        return True
    if s.startswith("http-request") and " waf_" in s:
        return True
    return False


def strip_auto_headers(headers: Optional[str], platform_regenerates: bool) -> Optional[str]:
    """Drop generator-owned lines from a `request_headers` value.

    Rate-limit lines are dropped only when the generator will emit them again for
    this frontend AND they match its exact form; otherwise they are the
    operator's own (e.g. a tracker feeding gpc0 rules) and are kept.
    """
    if not headers:
        return None
    kept = []
    for line in headers.split("\n"):
        if is_always_auto_header(line):
            continue
        if platform_regenerates and is_platform_rate_limit_header(line):
            continue
        kept.append(line)
    return "\n".join(kept) if kept else None


def drop_platform_stick_tables(
    options: Optional[str],
    platform_regenerates: bool,
    frontend_uses_counter: bool,
) -> Tuple[Optional[str], List[str]]:
    """Remove imported stick-table lines the generator will reproduce itself.

    Keeping them would freeze them in `options` (emitted first, so they win the
    dedup) and hide later rate_limit / WAF window changes. A generator-shaped
    line is dropped when rate_limit/WAF will emit a table, or when it is the
    30s auto-inject default and the frontend uses a counter (auto-inject then
    renders the identical line). Anything else is the operator's table.
    """
    if not options:
        return options, []
    kept, dropped = [], []
    for line in options.split("\n"):
        m = PLATFORM_STICK_TABLE_RE.match(line.strip())
        if m and (
            platform_regenerates
            or (int(m.group(1)) == AUTO_INJECT_EXPIRE_SECONDS and frontend_uses_counter)
        ):
            dropped.append(line.strip())
            continue
        kept.append(line)
    return ("\n".join(kept) if kept else None), dropped


def merge_options(parsed: Optional[str], existing: Optional[str]) -> Optional[str]:
    """Merge an imported `options` value into the stored one per directive type.

    Bulk import only overwrote `options` when the import carried `option` lines;
    with stick lines now landing in `options` too, a stick-only import must not
    wipe hand-entered `option` lines (and vice versa). Each group is replaced
    only when the import carries that group. Returns `existing` unchanged when
    the merged lines are the same set, so re-imports don't flag a change.
    """
    parsed_lines = _lines(parsed)
    existing_lines = _lines(existing)
    parsed_other = [l for l in parsed_lines if not is_stick_line(l)]
    parsed_stick = [l for l in parsed_lines if is_stick_line(l)]
    existing_other = [l for l in existing_lines if not is_stick_line(l)]
    existing_stick = [l for l in existing_lines if is_stick_line(l)]

    final = (parsed_other or existing_other) + (parsed_stick or existing_stick)
    if not final:
        return None
    if sorted(final) == sorted(existing_lines):
        return existing
    return "\n".join(final)


def frontend_uses_counter(fields: Iterable) -> bool:
    """True if any non-stick line of the given frontend fields uses a counter."""
    for value in fields:
        if not value:
            continue
        items = value if isinstance(value, (list, tuple)) else str(value).split("\n")
        for line in items:
            if isinstance(line, str) and not is_stick_line(line) and uses_stick_counter(line):
                return True
    return False


def stick_advisories(
    kind: str,
    name: str,
    final_options: Optional[str],
    imported_options: Optional[str],
    final_other_fields: dict,
    platform_regenerates: bool,
) -> List[str]:
    """Non-blocking import-preview warnings for stick directives.

    kind: 'Frontend' or 'Backend'. final_other_fields: {label: final value} of
    the other free-form fields (what they hold after this import is applied).
    """
    warnings: List[str] = []
    final_lines = _lines(final_options)
    tables = [l for l in final_lines if is_stick_table_line(l)]
    imported_tables = [l for l in _lines(imported_options) if is_stick_table_line(l)]

    if kind == "Frontend" and platform_regenerates:
        for t in tables:
            if not PLATFORM_STICK_TABLE_RE.match(t) and "http_req_rate" not in t:
                warnings.append(
                    f"⚠️ Frontend '{name}': the imported stick-table does not store "
                    f"http_req_rate, but this frontend's Rate Limit / rate_limit WAF rule "
                    f"checks sc_http_req_rate(0) against it. HAProxy accepts this and the "
                    f"rate limit silently never triggers. Add http_req_rate(10s) to the "
                    f"table's 'store' list to keep it working."
                )

    if imported_tables:
        for label, value in final_other_fields.items():
            if any(is_stick_table_line(l) for l in _lines(value)):
                effect = (
                    "only the first stick-table is rendered (Options), so the one in "
                    f"{label} is ignored"
                )
                warnings.append(
                    f"⚠️ {kind} '{name}': a stick-table is also stored in {label}; "
                    f"{effect}. Remove it from {label}."
                )

    if kind == "Backend":
        has_own_table = bool(tables) or any(
            is_stick_table_line(l) for v in final_other_fields.values() for l in _lines(v)
        )
        for l in final_lines:
            if _STICK_RULE_RE.match(l) and not _TABLE_ARG_RE.search(l) and not has_own_table:
                warnings.append(
                    f"⚠️ Backend '{name}': '{l}' needs a stick-table in this backend or a "
                    f"'table <name>' argument. HAProxy rejects it at apply "
                    f"(\"unable to find stick-table\"); the previous config keeps running."
                )

    for t in tables:
        m = _PEERS_ARG_RE.search(t)
        if m:
            warnings.append(
                f"ℹ️ {kind} '{name}': stick-table references peers section "
                f"'{m.group(1)}'. HAProxy OpenManager does not manage peers sections: define "
                f"it in each node's haproxy.cfg BEFORE the 'defaults' section (the agent "
                f"keeps everything above the first defaults/listen/frontend/backend and "
                f"replaces the rest)."
            )
    return warnings
