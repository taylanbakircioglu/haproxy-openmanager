"""
Issue #78 — Config Import policy for a frontend's `acl_rules` and
`use_backend_rules`.

Pure functions (no DB) so the import endpoint stays thin and the policy is unit
testable. Both columns are JSONB lists in `frontends`. Rows written by the UI
store ACLs without the `acl ` prefix, rows written by Config Import store the
parsed line with it; the generator (services/haproxy_config.py) renders both the
same way, so comparisons here go through that same rendering.
"""

import json
from typing import Any, List, Optional, Tuple

ACL = "acl"
USE_BACKEND = "use_backend"

_PREFIX = {ACL: "acl ", USE_BACKEND: "use_backend "}
# Values the generator skips instead of rendering.
_SKIPPED = {
    ACL: ('[]', '{}', 'null', 'None'),
    USE_BACKEND: ('[]', '{}', 'null', 'None', '""', "''"),
}
# Same characters the generator strips from both ends of a stored rule.
_RENDER_STRIP = '[]"\''
# The manual frontend API rejects these (models/frontend.py); Config Import
# bypasses that model, so it applies the same rule here.
_DANGEROUS = ('$(', '`')


def coerce_rule_list(value: Any) -> List[Any]:
    """JSONB text, a list or None -> list (items unchanged)."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError):
            return [l for l in text.split('\n') if l.strip()]
        if isinstance(parsed, list):
            return parsed
        return []
    return []


def render_rule(rule: Any, kind: str) -> Optional[str]:
    """The directive the generator emits for one stored rule, or None when it
    emits nothing for it."""
    if not isinstance(rule, str):
        return None
    text = rule.strip().strip(_RENDER_STRIP).strip()
    if not text or text in _SKIPPED[kind]:
        return None
    if not text.startswith(_PREFIX[kind]):
        text = _PREFIX[kind] + text
    return text


def normalize_rules(value: Any, kind: str) -> List[str]:
    return [r for r in (render_rule(x, kind) for x in coerce_rule_list(value)) if r]


def is_platform_rule(rule: Any, kind: str) -> bool:
    """Lines the generator owns (ACME routing, WAF ACLs). Config Import never
    stores them because the generator emits them itself."""
    if not isinstance(rule, str):
        return False
    rendered = render_rule(rule, kind) or ""
    if kind == ACL:
        return ("is_acme_challenge" in rule
                or rule.strip().startswith("acl waf_")
                or rendered.startswith("acl waf_"))
    return "_acme_challenge_backend" in rule


def strip_platform_rules(rules: Any, kind: str) -> List[Any]:
    return [r for r in coerce_rule_list(rules) if not is_platform_rule(r, kind)]


def sanitize_rules(rules: Any, kind: str) -> Tuple[List[str], List[Tuple[Any, str]]]:
    """Drop rules the generator must not render verbatim.

    Returns (kept, dropped) where dropped is a list of (rule, reason). A rule
    containing a line break would inject extra directives into haproxy.cfg.
    """
    kept: List[str] = []
    dropped: List[Tuple[Any, str]] = []
    for rule in coerce_rule_list(rules):
        if not isinstance(rule, str):
            dropped.append((rule, "not a string"))
        elif '\n' in rule or '\r' in rule:
            dropped.append((rule, "contains a line break"))
        elif any(d in rule.lower() for d in _DANGEROUS):
            dropped.append((rule, "contains '$(' or a backtick"))
        else:
            kept.append(rule)
    return kept, dropped


def rules_mangled_by_renderer(rules: Any) -> List[str]:
    """Rules whose first or last character the generator strips (a quote or a
    square bracket), e.g. `acl api hdr(host) -i "api.example.com"`."""
    out = []
    for rule in coerce_rule_list(rules):
        if isinstance(rule, str):
            s = rule.strip()
            if s and s != s.strip(_RENDER_STRIP):
                out.append(s)
    return out


def comparable_existing(existing: Any, kind: str) -> List[str]:
    return [r for r in normalize_rules(existing, kind) if not is_platform_rule(r, kind)]


def rules_changed(imported: Any, existing: Any, kind: str) -> bool:
    """True when the import carries rules and they render differently (order
    included) from what is stored. An import without rules keeps the stored
    list, like every other field Config Import merges."""
    new = normalize_rules(imported, kind)
    return bool(new) and new != comparable_existing(existing, kind)


def removed_rules(imported: Any, existing: Any, kind: str) -> List[str]:
    new = set(normalize_rules(imported, kind))
    return [r for r in comparable_existing(existing, kind) if r not in new]


def merge_imported_rules(imported: Any, existing: Any, kind: str) -> List[Any]:
    """The list to store: the imported rules in file order, with the generator-
    owned lines already in the row kept (older imports may have stored them and
    they render today), each after the stored rule it followed when that rule is
    still in the file, so the rendered order moves as little as possible."""
    result = list(coerce_rule_list(imported))
    present = [render_rule(r, kind) for r in result]
    anchor = -1
    for rule in coerce_rule_list(existing):
        rendered = render_rule(rule, kind)
        if rendered is not None and rendered in present[anchor + 1:]:
            anchor = present.index(rendered, anchor + 1)
        elif is_platform_rule(rule, kind):
            result.insert(anchor + 1, rule)
            present.insert(anchor + 1, rendered)
            anchor += 1
    return result


def is_waf_named_acl(rule: Any) -> bool:
    """An `acl waf_*` line. Config Import cannot tell one a WAF rule generated
    from one the frontend stores itself under that name, so it skips both."""
    return isinstance(rule, str) and (render_rule(rule, ACL) or "").startswith("acl waf_")


def is_waf_header_line(line: str) -> bool:
    """An `http-request ... waf_*` line; Config Import skips these the same way
    (utils/stick_table_import.is_always_auto_header)."""
    s = line.strip()
    return s.startswith("http-request") and " waf_" in s


def waf_named_lines(acl_rules: Any, request_headers: Optional[str]) -> List[str]:
    """A frontend's `acl waf_*` and `http-request ... waf_*` lines, as rendered."""
    acls = [render_rule(r, ACL) for r in coerce_rule_list(acl_rules) if is_waf_named_acl(r)]
    headers = [l.strip() for l in (request_headers or "").split('\n') if is_waf_header_line(l)]
    return acls + headers


def waf_line_differences(imported: List[str], current: List[str]) -> Tuple[List[str], List[str]]:
    """(lines only in the file, lines only in the current config), counting repeats."""
    rest = list(current)
    only_imported = []
    for line in imported:
        if line in rest:
            rest.remove(line)
        else:
            only_imported.append(line)
    return only_imported, rest


def keep_stored_waf_header_lines(new_headers: str, existing_headers: Optional[str]) -> str:
    """`new_headers` with the frontend's stored `http-request ... waf_*` lines put
    back, each after the stored line it followed when that line is still present.

    The import drops these lines from the file, so writing `new_headers` as-is
    would delete rules such as `http-request deny if waf_x` from the frontend
    while its ACLs stay. With nothing else changed the result equals the stored
    value, so no update is triggered.
    """
    result = [l for l in new_headers.split('\n')] if new_headers else []
    present = [l.strip() for l in result]
    anchor = -1
    for line in (existing_headers or "").split('\n'):
        s = line.strip()
        if not s:
            continue
        if s in present[anchor + 1:]:
            anchor = present.index(s, anchor + 1)
        elif is_waf_header_line(line):
            result.insert(anchor + 1, line)
            present.insert(anchor + 1, s)
            anchor += 1
    return '\n'.join(result)
