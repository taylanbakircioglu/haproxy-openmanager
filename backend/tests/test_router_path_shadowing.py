"""
v1.10.6 — literal API paths must never be declared after a parameterised one.

Found in production on the v1.10.4 VIP-adoption feature: `@router.get("/discoveries")`
sat at the bottom of routers/vip.py, below `@router.get("/{vip_id}")`. FastAPI matches
routes in DECLARATION order, so every `GET /api/vip/discoveries` was answered by the
`/{vip_id}` handler, which declares `vip_id: int` and therefore rejected the request with
422 before `list_vip_discoveries` ever ran.

Nothing about that failure was visible. The agents reported their discoveries correctly,
the rows landed in `vip_discoveries`, and the HA/VIP page treats any non-OK response as
"nothing to show" — so the adoption feature simply did not exist as far as the UI was
concerned, with no error anywhere.

These tests are a STATIC source scan on purpose: no imports, no app construction, no DB.
They therefore also cover routers that cannot be imported in a bare test environment, and
they keep covering routes added in the future.
"""
import pathlib
import re

import pytest

ROUTERS_DIR = pathlib.Path(__file__).resolve().parents[1] / "routers"

# `@router.get("/x")`, `@some_router.post("/x", ...)` — the path is the first string arg.
_DECORATOR = re.compile(r'^@(?:\w+)\.(get|post|put|delete|patch)\(\s*[\'"]([^\'"]*)[\'"]')


def _routes(source: str):
    """[(line_no, verb, path)] in declaration order."""
    out = []
    for line_no, line in enumerate(source.splitlines(), 1):
        match = _DECORATOR.match(line)
        if match:
            out.append((line_no, match.group(1), match.group(2)))
    return out


def _shadows(earlier: str, later: str) -> bool:
    """True if `earlier` (declared first) swallows the literal path `later`.

    Only literal paths can be silently swallowed, and only by a path that has the same
    number of segments where every non-placeholder segment matches. The collection route
    ("" or "/") is its own path and never collides.
    """
    if not later.strip("/") or not earlier.strip("/"):
        return False
    if "{" in later:
        return False
    if "{" not in earlier:
        return False
    earlier_segments = earlier.strip("/").split("/")
    later_segments = later.strip("/").split("/")
    if len(earlier_segments) != len(later_segments):
        return False
    return all(
        e.startswith("{") or e == l
        for e, l in zip(earlier_segments, later_segments)
    )


def _shadowed_routes(path: pathlib.Path):
    routes = _routes(path.read_text())
    found = []
    for index, (line_no, verb, route_path) in enumerate(routes):
        for prior_line, prior_verb, prior_path in routes[:index]:
            if prior_verb == verb and _shadows(prior_path, route_path):
                found.append(
                    f"{path.name}:{line_no} {verb.upper()} {route_path} is swallowed by "
                    f"{prior_path} declared at line {prior_line}"
                )
    return found


# ----------------------------------------------------------------------------
# 1. The specific regression: /api/vip/discoveries must outrank /{vip_id}
# ----------------------------------------------------------------------------

def test_vip_discoveries_declared_before_vip_id():
    routes = _routes((ROUTERS_DIR / "vip.py").read_text())
    get_paths = [path for _line, verb, path in routes if verb == "get"]

    assert "/discoveries" in get_paths, "the discoveries endpoint disappeared"
    assert "/{vip_id}" in get_paths, "the get-one endpoint disappeared"
    assert get_paths.index("/discoveries") < get_paths.index("/{vip_id}"), (
        "GET /discoveries is declared after GET /{vip_id}; FastAPI will route "
        "/api/vip/discoveries into get_vip and answer 422, silently emptying the "
        "adoption panel"
    )


# ----------------------------------------------------------------------------
# 2. The general guard: no literal path anywhere is shadowed
# ----------------------------------------------------------------------------

def test_no_literal_route_is_shadowed_in_any_router():
    problems = []
    for router_file in sorted(ROUTERS_DIR.glob("*.py")):
        problems.extend(_shadowed_routes(router_file))

    assert not problems, (
        "literal route(s) declared after a parameterised route that swallows them:\n  "
        + "\n  ".join(problems)
    )


# ----------------------------------------------------------------------------
# 3. The detector itself must actually detect (guards against a vacuous pass)
# ----------------------------------------------------------------------------

@pytest.mark.parametrize(
    "earlier,later,expected",
    [
        ("/{vip_id}", "/discoveries", True),        # the v1.10.4 bug
        ("/{vip_id}", "/{other}", False),           # two placeholders never shadow
        ("/{vip_id}", "", False),                   # collection route is its own path
        ("/{vip_id}/apply", "/adopt", False),       # different segment counts
        ("/{vip_id}/apply", "/adopt/now", False),   # literal mismatch in segment 2
        ("/{vip_id}/{action}", "/adopt/now", True), # both segments placeheld
        ("/vips", "/discoveries", False),           # literal never shadows a literal
    ],
)
def test_shadow_detector_semantics(earlier, later, expected):
    assert _shadows(earlier, later) is expected


def test_detector_flags_the_original_declaration_order():
    """A synthetic file in the pre-fix order must be reported, so a future refactor that
    breaks the detector cannot make the guard above pass vacuously."""
    source = (
        '@router.get("")\n'
        "async def list_vips(): ...\n"
        '@router.get("/{vip_id}")\n'
        "async def get_vip(vip_id: int): ...\n"
        '@router.get("/discoveries")\n'
        "async def list_vip_discoveries(): ...\n"
    )
    routes = _routes(source)
    assert [verb for _l, verb, _p in routes] == ["get", "get", "get"]
    assert _shadows(routes[1][2], routes[2][2]) is True
