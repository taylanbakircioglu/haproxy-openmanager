"""v1.11.0: the log's cost must follow operator activity, not fleet size.

Every property here was a real defect measured on the feature branch, and each
one only shows up at scale or at the edge of a setting's documented range, which
is why none of them were caught by the rule-level tests.

  * one row per API call becomes millions per day once the fleet is a few
    hundred nodes, and the row cap then evicts the forensic history the feature
    exists for;
  * the operator role could not see the rows its grant was written for;
  * every background call ever made shared one correlation id;
  * queue memory was a function of an operator-editable setting, not a limit.
"""
import asyncio
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dataclasses import replace  # noqa: E402

from utils.http_instrumentation import _correlation_id, begin_background_trace  # noqa: E402
from utils.request_log_settings import (  # noqa: E402
    DEFAULT_CONFIG,
    get_config,
    set_config,
)
from utils.request_log_sink import (  # noqa: E402
    TARGET_INBOUND_AGENT,
    RequestLogRow,
    RequestLogSink,
    request_id_context,
)

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ROUTER = os.path.join(_BACKEND, "routers", "request_logs.py")
_MIDDLEWARE = os.path.join(_BACKEND, "middleware", "request_logger.py")


@pytest.fixture(autouse=True)
def _restore_config():
    """These tests mutate the module-global snapshot; put it back."""
    before = get_config()
    yield
    set_config(before)


def _row(**kw):
    kw.setdefault("request_id", "a" * 32)
    kw.setdefault("direction", "inbound")
    kw.setdefault("method", "GET")
    kw.setdefault("url", "/api/agents/prod-lb-1/config")
    kw.setdefault("status_code", 200)
    return RequestLogRow(**kw)


class _CountingSink(RequestLogSink):
    """Counts what survives `offer()` without needing an event loop."""

    def __init__(self, **kw):
        super().__init__(kw.pop("maxsize", 10000), 100, 500, **kw)
        self.accepted = []

    def _ensure_queue(self):
        sink = self

        class _Q:
            def put_nowait(self, row):
                sink.accepted.append(row)

            def qsize(self):
                return len(sink.accepted)

        return _Q()


# --------------------------------------------------------------------------
# Volume: successful agent polls are not rows
# --------------------------------------------------------------------------

def test_successful_agent_polls_are_dropped_by_default():
    """~9 800 rows/day PER AGENT, all of them 200s meaning "nothing changed".

    At 200 nodes that is ~2M rows/day and the 500 000 row cap is reached in
    about six hours, so the configured "7 days of successes, 30 days of
    failures" silently becomes about six hours of each — for everything in the
    table, not just for the agent rows.
    """
    assert DEFAULT_CONFIG.capture_agent_success is False, (
        "the default must be off; on, the table's size is a function of node "
        "count rather than of anything anyone did"
    )
    sink = _CountingSink()
    for _ in range(100):
        sink.offer(_row(target=TARGET_INBOUND_AGENT, status_code=200))
    assert sink.accepted == []


@pytest.mark.parametrize("status", [401, 422, 500, None])
def test_failed_agent_calls_are_always_kept(status):
    """The half an operator actually needs, and rare enough to be free.

    `None` is a transport error with no HTTP response at all, which
    status_class reports as 0.
    """
    sink = _CountingSink()
    sink.offer(_row(target=TARGET_INBOUND_AGENT, status_code=status))
    assert len(sink.accepted) == 1, f"a {status} agent call must be recorded"


def test_operator_traffic_is_unaffected_by_the_agent_gate():
    sink = _CountingSink()
    sink.offer(_row(target=None, status_code=200, user_id=7))
    assert len(sink.accepted) == 1


def test_the_gate_can_be_turned_on_for_debugging():
    set_config(replace(get_config(), capture_agent_success=True))
    sink = _CountingSink()
    sink.offer(_row(target=TARGET_INBOUND_AGENT, status_code=200))
    assert len(sink.accepted) == 1


def test_agent_traffic_is_identified_by_headers_not_by_a_database_lookup():
    """The hot path runs on every request; a lookup per call is not affordable.

    The installed agent sends `X-API-Key` and never `Authorization`; the UI
    sends a JWT and never an agent key.
    """
    from middleware.request_logger import _is_agent_call

    def scope(headers):
        return {"type": "http", "headers": [(k.encode(), v.encode()) for k, v in headers.items()]}

    assert _is_agent_call(scope({"x-api-key": "agt_x"})) is True
    assert _is_agent_call(scope({"authorization": "Bearer x.y.z"})) is False
    # generate-install-script accepts either; self-upgrade sends only the key.
    assert _is_agent_call(scope({"authorization": "Bearer x.y.z", "x-api-key": "agt_x"})) is False
    assert _is_agent_call(scope({})) is False


def test_agent_gate_does_not_reach_for_a_connection():
    """`offer()` is called from the request coroutine and must stay pure."""
    src = open(os.path.join(_BACKEND, "utils", "request_log_sink.py"), encoding="utf-8").read()
    body = src.split("def offer(", 1)[1].split("\n    # -- consumer", 1)[0]
    for forbidden in ("await ", "get_database_connection", "fetch"):
        assert forbidden not in body, f"offer() must not {forbidden.strip()!r} — it runs on the hot path"


# --------------------------------------------------------------------------
# Visibility: the operator grant has to mean something
# --------------------------------------------------------------------------

def test_read_only_scoping_admits_agent_rows_but_not_other_users():
    """`operator` holds requestlog.read to "debug failing applies" — but an
    apply fails on the NODE, and the node reports over its own API key, so that
    row has user_id NULL and own-rows-only scoping hid it.

    Keyed on `target`, NOT on `user_id IS NULL`: anonymous traffic (failed
    logins and their usernames, unauthenticated probes) is not agent traffic
    and must stay admin-only.
    """
    src = open(_ROUTER, encoding="utf-8").read()
    clause = re.search(r"if not can_manage:(.*?)where_sql =", src, re.S)
    assert clause, "the self-scoping block moved; re-check this test"
    # Code only: the comment above the clause explains what it deliberately
    # does NOT do, and would otherwise match the negative assertion below.
    body = "\n".join(
        line for line in clause.group(1).splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "TARGET_INBOUND_AGENT" in body, "agent rows are still hidden from requestlog.read"
    assert "user_id IS NULL" not in body, (
        "scoping on NULL would also expose anonymous traffic, including failed "
        "logins and the usernames they carry"
    )


def test_detail_endpoint_uses_the_same_scoping_rule_as_the_list():
    src = open(_ROUTER, encoding="utf-8").read()
    detail = src.split('@router.get("/{log_id}")', 1)[1]
    assert "TARGET_INBOUND_AGENT" in detail, (
        "the detail endpoint would 404 on the very rows the list now shows"
    )


@pytest.mark.parametrize("decorator", [
    '@router.get("/settings")', '@router.put("/settings")',
    '@router.get("/stats")', '@router.post("/purge")',
    '@router.get("")', '@router.get("/{log_id}")',
])
def test_permission_is_enforced_before_the_try_block(decorator):
    """The repo's GHSA-3p5c pattern: a permission check inside `try` gets
    swallowed by the handler's own `except Exception -> 500`, turning a 403
    into a server error and, worse, hiding that the check ran at all."""
    src = open(_ROUTER, encoding="utf-8").read()
    body = src.split(decorator, 1)[1]
    body = body.split("\n@router.")[0]
    require_at = body.find("_require(authorization")
    try_at = body.find("\n    try:")
    assert require_at != -1, f"{decorator} does not call _require at all"
    assert try_at == -1 or require_at < try_at, (
        f"{decorator} checks permissions INSIDE its try block"
    )


# --------------------------------------------------------------------------
# Correlation: a trace that groups the wrong rows is worse than no trace
# --------------------------------------------------------------------------

def test_each_background_pass_gets_its_own_correlation_id():
    """Nothing in main.py names its tasks, so the old `bg:<task name>` fallback
    gave one long-lived loop a single id for its entire life — measured, 15
    ACME calls across 5 ticks came out as 1 id. `related` (LIMIT 100) then
    presents up to a hundred unrelated calls as this request's trace.
    """
    async def loop():
        per_tick = []
        for _ in range(5):
            begin_background_trace("acme_renewals")
            per_tick.append([_correlation_id() for _ in range(3)])
            await asyncio.sleep(0)
        return per_tick

    ticks = asyncio.run(loop())
    for tick in ticks:
        assert len(set(tick)) == 1, "calls within one pass must share an id"
    ids = [t[0] for t in ticks]
    assert len(set(ids)) == 5, f"passes must not share an id, got {ids}"


def test_unwrapped_background_code_does_not_collapse_onto_one_id():
    """Erring toward too little grouping: a row that stands alone is honest, a
    row falsely grouped with a hundred others is not."""
    async def unwrapped():
        request_id_context.set(None)
        return [_correlation_id() for _ in range(4)]

    ids = asyncio.run(unwrapped())
    assert len(set(ids)) == 4


def test_the_background_loops_that_make_outbound_calls_open_a_trace():
    src = open(os.path.join(_BACKEND, "main.py"), encoding="utf-8").read()
    for loop_name in ("complete_pending_acme_orders", "check_letsencrypt_renewals",
                      "monitor_agent_status"):
        body = src.split(f"async def {loop_name}", 1)[1].split("\nasync def ")[0]
        assert "begin_background_trace(" in body, (
            f"{loop_name} makes outbound calls but never opens a per-pass trace"
        )


# --------------------------------------------------------------------------
# Memory: a limit, not a setting
# --------------------------------------------------------------------------

def test_queue_memory_is_bounded_even_at_the_max_body_size_ceiling():
    """`max_body_bytes` is editable from Settings and its documented ceiling is
    256 KB, which a row carries twice. Against the default 2 000-row queue that
    is ~1 GiB — the entire pod limit — reachable from in-range values.
    """
    set_config(replace(get_config(), max_body_bytes=262144, capture_agent_success=True))
    budget = 8 * 1024 * 1024
    sink = _CountingSink(maxsize=2000, max_bytes=budget)
    blob = b"x" * 262144
    for _ in range(2000):
        sink.offer(_row(target=None, request_body_raw=blob, response_body_raw=blob))

    held = sum(r.queue_weight() for r in sink.accepted)
    assert held <= budget, f"queue held {held} bytes against a {budget} byte budget"
    assert sink.stats["dropped"] > 0, "over-budget rows must be dropped, and counted"
    unbounded = 2000 * (2 * 262144 + 1400)
    assert held < unbounded / 10, (
        f"without the byte budget this queue would hold {unbounded // 1024 // 1024} MiB"
    )


def test_the_byte_budget_is_released_as_rows_drain():
    """A budget that only ever counts up is a slow leak, not a limit."""
    async def drain():
        sink = RequestLogSink(2000, 100, 10, max_bytes=8 * 1024 * 1024)
        blob = b"x" * 4096
        set_config(replace(get_config(), capture_agent_success=True))
        for _ in range(50):
            sink.offer(_row(target=None, request_body_raw=blob, response_body_raw=blob))
        assert sink.stats["queued_bytes"] > 0
        await sink._collect()
        return sink.stats["queued_bytes"]

    assert asyncio.run(drain()) == 0


def test_stats_say_the_sink_counters_are_per_worker():
    """The sink is a module global; with UVICORN_WORKERS > 1 each process keeps
    its own. A number that looks fleet-wide but is not understates drops by
    exactly the worker count."""
    src = open(_ROUTER, encoding="utf-8").read()
    assert '"scope"' in src.split('"sink"', 1)[1][:400], (
        "the stats response must label the sink counters as this-worker-only"
    )
