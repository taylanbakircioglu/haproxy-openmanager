"""
Phase K Phase D follow-up (Bulgu #10) — HAProxy heuristic
validator timeout-value regex must accept the FULL set of HAProxy
time unit suffixes, not just single-character ones.

Per the HAProxy docs (Time format chapter), accepted units are:
    us  microseconds
    ms  milliseconds
    s   seconds
    m   minutes
    h   hours
    d   days

A bare integer (no suffix) is also accepted and interpreted as
milliseconds. Pre-fix the regex was `^\\d+[smhd]?$`, which rejected
`ms` and `us` outright. The Site Wizard's config synthesis emits
`timeout connect 10000ms` / `timeout server 60000ms` / `timeout
client 100ms`, so the dry-run preview surfaced 10+ FALSE-POSITIVE
errors on the wizard's own defaults and the operator could not
reach Create even though the real HAProxy `-c` parse was happy.

These tests pin the regex (or its semantic) so a future
"simplification" cannot regress us back to the buggy form.
"""
import pytest

from utils.haproxy_validator import HAProxyConfigValidator, ValidationLevel


def _validate_timeout_only(args):
    """Run the validator's private `_validate_timeout_directive`
    method and return the list of results so we can assert on the
    exact error messages without coupling to the public surface.
    """
    v = HAProxyConfigValidator()
    v._validate_timeout_directive(args)
    return v.results


@pytest.mark.parametrize(
    "value",
    [
        "10000ms",
        "60000ms",
        "100ms",
        "30000ms",
        "5s",
        "1m",
        "1h",
        "1d",
        "500us",  # microseconds — also valid per HAProxy docs
        "0",      # bare integer (= ms)
        "10000",  # bare integer (= ms)
    ],
)
def test_timeout_regex_accepts_all_haproxy_time_units(value):
    """All HAProxy-valid time formats must produce ZERO ERROR-level
    results from the timeout heuristic. (WARNING-level results from
    OTHER checks — unknown timeout type, etc. — are allowed but
    must not be raised by these well-formed examples.)
    """
    results = _validate_timeout_only(["connect", value])
    errors = [r for r in results if r.level == ValidationLevel.ERROR]
    assert errors == [], (
        f"Bulgu #10 regression: timeout value '{value}' was flagged "
        f"as ERROR by the heuristic validator, but HAProxy `-c` "
        f"accepts it. Errors: {[e.message for e in errors]}"
    )


@pytest.mark.parametrize(
    "value",
    [
        "10000xx",   # bogus suffix
        "abc",       # not a number
        "-100ms",    # negative
        "1.5s",      # decimal not supported
        "ms",        # suffix only
    ],
)
def test_timeout_regex_still_rejects_invalid_formats(value):
    """Real malformed timeout values must still surface as ERROR —
    the regex relaxation must NOT degenerate into "accept anything".
    """
    results = _validate_timeout_only(["connect", value])
    errors = [r for r in results if r.level == ValidationLevel.ERROR]
    assert any("Invalid timeout value" in e.message for e in errors), (
        f"Bulgu #10 over-relaxation regression: timeout value '{value}' "
        f"slipped past the heuristic. HAProxy would reject this at parse."
    )


def test_timeout_regex_rejects_legacy_ms_was_pre_fix_failure_mode():
    """Documentary pin — the EXACT failure mode reported by the
    operator (Image #8 of Phase K Phase D Bulgu #10): the wizard's
    default `timeout connect 10000ms` flagged ERROR on Step 4. Pin
    that the value is accepted post-fix.
    """
    for tval in ("10000ms", "60000ms", "100ms"):
        results = _validate_timeout_only(["connect", tval])
        for r in results:
            if r.level == ValidationLevel.ERROR:
                assert "Invalid timeout value" not in r.message, (
                    f"Bulgu #10 post-fix pin: the wizard-default "
                    f"timeout value '{tval}' must be accepted by "
                    f"the heuristic validator. Got error: {r.message}"
                )
