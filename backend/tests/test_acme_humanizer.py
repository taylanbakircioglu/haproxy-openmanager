"""
v1.5.0 Feature A — humanize_error_detail() unit tests.

Table-driven coverage of the RFC8555 problem types we humanize, plus
backwards-compatible behaviour for legacy plain-string error_detail values
that were written by v1.3.x and earlier.
"""
import json
import pytest

from services.acme_diagnostics import humanize_error_detail, _PROBLEM_HUMANIZED


# ----------------------------------------------------------------------------
# 1. Static coverage — we promise >= 11 RFC8555 problem types are humanized.
# ----------------------------------------------------------------------------


def test_humanizes_at_least_11_rfc8555_problem_types():
    assert len(_PROBLEM_HUMANIZED) >= 11


def test_every_humanized_entry_has_title_and_hint():
    for ptype, body in _PROBLEM_HUMANIZED.items():
        assert "title" in body and body["title"], ptype
        assert "hint" in body, ptype


# ----------------------------------------------------------------------------
# 2. Empty / None handling.
# ----------------------------------------------------------------------------


def test_none_returns_no_error_marker():
    out = humanize_error_detail(None)
    assert out["title"] == "No error"
    assert out["message"] == ""


def test_empty_string_returns_no_error_marker():
    out = humanize_error_detail("")
    assert out["title"] == "No error"


# ----------------------------------------------------------------------------
# 3. Legacy plain-string fallback (pre-v1.5.0 stored unstructured strings).
# ----------------------------------------------------------------------------


def test_legacy_plain_string_falls_back_cleanly():
    out = humanize_error_detail("connection refused: agent offline")
    assert out["title"] == "ACME error"
    assert "connection refused" in out["message"]
    # The hint is empty because we don't have a structured problem type.
    assert out["hint"] == ""
    assert out["raw"] == "connection refused: agent offline"


def test_legacy_plain_string_with_brace_but_invalid_json_falls_back():
    # Defensive: '{' prefix is the trigger for JSON parse, but garbled JSON
    # must NOT raise. It should fall through to the legacy string path.
    out = humanize_error_detail("{not valid json{")
    assert out["title"] == "ACME error"
    assert out["raw"] == "{not valid json{"


# ----------------------------------------------------------------------------
# 4. Structured RFC8555 problem types — table-driven across 11+ entries.
# ----------------------------------------------------------------------------


@pytest.mark.parametrize("problem_type,detail_text,expected_title_contains", [
    ("urn:ietf:params:acme:error:rateLimited", "too many orders",       "rate limit"),
    ("urn:ietf:params:acme:error:dns",          "no A record",          "DNS"),
    ("urn:ietf:params:acme:error:caa",          "issuance forbidden",   "CAA"),
    ("urn:ietf:params:acme:error:connection",   "timeout to :80",       "could not connect"),
    ("urn:ietf:params:acme:error:incorrectResponse", "wrong key auth",  "challenge response"),
    ("urn:ietf:params:acme:error:unauthorized", "verification failed",  "Unauthorized"),
    ("urn:ietf:params:acme:error:malformed",    "missing field 'csr'",  "Malformed"),
    ("urn:ietf:params:acme:error:badNonce",     "stale nonce",          "nonce"),
    ("urn:ietf:params:acme:error:rejectedIdentifier", "blacklisted",    "rejected"),
    ("urn:ietf:params:acme:error:serverInternal", "internal err",       "ACME server"),
    ("urn:ietf:params:acme:error:userActionRequired", "agree to ToS",   "User action"),
])
def test_known_problem_types_are_humanized(problem_type, detail_text, expected_title_contains):
    payload = json.dumps({"type": problem_type, "detail": detail_text, "status": 400})
    out = humanize_error_detail(payload)
    assert expected_title_contains.lower() in out["title"].lower(), (
        f"Title '{out['title']}' missing expected substring '{expected_title_contains}'"
    )
    assert out["message"] == detail_text
    assert out["status"] == 400
    assert out["type"] == problem_type
    # Hint should be a non-empty operator-targeted string
    assert isinstance(out["hint"], str) and len(out["hint"]) > 10


def test_unknown_problem_type_falls_back_to_generic_title():
    payload = json.dumps({
        "type": "urn:ietf:params:acme:error:notARealType",
        "detail": "future error",
        "status": 500,
    })
    out = humanize_error_detail(payload)
    assert out["title"] == "ACME error"
    assert out["message"] == "future error"
    assert out["hint"] == ""
    assert out["status"] == 500
    assert out["type"] == "urn:ietf:params:acme:error:notARealType"


# ----------------------------------------------------------------------------
# 5. Subproblems (per-domain failures) flatten cleanly.
# ----------------------------------------------------------------------------


def test_subproblems_are_flattened():
    payload = json.dumps({
        "type": "urn:ietf:params:acme:error:malformed",
        "detail": "multiple validation failures",
        "status": 400,
        "subproblems": [
            {
                "type": "urn:ietf:params:acme:error:dns",
                "detail": "no record for foo",
                "identifier": {"type": "dns", "value": "foo.example.com"},
            },
            {
                "type": "urn:ietf:params:acme:error:caa",
                "detail": "caa forbids",
                "identifier": {"type": "dns", "value": "bar.example.com"},
            },
        ],
    })
    out = humanize_error_detail(payload)
    assert "subproblems" in out
    assert len(out["subproblems"]) == 2
    sp = {item["identifier"]: item for item in out["subproblems"]}
    assert sp["foo.example.com"]["type"] == "urn:ietf:params:acme:error:dns"
    assert sp["bar.example.com"]["detail"] == "caa forbids"


def test_subproblems_with_garbage_entries_are_filtered():
    payload = json.dumps({
        "type": "urn:ietf:params:acme:error:malformed",
        "detail": "x",
        "subproblems": [
            "not a dict",                      # filtered out
            None,                              # filtered out
            {"type": "urn:ietf:params:acme:error:dns", "detail": "ok"},
        ],
    })
    out = humanize_error_detail(payload)
    assert len(out["subproblems"]) == 1
    assert out["subproblems"][0]["detail"] == "ok"


# ----------------------------------------------------------------------------
# 6. Dict input is accepted directly (avoids double-encode in some callers).
# ----------------------------------------------------------------------------


def test_dict_input_handled_directly():
    out = humanize_error_detail({
        "type": "urn:ietf:params:acme:error:rateLimited",
        "detail": "limit reached",
        "status": 429,
    })
    assert "rate limit" in out["title"].lower()
    assert out["message"] == "limit reached"
    assert out["status"] == 429
