"""v1.11.0: the retention policy the operator sees is the policy that runs.

Two things drift silently and are caught here:

  1. The defaults live in TWO places — the seed SQL in migrations.py and the
     dataclass in utils/request_log_settings.py. If they disagree, a fresh
     install and an upgraded install behave differently, which is the worst
     kind of bug to chase.
  2. Values in `system_settings` are operator-editable and arrive from asyncpg
     as raw JSON *strings*. Anything out of range, mistyped or hand-edited must
     be clamped rather than crash the writer loop.
"""
import asyncio
import json
import os
import re
import sys
from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import request_log_settings  # noqa: E402
from utils.request_log_settings import (  # noqa: E402
    DEFAULT_CONFIG,
    DEFAULT_EXCLUDE_PATHS,
    RequestLogConfig,
    config_from_mapping,
    get_config,
    normalize_exclude_paths,
    refresh_config,
    set_config,
)

_MIGRATIONS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "database", "migrations.py"
)


def _seeded_defaults():
    """Parse the ('requestlog.x', 'value', ...) tuples out of the seed SQL."""
    with open(_MIGRATIONS, encoding="utf-8") as f:
        src = f.read()

    body = src.split("async def ensure_request_log_settings", 1)[1].split("\nasync def ", 1)[0]
    out = {}
    for key, raw in re.findall(r"\('requestlog\.(\w+)', '(.*?)', 'requestlog'", body):
        try:
            out[key] = json.loads(raw)
        except json.JSONDecodeError:
            out[key] = raw
    return out


# --------------------------------------------------------------------------
# Defaults must not drift between the seed and the code
# --------------------------------------------------------------------------

def test_seed_and_dataclass_defaults_agree():
    seeded = _seeded_defaults()
    assert seeded, "could not parse the requestlog seed rows out of migrations.py"

    code = DEFAULT_CONFIG.as_dict()
    for key, seed_value in seeded.items():
        assert key in code, f"migrations seeds requestlog.{key} but RequestLogConfig has no such field"
        assert code[key] == seed_value, (
            f"requestlog.{key} default drifted: migrations.py seeds {seed_value!r} but "
            f"RequestLogConfig has {code[key]!r}. A fresh install and an upgraded install "
            f"would then behave differently."
        )

    for key in code:
        assert key in seeded, (
            f"RequestLogConfig has {key!r} but migrations.py does not seed requestlog.{key} — "
            f"existing installs would silently fall back to the in-code default"
        )


def test_log_viewer_is_excluded_by_default():
    assert "/api/request-logs" in DEFAULT_EXCLUDE_PATHS
    assert "/api/health" in DEFAULT_EXCLUDE_PATHS
    assert "/.well-known/acme-challenge" in DEFAULT_EXCLUDE_PATHS, (
        "the ACME challenge endpoint returns key_authorization — logging it would store "
        "the challenge secret"
    )
    assert "/api/agents/heartbeat" in DEFAULT_EXCLUDE_PATHS, (
        "the agent heartbeat is the highest-volume POST in the system; logging it by "
        "default would dominate the table"
    )


def test_error_retention_defaults_longer_than_success_retention():
    assert DEFAULT_CONFIG.error_retention_days > DEFAULT_CONFIG.success_retention_days, (
        "the whole point of splitting the two is to keep failures around after the "
        "ordinary traffic has aged out"
    )


# --------------------------------------------------------------------------
# Coercion and clamping
# --------------------------------------------------------------------------

def test_raw_json_strings_from_asyncpg_are_parsed():
    cfg = config_from_mapping({
        "enabled": True,
        "max_body_bytes": 4096,
        "sample_rate": 0.25,
        "success_retention_days": 3,
        "exclude_paths": ["/api/health", "/metrics"],
    })
    assert cfg.enabled is True
    assert cfg.max_body_bytes == 4096
    assert cfg.sample_rate == 0.25
    assert cfg.success_retention_days == 3
    assert cfg.exclude_paths == ("/api/health", "/metrics")


@pytest.mark.parametrize("raw,expected", [
    ("true", True), ("false", False), ("1", True), ("0", False),
    ("on", True), ("off", False), (1, True), (0, False), (True, True),
])
def test_boolean_coercion_accepts_hand_written_values(raw, expected):
    cfg = config_from_mapping({"enabled": raw})
    assert cfg.enabled is expected


@pytest.mark.parametrize("field,value,expected", [
    ("max_body_bytes", 10_000_000, 262144),
    ("max_body_bytes", -5, 0),
    ("success_retention_days", 0, 1),
    ("success_retention_days", 9999, 365),
    ("error_retention_days", 0, 1),
    ("max_rows", 10, 1000),
    ("prune_interval_minutes", 1, 5),
    ("prune_interval_minutes", 99999, 1440),
])
def test_out_of_range_values_are_clamped_not_rejected(field, value, expected):
    """A bad value in the table must not disable logging or crash the writer —
    it is clamped to the nearest sane bound."""
    cfg = config_from_mapping({field: value})
    assert getattr(cfg, field) == expected


@pytest.mark.parametrize("value,expected", [(1.5, 1.0), (-0.2, 0.0), ("0.4", 0.4)])
def test_sample_rate_is_clamped(value, expected):
    assert config_from_mapping({"sample_rate": value}).sample_rate == expected


def test_garbage_values_fall_back_to_the_default():
    cfg = config_from_mapping({"max_body_bytes": "not-a-number", "sample_rate": "abc"})
    assert cfg.max_body_bytes == DEFAULT_CONFIG.max_body_bytes
    assert cfg.sample_rate == DEFAULT_CONFIG.sample_rate


def test_exclude_paths_shape_is_enforced():
    out = normalize_exclude_paths(
        ["/good", "no-leading-slash", "/" + "x" * 500, 42, "/also-good"],
        DEFAULT_EXCLUDE_PATHS,
    )
    assert out == ("/good", "/also-good")


def test_exclude_paths_count_is_bounded():
    out = normalize_exclude_paths([f"/p{i}" for i in range(500)], DEFAULT_EXCLUDE_PATHS)
    assert len(out) <= 64


def test_empty_exclude_paths_falls_back_rather_than_logging_everything():
    """An empty list would re-enable logging of health checks and the docs, and
    flood the table — treat it as 'not configured'."""
    assert normalize_exclude_paths([], DEFAULT_EXCLUDE_PATHS) == DEFAULT_EXCLUDE_PATHS
    assert normalize_exclude_paths(None, DEFAULT_EXCLUDE_PATHS) == DEFAULT_EXCLUDE_PATHS


def test_partial_mapping_keeps_the_other_defaults():
    cfg = config_from_mapping({"sample_rate": 0.5})
    assert cfg.sample_rate == 0.5
    assert cfg.success_retention_days == DEFAULT_CONFIG.success_retention_days
    assert cfg.enabled is DEFAULT_CONFIG.enabled


# --------------------------------------------------------------------------
# refresh_config
# --------------------------------------------------------------------------

def test_refresh_config_parses_the_raw_jsonb_strings_asyncpg_returns():
    conn = AsyncMock()
    conn.fetch = AsyncMock(return_value=[
        {"key": "requestlog.enabled", "value": "false"},
        {"key": "requestlog.max_body_bytes", "value": "4096"},
        {"key": "requestlog.sample_rate", "value": "0.5"},
        {"key": "requestlog.exclude_paths", "value": '["/api/health","/metrics"]'},
    ])

    with patch.object(request_log_settings, "get_database_connection", AsyncMock(return_value=conn)), \
         patch.object(request_log_settings, "close_database_connection", AsyncMock()):
        cfg = asyncio.run(refresh_config())

    assert cfg.enabled is False
    assert cfg.max_body_bytes == 4096
    assert cfg.sample_rate == 0.5
    assert cfg.exclude_paths == ("/api/health", "/metrics")

    set_config(DEFAULT_CONFIG)


def test_refresh_config_keeps_the_previous_snapshot_on_db_failure():
    """A transient pool error must not silently flip logging on or off."""
    known = RequestLogConfig(enabled=False, sample_rate=0.1)
    set_config(known)

    with patch.object(request_log_settings, "get_database_connection",
                      AsyncMock(side_effect=RuntimeError("pool exhausted"))), \
         patch.object(request_log_settings, "close_database_connection", AsyncMock()):
        cfg = asyncio.run(refresh_config())

    assert cfg.enabled is False
    assert cfg.sample_rate == 0.1
    set_config(DEFAULT_CONFIG)


def test_get_config_is_synchronous_and_needs_no_database():
    """The middleware calls this on every request; it must never await."""
    assert not asyncio.iscoroutinefunction(get_config)
    assert isinstance(get_config(), RequestLogConfig)


# --------------------------------------------------------------------------
# The Pydantic model the API exposes
# --------------------------------------------------------------------------

def test_api_model_defaults_match_the_dataclass():
    from routers.request_logs import RequestLogSettings

    model = RequestLogSettings().model_dump()
    code = DEFAULT_CONFIG.as_dict()
    for key, value in code.items():
        assert model[key] == value, f"API model default for {key} disagrees with RequestLogConfig"


@pytest.mark.parametrize("payload", [
    {"max_body_bytes": 999999},
    {"success_retention_days": 0},
    {"error_retention_days": 400},
    {"sample_rate": 1.5},
    {"max_rows": 10},
    {"prune_interval_minutes": 1},
    {"exclude_paths": ["no-slash"]},
    {"exclude_paths": ["/" + "x" * 300]},
])
def test_api_model_rejects_out_of_range_input(payload):
    from pydantic import ValidationError

    from routers.request_logs import RequestLogSettings

    with pytest.raises(ValidationError):
        RequestLogSettings(**payload)
