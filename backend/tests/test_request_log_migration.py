"""v1.11.0: the request_logs migration actually runs on existing installs.

Source-scan tests (the sanctioned pattern here — there is no database in this
suite). The failure mode being pinned is specific and silent: migrations are
gated on `applied_version >= SCHEMA_VERSION`, so forgetting the bump means the
whole sequence is skipped on every already-deployed database and neither the
table nor the new permissions ever appear — while a fresh install works fine,
so it looks correct in development.
"""
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MIGRATIONS = os.path.join(_BACKEND, "database", "migrations.py")
_MAIN = os.path.join(_BACKEND, "main.py")


@pytest.fixture(scope="module")
def src():
    with open(_MIGRATIONS, encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def runner_body(src):
    """The body of _run_all_migrations_inner, where steps are registered."""
    assert "async def _run_all_migrations_inner" in src
    return src.split("async def _run_all_migrations_inner", 1)[1].split("\nasync def ", 1)[0]


@pytest.fixture(scope="module")
def rbac_body(src):
    return src.split("async def update_system_roles_to_enterprise_rbac", 1)[1].split("\nasync def ", 1)[0]


def _role_block(rbac_body, role):
    """Slice one role's permission list out of the enterprise_roles literal."""
    start = rbac_body.index(f"'{role}': {{")
    end = rbac_body.index("]", rbac_body.index("'permissions': [", start))
    return rbac_body[start:end]


# --------------------------------------------------------------------------
# The version gate
# --------------------------------------------------------------------------

def test_schema_version_bumped_to_at_least_11(src):
    match = re.search(r"^SCHEMA_VERSION\s*=\s*(\d+)", src, re.MULTILINE)
    assert match, "SCHEMA_VERSION assignment not found in migrations.py"
    assert int(match.group(1)) >= 11, (
        "SCHEMA_VERSION was not bumped for the request_logs table. run_all_migrations() "
        "returns early when the recorded version is already >= SCHEMA_VERSION, so every "
        "existing deployment would skip the whole run: no request_logs table, no "
        "requestlog.* permissions, and the feature would silently do nothing in production "
        "while working perfectly on a fresh database."
    )


# --------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------

def test_both_migration_steps_are_registered(runner_body):
    assert "await ensure_request_logs_table()" in runner_body, (
        "ensure_request_logs_table is defined but never called from the migration runner"
    )
    assert "await ensure_request_log_settings()" in runner_body, (
        "the retention defaults are never seeded, so an upgraded install has no "
        "requestlog.* rows and Settings shows blanks"
    )


def test_table_is_created_before_its_settings_are_seeded(runner_body):
    table_at = runner_body.index("await ensure_request_logs_table()")
    seed_at = runner_body.index("await ensure_request_log_settings()")
    assert table_at < seed_at, (
        "the settings seed runs before the table step; if the table step then raises, the "
        "run aborts with settings but no table"
    )


# --------------------------------------------------------------------------
# The DDL itself
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def ddl_body(src):
    return src.split("async def ensure_request_logs_table", 1)[1].split("\nasync def ", 1)[0]


@pytest.mark.parametrize("fragment", [
    "CREATE TABLE IF NOT EXISTS request_logs",
    "id                  BIGSERIAL PRIMARY KEY",
    "request_id          VARCHAR(64) NOT NULL",
    "direction           VARCHAR(8)  NOT NULL",
    "status_class        SMALLINT",
    "created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()",
    "request_logs_direction_check",
    "client_ip           INET",
])
def test_ddl_essentials(ddl_body, fragment):
    assert fragment in ddl_body, f"request_logs DDL is missing {fragment!r}"


def test_ddl_is_idempotent(ddl_body):
    assert "CREATE TABLE IF NOT EXISTS" in ddl_body
    creates = re.findall(r"CREATE INDEX(?: IF NOT EXISTS)?", ddl_body)
    assert creates, "no indexes are created for request_logs"
    assert all(c == "CREATE INDEX IF NOT EXISTS" for c in creates), (
        "an index is created without IF NOT EXISTS — the second startup would raise and "
        "abort the whole migration run"
    )


def test_prune_partial_indexes_are_present(ddl_body):
    """The retention delete is split by outcome, so a plain
    (status_class, created_at) index would still range-scan the half it does not
    want."""
    assert "idx_request_logs_prune_ok" in ddl_body
    assert "idx_request_logs_prune_err" in ddl_body
    assert "WHERE status_class BETWEEN 1 AND 3" in ddl_body
    assert "WHERE status_class = 0 OR status_class >= 4" in ddl_body


def test_request_id_index_exists_for_the_trace_view(ddl_body):
    assert "idx_request_logs_request_id" in ddl_body, (
        "without this index, opening one request to see the outbound calls it triggered "
        "is a sequential scan"
    )


def test_no_foreign_key_on_user_id(ddl_body):
    """Deliberate deviation from the house style — see the docstring in
    migrations.py. Pinned so it is not 'fixed' back into an FK later."""
    user_id_line = [line for line in ddl_body.splitlines() if "user_id " in line and "INTEGER" in line]
    assert user_id_line, "user_id column not found"
    assert "REFERENCES" not in user_id_line[0], (
        "an FK was added to request_logs.user_id — per-insert FK validation on the "
        "highest-volume table in the system, and audit rows must outlive the account"
    )


def test_migration_step_reraises_on_failure(ddl_body):
    """The version marker is written only after the inner sequence completes, so
    swallowing here would stamp version 11 with no table and the gate would then
    skip every retry, permanently."""
    assert re.search(r"\n\s+raise\n", ddl_body), (
        "ensure_request_logs_table swallows its exception instead of re-raising"
    )


def test_settings_seed_does_not_overwrite_operator_tuning(src):
    seed_body = src.split("async def ensure_request_log_settings", 1)[1].split("\nasync def ", 1)[0]
    assert "ON CONFLICT (key) DO NOTHING" in seed_body, (
        "the seed uses DO UPDATE, so every upgrade would reset the operator's retention "
        "settings back to the defaults"
    )


# --------------------------------------------------------------------------
# Permission seeding
# --------------------------------------------------------------------------

def test_super_admin_gets_both_permissions(rbac_body):
    block = _role_block(rbac_body, "super_admin")
    assert "'requestlog.read'" in block
    assert "'requestlog.manage'" in block


def test_security_admin_gets_both_permissions(rbac_body):
    block = _role_block(rbac_body, "security_admin")
    assert "'requestlog.read'" in block
    assert "'requestlog.manage'" in block


def test_operator_gets_read_only(rbac_body):
    block = _role_block(rbac_body, "operator")
    assert "'requestlog.read'" in block
    assert "'requestlog.manage'" not in block, (
        "operators should be able to read the log to debug an apply or an ACME order, but "
        "retention policy and purge belong to the admins"
    )


def test_viewer_gets_neither(rbac_body):
    block = _role_block(rbac_body, "viewer")
    assert "requestlog" not in block, (
        "viewer was granted a requestlog permission. Even redacted, captured request and "
        "response bodies are a far broader disclosure surface than the read-only config "
        "views a viewer is meant to have."
    )


def test_permission_strings_have_exactly_one_dot(rbac_body):
    """get_user_permissions splits on the FIRST dot and silently drops any
    string without one."""
    for perm in re.findall(r"'(requestlog[^']*)'", rbac_body):
        assert perm.count(".") == 1, f"{perm!r} is not a <resource>.<action> pair"


def test_initial_seed_lists_stay_in_sync(src):
    """create_initial_system_data() is overwritten by the enterprise seeder on
    every run, but that seeder swallows all exceptions — keeping the two in sync
    is the safety net."""
    initial = src.split("system_roles = [", 1)[1].split("\n        ]", 1)[0]
    assert '"requestlog.read"' in initial
    assert '"requestlog.manage"' in initial


# --------------------------------------------------------------------------
# Runtime wiring
# --------------------------------------------------------------------------

def test_prune_loop_is_started_and_independent_of_the_acme_loop():
    with open(_MAIN, encoding="utf-8") as f:
        main_src = f.read()

    assert "async def prune_request_logs_loop" in main_src
    assert "asyncio.create_task(prune_request_logs_loop())" in main_src, (
        "the retention prune task is defined but never started, so request_logs grows "
        "without bound"
    )
    loop_body = main_src.split("async def prune_request_logs_loop", 1)[1].split("\n# Production middleware", 1)[0]
    assert "table_name = 'request_logs'" in loop_body, (
        "the prune loop does not check for its own table, so it would log an error every "
        "tick on a database where the migration has not run yet"
    )
    assert "table_name = 'letsencrypt_orders'" not in loop_body, (
        "the prune loop was gated on the ACME table, which would disable retention "
        "entirely on an install that never uses ACME"
    )


def test_sink_is_flushed_before_the_pool_closes():
    with open(_MAIN, encoding="utf-8") as f:
        main_src = f.read()

    body = main_src.split("async def shutdown_event", 1)[1]
    flush_at = body.find("request_log_sink.flush")
    close_at = body.find("close_database_pool()")
    assert flush_at != -1, "queued request-log rows are never flushed on shutdown"
    assert flush_at < close_at, (
        "the sink is flushed after the pool is closed, so the queued rows are lost. The "
        "sink's writer is a `while True` loop and can never satisfy the generic "
        "asyncio.wait drain, so it needs its own explicit flush first."
    )
