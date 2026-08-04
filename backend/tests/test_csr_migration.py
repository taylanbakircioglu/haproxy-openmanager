"""
v1.9.0 CSR creation — static source assertions (pattern: test_vip_purge.py).

Guards the migration wiring that a unit test cannot exercise without a real
database: the SCHEMA_VERSION bump (without it, deployed installs skip the
whole migration run and the ssl_csrs table never appears), the migration
registration, the security-relevant DDL, and the router registration.
"""
import os
import re

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel_path: str) -> str:
    with open(os.path.join(_BACKEND_DIR, rel_path), encoding="utf-8") as f:
        return f.read()


def test_schema_version_bumped_to_10():
    src = _read(os.path.join("database", "migrations.py"))
    m = re.search(r"^SCHEMA_VERSION\s*=\s*(\d+)", src, re.MULTILINE)
    assert m, "SCHEMA_VERSION constant not found in migrations.py"
    assert int(m.group(1)) >= 10, (
        "SCHEMA_VERSION must be >= 10 for the v1.9.0 ssl_csrs table — "
        "without the bump, existing installs (version >= 9) skip the whole "
        "migration run and never gain the table."
    )


def test_ssl_csrs_migration_defined_and_registered():
    src = _read(os.path.join("database", "migrations.py"))
    assert "async def ensure_ssl_csrs_table" in src

    inner = src.split("async def _run_all_migrations_inner", 1)[1]
    inner = inner.split("\nasync def ", 1)[0]  # body of the runner only
    assert "await ensure_ssl_csrs_table()" in inner, (
        "ensure_ssl_csrs_table must be invoked from _run_all_migrations_inner"
    )


def test_ssl_csrs_ddl_essentials():
    src = _read(os.path.join("database", "migrations.py"))
    ddl_start = src.index("CREATE TABLE IF NOT EXISTS ssl_csrs")
    ddl = src[ddl_start:ddl_start + 2500]

    assert "private_key_pem TEXT" in ddl
    assert "name VARCHAR(100) NOT NULL" in ddl, (
        "ssl_csrs.name must align with ssl_certificates.name VARCHAR(100)"
    )
    assert "ssl_certificate_id INTEGER REFERENCES ssl_certificates(id) ON DELETE SET NULL" in ddl, (
        "deleting the imported cert must not cascade into CSR history"
    )
    # Partial unique index: only PENDING CSRs reserve their target cert name.
    assert "uq_ssl_csrs_name_pending" in src
    assert re.search(
        r"uq_ssl_csrs_name_pending\s+ON\s+ssl_csrs\(name\)\s+WHERE\s+status\s*=\s*'pending'",
        src,
    ), "name uniqueness must be scoped to pending CSRs (partial index)"


def test_csr_router_registered_in_main():
    src = _read("main.py")
    assert "from routers.csr import router as csr_router" in src
    assert "app.include_router(csr_router)" in src


def test_csr_endpoint_permission_mapping():
    """Pin which ssl.<action> permission each endpoint enforces: a regression
    that dropped or weakened a _require() call would otherwise pass the
    auth-rejection tests (they only assert 401/403 for unauthenticated calls)."""
    src = _read(os.path.join("routers", "csr.py"))

    def _handler_body(decorator):
        start = src.index(decorator)
        nxt = src.find("@router.", start + 1)
        return src[start:nxt if nxt != -1 else len(src)]

    expectations = [
        ('@router.post("")', '"create"'),
        ('@router.get("")', '"read"'),
        ('@router.get("/{csr_id}")', '"read"'),
        ('@router.post("/{csr_id}/import")', '"create"'),
        ('@router.delete("/{csr_id}")', '"delete"'),
    ]
    for decorator, action in expectations:
        body = _handler_body(decorator)
        assert f"_require(authorization, {action})" in body, (
            f"endpoint {decorator} must enforce ssl.{action.strip(chr(34))}"
        )


def test_csr_router_never_selects_private_key():
    """The CSR endpoints must use the explicit column list — a bare
    `SELECT *` into an API response is how the key would leak. The one place
    SELECT * is allowed is the service-layer FOR UPDATE row (it needs the key
    to pair with the cert); the router itself must not touch the column."""
    src = _read(os.path.join("routers", "csr.py"))
    code_only = re.sub(r"#.*", "", src)  # strip comments; the column name may
    # legitimately appear there as documentation
    assert "private_key_pem" not in code_only, (
        "routers/csr.py must never reference private_key_pem in code"
    )
    assert "SELECT *" not in code_only, "routers/csr.py must use explicit column lists"
