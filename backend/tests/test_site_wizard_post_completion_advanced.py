"""v1.5.0 R12 — _execute_post_completion_actions advanced field forwarding.

Bulgu #f1 (CRITICAL): the SimpleNamespace shim assembled inside
routers/letsencrypt.py::_execute_post_completion_actions used to forward
only a handful of frontend fields (name, mode, bind_*, default_backend,
acl/redirect/use_backend rules, timeout_*, maxconn, options) — silently
dropping HSTS / ALPN / TLS-version / compression / monitor_uri /
log_separate / rate_limit / request_headers / strict-sni / ciphers /
ciphersuites for ACME-issued HTTPS frontends.

User-visible symptom: "I enabled HSTS in the wizard but the resulting
HTTPS frontend doesn't have it" after the LE order completed.

These tests pin the FULL list of forwarded keys via static source-code
assertions so a future refactor cannot silently regress the bug.
"""
from pathlib import Path

import pytest


SOURCE = (
    Path(__file__).resolve().parent.parent
    / "routers"
    / "letsencrypt.py"
).read_text()


# Every key the wizard may store on frontend_config (matches the dict
# built in routers/site_wizard.py::create_proxied_host for ACME mode).
# NOTE: `ssl_enabled` is intentionally NOT in this list — it's hardcoded
# to True at the SimpleNamespace level (post-completion only fires when
# we successfully completed an HTTPS cert), so it does NOT come from
# fe_cfg.get(...).
_REQUIRED_FORWARDED_KEYS = [
    # core
    "name", "bind_address", "bind_port", "default_backend", "mode",
    # routing
    "acl_rules", "redirect_rules", "use_backend_rules",
    # tcp-mode
    "tcp_request_rules",
    # timeouts + capacity
    "timeout_client", "timeout_http_request", "maxconn", "rate_limit",
    # observability + traffic shaping
    "compression", "log_separate", "monitor_uri",
    # header injection (HSTS lands here)
    "request_headers", "response_headers",
    # raw HAProxy options
    "options",
    # advanced TLS — HAProxy 2.4+ bind directives
    "ssl_alpn", "ssl_ciphers", "ssl_ciphersuites",
    "ssl_min_ver", "ssl_max_ver", "ssl_strict_sni",
]


@pytest.mark.parametrize("key", _REQUIRED_FORWARDED_KEYS)
def test_post_completion_simple_namespace_forwards_key(key):
    """Each of the wizard-managed frontend_config keys must be referenced
    by name inside _execute_post_completion_actions's SimpleNamespace
    shim. We use a literal substring match (`fe_cfg.get("KEY")` or
    `KEY=fe_cfg.get`) — both forms appear in the source — and require
    AT LEAST one of them.
    """
    fe_cfg_get = f'fe_cfg.get("{key}"'
    kwarg_form = f'{key}=fe_cfg.get'
    assert fe_cfg_get in SOURCE or kwarg_form in SOURCE, (
        f"Bulgu #f1 regression: routers/letsencrypt.py::"
        f"_execute_post_completion_actions does not forward "
        f"frontend_config.{key} to the create_frontend_row payload. "
        f"This silently drops the wizard's user-selected setting for "
        f"ACME-issued HTTPS frontends."
    )


def test_post_completion_schema_version_2_understood():
    """v1.5.0 R12 bumped schema_version to 2 to mark the action as
    carrying the extended TLS/HSTS/header field set. The reader does
    not switch on schema_version (forward-compat by reading via
    fe_cfg.get with default=None), but we assert the marker is at
    least documented in the calling site for future maintainers."""
    proxied_host_src = (
        Path(__file__).resolve().parent.parent
        / "routers"
        / "site_wizard.py"
    ).read_text()
    assert '"schema_version": 2' in proxied_host_src, (
        "Wizard create_proxied_host should set post_completion_action.schema_version=2 "
        "when emitting the extended TLS/HSTS field set."
    )
