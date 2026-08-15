"""v1.11.0: redaction pinned against THIS codebase's real payloads.

test_request_log_redaction.py pins the RULES — which key names match, which
value shapes fire. It passed 72/72 while six real endpoints of this application
still wrote secrets to `request_logs`, because a rule test proves the rule, not
the coverage. Every case here is built from an actual handler's request or
response shape, with the field names taken from the source and named in the
docstring, so a future change to redaction is measured against what this system
actually sends rather than against what someone remembered to imagine.

Method note: the payloads go through `decode_body()`, the same entry point the
writer task uses, rather than calling `redact()` directly. That is deliberate —
two of the findings below only appear on the way in (an oversized body never
reaches `redact()` as a dict at all, it arrives as one `_raw` string), so a test
that starts from a dict would report a pass on a payload that leaks in
production.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.request_log_redaction import (  # noqa: E402
    decode_body,
    is_secret_key,
    redact_headers,
)

VRRP_SECRET = "S3cr3tVrrpPass!"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
STATS_PASSWORD = "StatsPa55word"
USERLIST_HASH = "$6$rounds=5000$abcdefgh$XyZ"
JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxIiwidXNlcm5hbWUiOiJhZG1pbiJ9"
    ".dQw4w9WgXcQdQw4w9WgXcQdQw4w9WgXcQ"
)
PEM_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    + "MIIEowIBAAKCAQEA" + "A" * 200 + "\n"
    + "-----END RSA PRIVATE KEY-----\n"
)

# The rendered file `GET /api/agents/{n}/keepalived-config` hands to an agent,
# and the one `POST /api/agents/{n}/keepalived-discovery` sends back.
KEEPALIVED_CONF = f"""! Managed by HAProxy OpenManager
vrrp_instance VI_1 {{
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 200
    advert_int 1
    authentication {{
        auth_type PASS
        auth_pass {VRRP_SECRET}
    }}
    virtual_ipaddress {{
        10.20.30.40/24
    }}
}}
"""

# A production haproxy.cfg as the agent uploads it verbatim from the node
# (`config_content=$(cat "$config_path")` -> POST .../config-response).
HAPROXY_CFG = f"""global
    log stdout local0
    stats socket /var/run/haproxy.sock mode 660

userlist admins
    user ops password {USERLIST_HASH}
    user dev insecure-password Hunter2Plain

listen stats
    bind *:8404
    stats enable
    stats auth admin:{STATS_PASSWORD}
    stats uri /stats

backend web
    server web1 10.0.0.1:80 check
"""


def _capture(payload, *, cap=8192, content_type="application/json"):
    """Run a payload through the capture path exactly as the writer does.

    `cap` is `requestlog.max_body_bytes`. Bodies larger than it arrive
    truncated, do not parse as JSON, and land in the `{"_raw": ...}` fallback —
    which is the common case for config uploads and the case a dict-based test
    never exercises.
    """
    body = json.dumps(payload).encode()
    value, truncated = decode_body(body[:cap], content_type, len(body))
    return json.dumps(value, default=str), truncated


def _assert_absent(rendered, *secrets):
    for secret in secrets:
        assert secret not in rendered, (
            f"{secret!r} reached request_logs. Rendered row: {rendered[:400]}"
        )


# --------------------------------------------------------------------------
# The VRRP password. routers/vip.py: "the secret never leaves the server in
# cleartext ... only the at-rest Fernet token and the agent-delivery endpoint
# ever see the real value."
# --------------------------------------------------------------------------

def test_vip_create_body_does_not_store_auth_pass():
    """POST/PUT /api/vip — `payload.auth_pass`, routers/vip.py:585,679."""
    rendered, _ = _capture({
        "name": "vip-prod", "virtual_ip": "10.20.30.40", "interface": "eth0",
        "virtual_router_id": 51, "auth_pass": VRRP_SECRET,
    })
    _assert_absent(rendered, VRRP_SECRET)


def test_keepalived_config_delivery_does_not_store_the_rendered_secret():
    """GET /api/agents/{n}/keepalived-config — `keepalived.config_content`.

    Polled on the SSL cadence, so an unmasked capture rewrites the secret to the
    audit table roughly 576 times a day per member node.
    """
    rendered, _ = _capture({
        "agent_name": "prod-lb-01", "status": "available",
        "config_path": "/etc/keepalived/keepalived.conf",
        "keepalived": {
            "vip_id": 3, "vip_name": "vip-prod",
            "config_content": KEEPALIVED_CONF, "config_hash": "abc123",
        },
    })
    _assert_absent(rendered, VRRP_SECRET)
    assert "auth_pass" in rendered, "the directive should stay visible, only its value masked"
    assert "vrrp_instance VI_1" in rendered, "masking must not destroy the rest of the config"


def test_keepalived_discovery_body_does_not_store_the_found_secret():
    """POST /api/agents/{n}/keepalived-discovery — `config_content`.

    routers/agent.py already pops auth_pass out of the parsed analysis,
    Fernet-encrypts it into its own column and stores only
    `vip_discoveries.raw_config_masked`. Capturing the request that produced all
    that, unmasked, would put the plaintext straight back next to it.
    """
    rendered, _ = _capture({
        "agent_name": "prod-lb-01", "exists": True, "is_managed": False,
        "config_path": "/etc/keepalived/keepalived.conf",
        "config_content": KEEPALIVED_CONF,
    })
    _assert_absent(rendered, VRRP_SECRET)


def test_auth_pass_is_masked_when_the_body_is_too_large_to_parse():
    """The truncated `_raw` path, where line breaks are the escape `\\n`.

    A value pattern that stops only at a REAL newline runs to the end of the
    string here: no leak, but the whole remainder of the config is masked and
    the row is useless. Both properties are asserted.
    """
    payload = {"config_content": KEEPALIVED_CONF + "backend b\n    server s1 10.0.0.1:80 check\n" * 400}
    rendered, truncated = _capture(payload)
    assert truncated, "this fixture must exercise the truncated path"
    _assert_absent(rendered, VRRP_SECRET)
    assert "server s1 10.0.0.1:80" in rendered, (
        "masking ran past the end of the auth_pass line and ate the rest of the config"
    )


# --------------------------------------------------------------------------
# TOTP. routers/mfa.py logs `{"secret_len": ...}` with the comment
# "NEVER log the secret itself".
# --------------------------------------------------------------------------

def test_mfa_enroll_response_does_not_store_the_totp_secret_in_either_field():
    """POST /api/mfa/enroll — returns `secret` AND `otpauth_uri`.

    Redacting one while the same value sits in the other is not redaction.
    """
    rendered, _ = _capture({
        "secret": TOTP_SECRET,
        "otpauth_uri": f"otpauth://totp/OpenManager:admin?secret={TOTP_SECRET}&issuer=OpenManager",
        "qr_size": 256,
    })
    _assert_absent(rendered, TOTP_SECRET)


def test_userinfo_credentials_in_a_url_are_dropped():
    rendered, _ = _capture({"webhook": "https://svc:Sup3rSecret@hooks.example.com/notify?api_key=abc123"})
    _assert_absent(rendered, "Sup3rSecret", "abc123")
    assert "hooks.example.com" in rendered, "the host is the diagnostic value; keep it"


# --------------------------------------------------------------------------
# HAProxy config. We never RENDER credentials into one, but the agent uploads
# the node's real file and the operator can paste one.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("cap,label", [(8192, "truncated _raw path"), (10 ** 6, "parsed path")])
def test_uploaded_haproxy_config_masks_credentials_on_both_paths(cap, label):
    """POST /api/configuration/agents/{n}/config-response, and
    POST /api/config/validate."""
    rendered, _ = _capture({"config_content": HAPROXY_CFG, "config_path": "/etc/haproxy/haproxy.cfg"}, cap=cap)
    _assert_absent(rendered, STATS_PASSWORD, USERLIST_HASH, "Hunter2Plain")
    assert "stats auth admin:" in rendered, f"[{label}] the account name is diagnostic; keep it"
    assert "server web1 10.0.0.1:80" in rendered, f"[{label}] the rest of the config must survive"


@pytest.mark.parametrize("prose", [
    "invalid password format",
    "the password must be at least 8 characters",
    "authentication failed for user admin",
])
def test_ordinary_prose_is_not_mangled(prose):
    """Over-matching would blank the messages the log exists to show."""
    rendered, _ = _capture({"detail": prose})
    assert prose in rendered, f"redaction damaged an ordinary message: {rendered}"


# --------------------------------------------------------------------------
# Regressions guarding what already worked, so a later rule change cannot
# quietly trade one of these away for one of the above.
# --------------------------------------------------------------------------

def test_login_exchange_stores_neither_the_password_nor_the_token():
    req, _ = _capture({"username": "admin", "password": "hunter2hunter2"})
    _assert_absent(req, "hunter2hunter2")
    res, _ = _capture({"access_token": JWT, "token_type": "bearer", "user": {"id": 1}})
    _assert_absent(res, JWT)


def test_private_key_is_redacted_even_under_an_innocent_key_name():
    """The value-shape guard is the net under the key-name rules."""
    rendered, _ = _capture({"blob": PEM_KEY, "note": "backup"})
    _assert_absent(rendered, "MIIEowIBAAKCAQEA")


def test_dns_provider_credentials_are_redacted():
    cf, _ = _capture({"provider": "cloudflare", "api_token": "cf_live_abcdefghijklmnop", "zone_id": "z1"})
    _assert_absent(cf, "cf_live_abcdefghijklmnop")
    gd, _ = _capture({"provider": "godaddy", "api_key": "gd_key_1234567890", "api_secret": "gd_secret_098"})
    _assert_absent(gd, "gd_key_1234567890", "gd_secret_098")


def test_innocent_urls_survive_untouched():
    """Scrubbing must not rewrite the ACME URLs an operator reads back."""
    for url in (
        "https://acme-v02.api.letsencrypt.org/directory",
        "https://acme-v02.api.letsencrypt.org/acme/acct/12345",
    ):
        rendered, _ = _capture({"directory_url": url})
        assert url in rendered, f"an innocent URL was rewritten: {rendered}"


def test_credential_headers_are_presence_only_and_the_rest_are_dropped():
    out = redact_headers({
        "authorization": f"Bearer {JWT}",
        "x-api-key": "agt_" + "a" * 32,
        "cookie": "session=abc123",
        "user-agent": "curl/8.4.0",
        "x-forwarded-for": "10.20.30.5",
        "x-internal-secret": "not-on-the-allowlist",
    })
    rendered = json.dumps(out)
    _assert_absent(rendered, JWT, "agt_" + "a" * 32, "abc123", "not-on-the-allowlist")
    assert out["user-agent"] == "curl/8.4.0"
    assert out["x-forwarded-for"] == "10.20.30.5"
    assert "x-internal-secret" not in out, "an unlisted header must be dropped, not kept"


@pytest.mark.parametrize("key", ["auth_pass", "authPass", "auth-pass", "AUTH_PASS"])
def test_auth_pass_key_matches_in_every_spelling(key):
    assert is_secret_key(key), (
        f"{key!r} normalizes to something no rule matches. 'password' is not a "
        f"substring of 'authpass' and the bare 'auth' entry is an exact match."
    )


@pytest.mark.parametrize("key", [
    "monkey", "key_suffix", "payload_size", "nonce_count", "keyboard_layout",
    "config_path", "authenticated", "author",
])
def test_innocent_field_names_are_still_kept(key):
    """The other half of the trade: over-redaction blanks the fields the
    feature exists to show."""
    assert not is_secret_key(key)
