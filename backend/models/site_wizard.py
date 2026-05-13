"""
v1.5.0 Feature B (Issue #14): Pydantic models for the New Site Setup
Wizard.

The wizard accepts an entire host bundle (cluster, domains, backend, server(s),
HTTP frontend, SSL choice, optional ACME) in a single atomic POST. The
backend then opens a single transaction and creates all entities in order.

Design notes:
- We deliberately use Pydantic v2 syntax (`pattern=` not the deprecated
  `regex=`).
- M22: ssl.mode='acme' MUST set apply_immediately=true (the wizard does NOT
  let the user save an ACME-staged order without an actual config-version
  apply that the agent can confirm).
- Round 10 micro-finding: ssl.mode='acme' also requires frontend.mode='http'
  (HTTP-01 challenge is HTTP-only).
- M19: frontend.https_redirect (UI sugar) is expanded server-side to a
  redirect_rules JSONB row; the wizard rejects payloads that set BOTH
  https_redirect=true AND a non-empty redirect_rules list.
- Backend names beginning with `_` are reserved for system-managed entities
  (e.g. `_acme_challenge_backend`); rejected at validation time.
"""

import re
from typing import Any, List, Literal, Optional, Union

from pydantic import BaseModel, Field, field_validator, model_validator

# Re-use the canonical domain regex (M10) so client + server stay in sync.
from utils.domain_validation import DOMAIN_REGEX, validate_domain


# Backend name: HAProxy-section-name-safe identifier. We additionally forbid
# leading underscore (system-managed names) and the literal HAProxy-reserved
# names mentioned in the v1.5.0 plan.
_BACKEND_NAME_REGEX = r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$"
_FRONTEND_NAME_REGEX = r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$"
_SERVER_NAME_REGEX = r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$"

# Bulgu #43 (round-17 audit) — HAProxy section-type keywords are reserved
# globals in HAProxy's grammar. A section directive of the form
# `<section_type> <name>` is grammatically legal even when <name> equals
# another section-type keyword (e.g. `backend defaults`), but the result
# is impossible to scan, confuses every operator who reads the rendered
# config, and breaks downstream tooling that grep's for sections by name.
# We reject these as backend/frontend/server names at the wizard
# boundary so the operator gets a single, actionable error rather than
# producing a config that loads but is unreadable.
# Source: HAProxy 2.6+ configuration manual, section "2. Quick reminder
# about HTTP" and the section-type table. Lowercased; the field
# validators compare case-insensitively.
_HAPROXY_SECTION_KEYWORDS = frozenset({
    "global", "defaults", "listen", "frontend", "backend",
    "peers", "mailers", "resolvers", "cache", "program", "ring",
    "userlist", "http-errors", "fcgi-app", "crt-store", "traces",
    "ssl-engine", "cpu-map",
})

# ACL operators / condition keywords that, when used as a section name,
# would silently shadow grammar tokens in `use_backend X if Y` strings.
# Reject defensively so operators can't paint themselves into a corner.
_ACL_RESERVED_KEYWORDS = frozenset({"if", "unless", "or", "and"})


def _validate_not_haproxy_keyword(value: str, field_label: str) -> str:
    """Bulgu #43 (round-17 audit) — common implementation shared by
    backend / frontend / server name validators. Performs the
    case-insensitive keyword check and raises a clear ValueError when
    the operator-supplied name collides with a HAProxy section keyword
    or ACL operator."""
    if not value:
        return value
    low = value.strip().lower()
    if low in _HAPROXY_SECTION_KEYWORDS:
        raise ValueError(
            f"{field_label}={value!r} collides with the HAProxy section "
            f"keyword '{low}'. While HAProxy's grammar technically allows "
            f"`{low} {low}` as a section header, the resulting config is "
            "unreadable and breaks tooling that parses sections by name. "
            "Pick a non-keyword identifier."
        )
    if low in _ACL_RESERVED_KEYWORDS:
        raise ValueError(
            f"{field_label}={value!r} collides with the ACL operator "
            f"keyword '{low}', which is used by `use_backend X if Y` "
            "directives. Pick a different identifier to avoid grammar "
            "ambiguity."
        )
    return value


# Bulgu #44 (round-17 audit) — bind_address character class. HAProxy
# accepts several syntaxes (`*`, `0.0.0.0`, IPv6 in brackets `[::1]`,
# DNS name resolved at start, `@<varname>` env reference). We
# accept a conservative class that covers all common forms and
# explicitly rejects whitespace + shell metacharacters. The renderer
# emits the value verbatim as the host part of `bind <addr>:<port>`,
# so a value like `'foo bar'` would produce `bind foo bar:80` which
# HAProxy tokenises as `bar:80` and ignores `foo` (the operator's
# IP allocation is silently wrong). Reject upfront so the operator
# sees `'foo bar' is not a valid bind_address` instead of debugging a
# misrouted port.
_BIND_ADDRESS_REGEX = re.compile(
    # Allow:
    #   - bare `*`
    #   - IPv4 dotted form
    #   - IPv6 raw (no brackets, e.g. `::`) — HAProxy accepts in `bind`
    #   - IPv6 in brackets `[::1]`
    #   - IPv6 with scope-id `[fe80::1%eth0]` — Bulgu #59 (round-20).
    #     Link-local IPv6 binds require the interface name (`%eth0`,
    #     `%bond0.42`, …) so HAProxy can pick the right NIC. Pre-fix
    #     `_BIND_ADDRESS_REGEX` rejected the `%` character outright
    #     and link-local listeners had to drop down to the manual
    #     frontend API. The character class also accepts digits in
    #     case the operator uses a numeric zone index (RFC 4007 §11).
    #   - hostnames a-z 0-9 . -
    #   - `@<varname>` HAProxy env reference (advanced)
    r"^(?:"
    r"\*"
    r"|@[A-Za-z_][A-Za-z0-9_]*"
    r"|\[[0-9a-fA-F:.]{1,40}(?:%[A-Za-z0-9._-]{1,16})?\]"
    r"|[0-9a-zA-Z.:_-]{1,63}"
    r")$"
)


# Bulgu #45 (round-17 audit) — HAProxy parses timeout values as a
# signed 32-bit integer of milliseconds (signed int upper bound:
# 2_147_483_647 ms ≈ 24.85 days). Values above that overflow the
# parser; values close to it are operator confusion. The wizard
# caps at 24h × 30 = 30 days ≈ 2_592_000_000 ms which already
# overflows int32, so we cap below that. 24h = 86_400_000 ms is the
# longest reasonable HAProxy timeout — anything beyond that is
# almost certainly a missing-unit typo (e.g. operator typed
# 60_000_000 thinking it was seconds).
_MAX_HAPROXY_TIMEOUT_MS = 86_400_000  # 24 hours, well below int32 overflow

# Bulgu #46 (round-17 audit) — HAProxy `maxconn` / `rate_limit` are
# unsigned ints in the parser but practical limits are bounded by
# the agent's `ulimit -n` (file descriptors). A typical Linux box
# defaults to 1024 nofile, tuned production typically tops out at
# 1M. Anything > 1M is almost certainly a typo and produces a
# config that the agent fails to load (`socket(): too many open
# files`). Cap defensively.
_MAX_HAPROXY_CONN_LIMIT = 1_000_000

# Phase K (Site Wizard validation hardening) — safety validators for
# HAProxy directive fragments that the ACL builder serialises into the
# wizard payload. Mirrors the danger-pattern set the manual frontend
# API has been enforcing on raw ACL strings since pre-R14
# (`backend/models/frontend.py::validate_acl_rules`). The wizard never
# inherited that protection because the rule fields were typed as
# `List[dict]` and never reached a string-aware validator — every ACL
# attempt instead failed with "Input should be a valid dictionary".
#
# 4 KB per element keeps us under the existing R14 hardening posture
# (PEM fields capped at 64 KB; rule strings should be at most ~1 KB
# in practice, so 4 KB is a comfortable headroom that still defeats
# pathological-DoS payloads).
_MAX_RULE_STRING_LEN = 4096

# Bulgu #64 (round-22 audit) — the previous danger-pattern list was
# `("system", "exec", "eval", "$(", "`")` and matched the substring
# anywhere in the rule string. That blocked legitimate ACL names
# such as `acl is_system path_beg /admin`, `acl my_subsystem …`,
# or `acl block_executable path_end .exe`, because the literal
# words happen to be common in operator-facing naming. HAProxy is
# NOT a shell — there is no `system`/`exec`/`eval` directive, and
# substrings of these tokens carry no runtime meaning inside a
# rendered HAProxy config. The substring check was over-cautious
# and a real false-positive trap on the UPDATE path (legacy rows
# could not be edited at all).
#
# The retained patterns are shell-substitution markers (`$(`,
# backtick) — these don't appear in any legitimate HAProxy
# directive shape; if an operator pastes them in it almost always
# means a copy-paste from a shell script that needs review. The
# newline/CR check below still defeats actual directive-injection
# attempts.
_DANGEROUS_RULE_PATTERNS = ("$(", "`")

# Phase K Phase D follow-up (Bulgu #12 round 3) — the HAProxy `-f
# <file>` ACL/condition flag instructs HAProxy to load match patterns
# from a server-side file at parse time. HAProxy OpenManager is a
# fully-managed product: we do NOT provision pattern files onto the
# HAProxy node's filesystem, and operators have no UI to upload one.
# A `-f /some/path` reference therefore ALWAYS resolves to
# "file not found" when HAProxy's real `-c` parse runs at apply
# time, producing exactly the operator-reported failure mode:
#   [ALERT] parsing ACL 'acl1' : failed to open pattern file </path>.
#   [ALERT] parsing switching rule : no such ACL : 'acl1'.
#
# Surface this BEFORE persist by rejecting `-f` in any rule string
# that comes through the wizard / manual frontend API. Reject ALL
# variants (` -f `, leading `-f `, trailing `... -f`) defensively so
# operators cannot slip the flag through with creative spacing.
# The check is anchored to ACL/condition rule strings only; raw
# HAProxy snippet fields (tcp_request_rules, request_headers, ...)
# are NOT touched because those are inherently free-form and
# advanced operators may legitimately reference pre-provisioned
# pattern files there.
_ACL_FILE_FLAG_PATTERN = re.compile(r"(^|\s)-f(\s|$)")
_ACL_FILE_FLAG_MESSAGE = (
    "pattern-file references with '-f <file>' are not supported in ACL / "
    "use_backend / redirect rules: HAProxy OpenManager does not provision "
    "pattern files onto the HAProxy node's filesystem, so the reference "
    "would always fail at HAProxy reload time. Use inline values "
    "instead (e.g. `acl is_admin src 10.0.0.0/24` rather than "
    "`acl is_admin src -f /etc/haproxy/admins.lst`)."
)

# Phase K Phase D follow-up (Bulgu #13) — detect a routing /
# redirect rule whose condition references the SAME ACL in both
# positive and negated form (e.g. `use_backend foo if acl1 !acl1`).
# HAProxy accepts the syntax but the predicate `X AND NOT X` is
# permanently false, so the rule never fires and traffic silently
# falls through to `default_backend`. The wizard's visual builder
# (mode="tags" Select for routing conditions) previously allowed
# the operator to pick both forms; the auto-dedup there is the
# first guard, this is the server-side gate.
_ACL_NAME_TOKEN = re.compile(r"^!?([A-Za-z_][\w.-]*)$")
_ACL_CONTRADICTION_MESSAGE = (
    "self-contradictory condition: the same ACL appears in both "
    "positive and negated form (e.g. `acl1 !acl1`). HAProxy accepts "
    "the syntax but the predicate `X AND NOT X` is always false, so "
    "the rule never fires and traffic silently falls through to "
    "`default_backend`. Remove one of the two tokens."
)


def _detect_acl_contradiction(directive: str) -> List[str]:
    """Return the list of ACL names that appear in BOTH positive
    and negated form in the given directive string. Empty list
    means no obvious self-contradiction.

    Only flags pure ACL identifier tokens (`acl1`, `!acl1`). Does
    not interpret anonymous ACLs (`{ ssl_fc }`) or compound forms.
    """
    pos: set = set()
    neg: set = set()
    for raw in directive.split():
        if raw in ("if", "unless"):
            continue
        m = _ACL_NAME_TOKEN.match(raw)
        if not m:
            continue
        name = m.group(1)
        if raw.startswith("!"):
            neg.add(name)
        else:
            pos.add(name)
    return sorted(pos & neg)


def _validate_haproxy_directive_string(
    value: Any,
    field_label: str,
    *,
    check_acl_contradiction: bool = False,
) -> str:
    """Shared safety validator for ACL / use_backend / redirect rule strings.

    Returns the trimmed string on success; raises ValueError with a clear,
    operator-friendly message on any of:
      - non-string element
      - empty / whitespace-only string
      - string longer than 4 KB (R14 hardening posture)
      - newline / carriage return embedded in the string (HAProxy
        directives are line-oriented; a multi-line string would inject
        arbitrary directives into the rendered config)
      - dangerous shell-substitution / interpolation patterns the manual
        frontend API also rejects (`system`, `exec`, `eval`, `$(`,
        backtick).
      - `-f <file>` pattern-file references (operator cannot provision
        files onto the HAProxy node).
      - (when `check_acl_contradiction=True`) the same ACL appearing in
        both positive AND negated form, producing a permanently-false
        predicate.
    """
    if not isinstance(value, str):
        raise ValueError(
            f"{field_label} entries must be HAProxy directive strings; "
            f"got {type(value).__name__}"
        )
    stripped = value.strip()
    if not stripped:
        raise ValueError(
            f"{field_label} entries must not be empty / whitespace-only"
        )
    if len(stripped) > _MAX_RULE_STRING_LEN:
        raise ValueError(
            f"{field_label} entry exceeds {_MAX_RULE_STRING_LEN} characters "
            f"(got {len(stripped)})"
        )
    if "\n" in stripped or "\r" in stripped:
        raise ValueError(
            f"{field_label} entries must not contain line breaks "
            "(HAProxy directives are line-oriented; embedded newlines "
            "would inject arbitrary directives into the rendered config)"
        )
    lowered = stripped.lower()
    for pattern in _DANGEROUS_RULE_PATTERNS:
        if pattern in lowered:
            raise ValueError(
                f"{field_label} entry contains potentially dangerous content: "
                f"{pattern!r}"
            )
    # Phase K Phase D follow-up (Bulgu #12 round 3) — reject the
    # HAProxy `-f <file>` pattern-file flag because OpenManager does
    # not manage the HAProxy node filesystem. See the module-level
    # `_ACL_FILE_FLAG_PATTERN` docstring for the full operator-
    # reported failure mode this guards against.
    if _ACL_FILE_FLAG_PATTERN.search(stripped):
        raise ValueError(f"{field_label}: {_ACL_FILE_FLAG_MESSAGE}")
    # Phase K Phase D follow-up (Bulgu #13) — for routing /
    # redirect rules (not ACL definitions themselves), reject a
    # condition that contains the same ACL in both positive and
    # negated polarity. The wizard's visual builder dedups this
    # at edit time; this server-side gate catches hand-crafted
    # API payloads and stale drafts that may have been saved
    # before the UI dedup landed.
    if check_acl_contradiction:
        conflicts = _detect_acl_contradiction(stripped)
        if conflicts:
            raise ValueError(
                f"{field_label}: {_ACL_CONTRADICTION_MESSAGE} "
                f"Conflicting ACL(s): {', '.join(conflicts)}."
            )
    return stripped


class ServerStep(BaseModel):
    server_name: str = Field(..., pattern=_SERVER_NAME_REGEX)
    server_address: str = Field(..., min_length=1, max_length=253)
    server_port: int = Field(..., ge=1, le=65535)

    @field_validator("server_name")
    @classmethod
    def _server_name_not_haproxy_keyword(cls, v: str) -> str:
        """Bulgu #43 (round-17 audit) — guard against HAProxy section
        keywords and ACL operators in server names. While the rendered
        `server defaults 10.0.0.1:80 …` is technically legal, the
        operator can no longer grep for `default-server` lines without
        false positives. Reject defensively."""
        return _validate_not_haproxy_keyword(v, "server.server_name")

    @field_validator("server_address")
    @classmethod
    def _validate_server_address(cls, v: str) -> str:
        """Bulgu #17 (round-7 audit): pre-fix `server_address`
        only enforced `min_length=1`, which accepted single-space
        and tab-only strings. The renderer then emits
        `server srv1  :8080` (literally a leading space before the
        colon) which HAProxy's parser rejects with a generic
        syntax error.

        Strip and re-check non-empty. We do NOT validate IP /
        hostname syntax here — operators sometimes intentionally
        use DNS names that resolve to internal hosts only at
        runtime — but whitespace-only is unambiguously garbage.
        """
        if v is None:
            return v
        stripped = v.strip()
        if not stripped:
            raise ValueError(
                "server.server_address must not be empty or whitespace-only"
            )
        # Reject embedded whitespace too — HAProxy splits the line
        # at the first space, so 'srv1 1.1.1.1' would parse as
        # name='srv1', address='1.1.1.1' which is NOT what the
        # operator typed.
        if any(ch.isspace() for ch in stripped):
            raise ValueError(
                f"server.server_address must not contain whitespace "
                f"(got {v!r}). HAProxy parses server lines token-by-"
                f"token; an embedded space would shift the address "
                f"into a keyword position."
            )
        return stripped
    weight: int = Field(default=100, ge=0, le=256)
    # Bulgu #46 (round-17 audit) — per-server maxconn upper bound: a
    # single server cannot reasonably hold more than the cluster's
    # global maxconn, so capping at the same defensive 1M ceiling is
    # safe and rules out typos like `10**12`.
    max_connections: Optional[int] = Field(
        default=None, ge=0, le=_MAX_HAPROXY_CONN_LIMIT,
    )
    # Advanced health-check tuning (HAProxy `inter`, `fall`, `rise`)
    check_enabled: bool = True
    check_port: Optional[int] = Field(default=None, ge=1, le=65535)
    # Bulgu #22 (round-11 audit): HAProxy rejects `inter 0`, `fall 0`,
    # `rise 0` with parser errors ("inter: minimum 1ms", "fall/rise:
    # argument 0 is invalid range from 1 to 100"). Pre-fix the wizard
    # accepted 0 and surfaced the failure only at apply-time via the
    # agent's `haproxy -c`. Tighten to `ge=1` so the wizard rejects
    # at submit-time with a clear field-level error.
    #
    # Bulgu #45 (round-17 audit): `inter` is a ms timeout — cap at 24h
    # (well below int32 overflow). `fall`/`rise` are check counts —
    # HAProxy documents the upper bound as 100; we mirror it. Pre-fix
    # the wizard accepted `inter=10**12`, `fall=10**6` which the
    # renderer emitted verbatim; HAProxy parser overflow surfaced
    # only at apply time.
    inter: Optional[int] = Field(
        default=None, ge=1, le=_MAX_HAPROXY_TIMEOUT_MS,
        description="Health check interval in ms (HAProxy requires >= 1, cap 24h)",
    )
    fall: Optional[int] = Field(
        default=None, ge=1, le=100,
        description="Failed checks before marking server DOWN (HAProxy 1-100)",
    )
    rise: Optional[int] = Field(
        default=None, ge=1, le=100,
        description="Successful checks before marking server UP (HAProxy 1-100)",
    )
    # Advanced server flags
    backup_server: bool = False
    cookie_value: Optional[str] = Field(default=None, max_length=255, description="Sticky session cookie value")
    # SSL/TLS to backend (HAProxy `server ... ssl`)
    ssl_enabled: bool = False
    ssl_verify: Optional[Literal["none", "required"]] = None
    ssl_sni: Optional[str] = Field(default=None, max_length=253)
    ssl_min_ver: Optional[Literal["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]] = None
    ssl_max_ver: Optional[Literal["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]] = None
    ssl_ciphers: Optional[str] = Field(default=None, max_length=2048)

    @field_validator("cookie_value", "ssl_sni", "ssl_ciphers")
    @classmethod
    def _validate_single_line_server_value(
        cls, v: Optional[str], info
    ) -> Optional[str]:
        """Bulgu #33 (round-14 audit): the wizard interpolates these
        fields directly into the rendered `server <name> <addr>:<port>
        ... cookie <val> sni <val> ciphers <val>` line. Pre-fix the
        Pydantic model only enforced `max_length`, so an operator with
        wizard permission could embed a newline:

            cookie_value = "srv1\\n    use_backend evil if always\\n"

        The renderer split the line at the newline and emitted:

            server srv1 1.1.1.1:80 ... cookie srv1
                use_backend evil if always

        — smuggling a directive into the parent backend block. The
        same smuggling vector exists for `ssl_sni` (`sni <val>`) and
        `ssl_ciphers` (`ciphers <val>`) because both land on the same
        server line. None of these values are legitimately multi-line:

          * `cookie_value` is a short identifier (HAProxy stores it
            in the Set-Cookie response header verbatim).
          * `ssl_sni` is a single hostname (DNS / FQDN form).
          * `ssl_ciphers` is an OpenSSL cipher spec — colon-separated,
            no whitespace.

        Reject any newline (\\n, \\r, \\r\\n). Additionally reject
        embedded whitespace inside `ssl_sni` (HAProxy splits the
        server line at the first space, so a space inside the SNI
        value would shift later keywords into wrong positions). The
        cipher list and cookie value tolerate `tab` historically; we
        keep the strict newline-only rejection there to stay
        backward-compatible with operator inputs.

        Multi-line free-form fields (`request_headers`,
        `response_headers`, `tcp_request_rules`, raw `options`) are
        intentionally line-oriented and ARE NOT touched here.
        """
        if v is None:
            return v
        if '\n' in v or '\r' in v:
            field_name = info.field_name if info else 'server field'
            raise ValueError(
                f"server.{field_name} must not contain line breaks "
                "(HAProxy server lines are single-line; embedded "
                "newlines would smuggle additional directives into "
                "the rendered backend block)"
            )
        # ssl_sni is a hostname — HAProxy's server-line tokenizer
        # splits at the first whitespace, so any embedded space would
        # shift later server keywords (`ciphers`, `inter`, `check`,
        # …) into the wrong positions.
        if info and info.field_name == "ssl_sni":
            if any(ch.isspace() for ch in v):
                raise ValueError(
                    f"server.ssl_sni must not contain whitespace "
                    f"(got {v!r}). HAProxy's server-line tokenizer "
                    "splits at the first space, so a space inside the "
                    "SNI value would corrupt the rendered config."
                )
        return v
    # R17 (label corrected R18): CA bundle used by HAProxy to VERIFY the
    # upstream server's TLS certificate. Maps to the `ca-file` directive
    # on the HAProxy server line (services/haproxy_config.py:785). The
    # field is named `ssl_certificate_id` for parity with the manual
    # BackendServers create endpoint; semantics is "CA verification
    # bundle", NOT "client cert presented by HAProxy". The latter would
    # require a separate `crt` directive which is not exposed by the
    # wizard or the manual UI today.
    # Optional + None default = backward-compatible with v1.5.0 saved drafts
    # and direct API callers that don't send the field.
    ssl_certificate_id: Optional[int] = Field(
        default=None, ge=1,
        description="CA bundle used by HAProxy to verify the upstream server's TLS certificate (HAProxy `ca-file` directive on the server line). FK -> ssl_certificates.id.",
    )

    @field_validator("ssl_verify", mode="before")
    @classmethod
    def coerce_ssl_verify_empty_to_none(cls, v):
        """PR-2 (R11.B): UI Select widgets clear to '' (empty string)
        which the strict Literal would reject. Coerce '' / sentinels
        / legacy 'optional' (server-side mTLS doesn't support it) to
        None so the generator omits the directive."""
        if v is None:
            return None
        if isinstance(v, str):
            stripped = v.strip().lower()
            if stripped in ("", "[]", "{}", "null", "optional"):
                return None
            if stripped == "none":
                return "none"
            if stripped == "required":
                return "required"
        return v

    @model_validator(mode="after")
    def reject_server_ca_bundle_without_ssl(self):
        """R17 (renamed in R18): ssl_certificate_id (HAProxy `ca-file`)
        is meaningless when the upstream server connection itself is
        plaintext. Reject the combination at the wizard layer so users
        get a clear error instead of HAProxy silently ignoring the
        ca-file directive."""
        if self.ssl_certificate_id is not None and not self.ssl_enabled:
            raise ValueError(
                "server.ssl_certificate_id requires server.ssl_enabled=true. "
                "Enable SSL to backend or clear the CA bundle selection."
            )
        # R18c audit fix (round 3 #6): refuse to accept TLS 1.0 / 1.1
        # for upstream server connections. Both protocols were
        # formally deprecated by RFC 8996 (March 2021); modern
        # browsers, Cloudflare, AWS and Azure have long since
        # disabled them, and accepting them on the wizard surface
        # creates a route for operators to accidentally ship
        # downgrade-prone configurations. The Pydantic Literal
        # accepts the strings so that existing DB rows can still
        # round-trip through API serializers (responses are not
        # blocked); the wizard CREATE path explicitly rejects new
        # values with a clear error. Operators with a hard
        # requirement can still author the backend through the
        # regular Backends UI which has its own audited path.
        for fld in ("ssl_min_ver", "ssl_max_ver"):
            v = getattr(self, fld, None)
            if v in ("TLSv1.0", "TLSv1.1"):
                raise ValueError(
                    f"server.{fld}={v} is no longer accepted by the wizard. "
                    "TLS 1.0 / 1.1 are deprecated by RFC 8996. Use TLSv1.2 "
                    "or TLSv1.3."
                )
        return self


class BackendStep(BaseModel):
    name: str = Field(..., pattern=_BACKEND_NAME_REGEX)
    # NOTE: HAProxy supports parametric algorithms `hdr(<name>)`,
    # `url_param(<name>)` and `rdp-cookie(<name>)`. The wizard does NOT
    # accept those today because the parameter (header / query name)
    # would need a dedicated input. Without the parameter HAProxy rejects
    # the bare directive (`balance hdr` is invalid syntax). Stick to
    # parameter-free algorithms here; advanced users wanting parametric
    # balance can author the backend in the regular Backends UI.
    balance_method: Literal[
        "roundrobin", "leastconn", "static-rr", "first", "source", "uri", "random",
    ] = "roundrobin"
    mode: Literal["http", "tcp"] = "http"
    health_check_uri: Optional[str] = Field(default="/", max_length=2048)
    # Bulgu #45 (round-17 audit) — cap health-check + timeout values at
    # HAProxy's safe ms upper bound (24h, well below int32 overflow at
    # ~24.85 days). Pre-fix the wizard accepted `timeout_connect=10**18`
    # which produced a config the agent's `haproxy -c` rejected with
    # an opaque "invalid timeout" message.
    health_check_interval: Optional[int] = Field(
        default=2000, ge=100, le=_MAX_HAPROXY_TIMEOUT_MS,
    )
    health_check_expected_status: Optional[int] = Field(default=200, ge=100, le=599)
    timeout_connect: Optional[int] = Field(
        default=10000, ge=100, le=_MAX_HAPROXY_TIMEOUT_MS,
    )
    timeout_server: Optional[int] = Field(
        default=60000, ge=100, le=_MAX_HAPROXY_TIMEOUT_MS,
    )
    timeout_queue: Optional[int] = Field(
        default=60000, ge=100, le=_MAX_HAPROXY_TIMEOUT_MS,
    )
    # Bulgu #46 (round-17 audit) — fullconn cap. HAProxy parses this as
    # uint; >1M is almost always a typo.
    fullconn: Optional[int] = Field(
        default=None, ge=0, le=_MAX_HAPROXY_CONN_LIMIT,
        description="Backend total active connections threshold",
    )
    options: Optional[str] = Field(default=None, max_length=8192)
    # Sticky-session via cookie persistence (HAProxy `cookie SRVID insert indirect nocache`)
    cookie_name: Optional[str] = Field(default=None, max_length=128)
    cookie_options: Optional[str] = Field(default=None, max_length=512)
    # Default-server-* directives (defaults applied to every server)
    # Bulgu #22 (round-11 audit): same HAProxy parser constraint as
    # per-server inter/fall/rise — values must be >= 1 or HAProxy
    # rejects the `default-server` line at parse time.
    # Bulgu #45 (round-17 audit) — apply the same upper bounds the
    # per-server fields enforce so default-server caps cannot exceed
    # what each server can.
    default_server_inter: Optional[int] = Field(
        default=None, ge=1, le=_MAX_HAPROXY_TIMEOUT_MS,
        description="Default health interval (ms, HAProxy 1-86400000)",
    )
    default_server_fall: Optional[int] = Field(
        default=None, ge=1, le=100,
        description="Default fall count (HAProxy 1-100)",
    )
    default_server_rise: Optional[int] = Field(
        default=None, ge=1, le=100,
        description="Default rise count (HAProxy 1-100)",
    )
    # Header injection (multi-line; validated by HAProxy at apply time)
    request_headers: Optional[str] = Field(default=None, max_length=8192)
    response_headers: Optional[str] = Field(default=None, max_length=8192)

    @field_validator("name")
    @classmethod
    def reject_system_prefix(cls, v: str) -> str:
        if v.startswith("_"):
            raise ValueError(
                "Backend name must not start with '_' (reserved for system-managed entities)"
            )
        # Bulgu #43 (round-17 audit) — additional HAProxy section
        # keyword check (defaults / global / listen / frontend / …).
        return _validate_not_haproxy_keyword(v, "backend.name")

    @field_validator("cookie_name", "cookie_options")
    @classmethod
    def _validate_single_line_cookie_field(
        cls, v: Optional[str], info
    ) -> Optional[str]:
        """Bulgu #18 (round-8 audit): `cookie_name` and `cookie_options`
        are single-line fields by HAProxy syntax (one `cookie <name>
        [options]*` directive per backend block). Pre-fix the Pydantic
        model only enforced `max_length`, so an operator could embed
        a newline:

            cookie_options = "insert indirect\\n    server evil 8.8.8.8:80"

        The renderer then split the value at the newline and emitted:

            cookie SRVNAME insert indirect
                server evil 8.8.8.8:80

        — smuggling a `server` line into the backend block. Reject any
        newline (\\n, \\r, \\r\\n) in these fields. Multi-line free-form
        fields like `request_headers` / `response_headers` /
        `tcp_request_rules` are intentionally line-oriented and ARE
        NOT touched here.
        """
        if v is None:
            return v
        if '\n' in v or '\r' in v:
            field_name = info.field_name if info else 'cookie field'
            raise ValueError(
                f"backend.{field_name} must not contain line breaks "
                "(HAProxy `cookie` directive is single-line; embedded "
                "newlines would smuggle additional directives into "
                "the rendered config)"
            )
        return v

    @field_validator("health_check_uri")
    @classmethod
    def _validate_health_check_uri(cls, v: Optional[str]) -> Optional[str]:
        """Bulgu #17 (round-7 audit): HAProxy's `option httpchk GET <uri>`
        emits the URI verbatim into the health-check HTTP request.
        Pre-fix the wizard accepted `health_check_uri='hh1'` (no
        leading slash) and emitted `option httpchk GET hh1`. The
        agent's HTTP probe then sends `GET hh1 HTTP/1.0` which the
        upstream silently returns 400 for — the operator's health
        check is permanently failing.

        Same gating as `frontend.monitor_uri` (Bulgu #16):
        non-empty, leading `/`, no whitespace.
        """
        if v is None:
            return v
        s = v.strip()
        if not s:
            # Empty string is a misconfiguration — the field is
            # Optional[str] with default '/', so an operator who
            # really wants to disable the health check should set
            # `check_enabled=False` on the per-server level, not
            # blank the backend default.
            raise ValueError(
                "backend.health_check_uri must not be empty. "
                "Use the default '/' or a real path. To disable "
                "health checks, set `check_enabled=False` on each "
                "server instead."
            )
        if not s.startswith('/'):
            raise ValueError(
                "backend.health_check_uri must start with '/' "
                "(HAProxy emits the value verbatim into the "
                f"health-check HTTP request, got {v!r})"
            )
        if any(ch.isspace() for ch in s):
            raise ValueError(
                "backend.health_check_uri must not contain whitespace "
                f"(HAProxy directive parser would break, got {v!r})"
            )
        return s

    @model_validator(mode="after")
    def reject_cookie_on_tcp_mode(self):
        """v1.5.0 R12: HAProxy `cookie` directive is HTTP-only. Asking
        for sticky-cookie persistence on a TCP backend produces an
        invalid config that HAProxy refuses to load. Catch it at the
        wizard layer with a clear error rather than letting it surface
        as an opaque `option httpchk` / cookie syntax error at apply
        time.

        Bulgu #56 (round-19 audit) — backend-side companion of the
        FrontendStep guard. `request_headers` / `response_headers` on a
        backend render via haproxy_config.py:1306-1321 as
        `http-request set-header …` / `http-response set-header …`
        directives, and HAProxy's parser refuses these inside a
        `mode tcp` backend block exactly the same way it does for
        frontends ("'http-response' is not allowed in 'backend' section
        in mode tcp"). Reject the combo at submit time so the operator
        does not wedge the cluster's apply queue with a parse error
        only discovered after the rows are inserted.
        """
        if self.mode == "tcp":
            tcp_blockers: List[str] = []
            if self.cookie_name:
                tcp_blockers.append("cookie_name")
            if self.request_headers:
                tcp_blockers.append("request_headers")
            if self.response_headers:
                tcp_blockers.append("response_headers")
            # Bulgu #61 (round-21 audit) — `balance uri` is HTTP-only.
            #
            # HAProxy configuration manual section 4.2 on `balance`:
            #   "uri — Note that this algorithm may only be used in
            #    an HTTP backend."
            #
            # The wizard's renderer emits `balance <method>` for any
            # backend regardless of mode. Pre-fix a payload with
            # `mode='tcp' + balance_method='uri'` rendered cleanly,
            # the agent's `haproxy -c` then refused the config with
            # the same kind of parse error as the round-19 #56
            # `http-response`-in-tcp-mode failure, blocking the
            # cluster's apply queue until an operator manually
            # corrected the entity. Catch the combination here so
            # the operator sees an actionable message at submit
            # time instead of after the rows are inserted.
            #
            # Other parametric HTTP-only methods (`hdr(...)`,
            # `url_param(...)`) are intentionally not in the
            # wizard's enum (see line 545-552 above) so they
            # cannot reach this validator.
            if self.balance_method == "uri":
                tcp_blockers.append("balance_method='uri'")
            if tcp_blockers:
                raise ValueError(
                    f"backend.mode='tcp' is incompatible with the "
                    f"following HTTP-only field(s): {', '.join(tcp_blockers)}. "
                    "HAProxy rejects these directives in a TCP-mode "
                    "backend at parse time. Switch to mode='http' OR "
                    "unset the listed field(s) and resubmit."
                )
        return self


class FrontendStep(BaseModel):
    name: str = Field(..., pattern=_FRONTEND_NAME_REGEX)
    mode: Literal["http", "tcp"] = "http"
    bind_address: str = Field(default="*", max_length=64)
    bind_port: int = Field(default=80, ge=1, le=65535)
    https_redirect: bool = False
    # Phase K: `redirect_rules` is intentionally heterogeneous to keep
    # `services/haproxy_config.py::_format_redirect_rule` (which accepts
    # both legacy raw strings and structured dicts) backward compatible.
    # `acl_rules` and `use_backend_rules` are pure `List[str]` because
    # the renderer only knows how to emit string elements there
    # (non-strings are silently dropped with a warning, and
    # `routers/backend.py` does substring-match on these lists when
    # cleaning up after a backend deletion — both paths assume strings).
    # Bulgu #58 (round-20 audit) — cap list lengths.
    #
    # Pre-fix `acl_rules` / `use_backend_rules` / `redirect_rules` had
    # NO max_length, so an authenticated wizard user could POST a
    # frontend payload with tens of thousands of rules. Two failure
    # modes:
    #   1. The body itself passes the 256KB draft cap (`SiteDraftCreate`
    #      enforces that for drafts, but POST /api/sites accepts a
    #      larger inline body up to FastAPI/uvicorn's default request
    #      size). The wizard happily INSERTs a frontend whose JSONB
    #      columns are megabytes wide.
    #   2. The agent's HAProxy config render expands every entry into
    #      a line; the generated config can easily push past HAProxy's
    #      parser memory limits and reload becomes a several-second
    #      stop-the-world event.
    #
    # Real wizard frontends rarely need more than a dozen rules. The
    # cap is set to 256 per list — generous for advanced multi-domain
    # proxies but bounded enough to refuse abuse. Operators with a
    # genuine 257-rule frontend can split the work across two
    # frontends (or use a regex-aggregating ACL).
    redirect_rules: List[Union[str, dict]] = Field(
        default_factory=list, max_length=256,
    )
    acl_rules: List[str] = Field(default_factory=list, max_length=256)
    use_backend_rules: List[str] = Field(default_factory=list, max_length=256)
    options: Optional[str] = Field(default=None, max_length=8192)
    tcp_request_rules: Optional[str] = Field(default=None, max_length=8192)
    # Bulgu #45 (round-17 audit) — frontend timeouts share the same
    # ms upper bound as backend timeouts (HAProxy parser is signed
    # int32 of ms). Cap at 24h to defend against typos like
    # 60_000_000 ("operator meant seconds").
    timeout_client: Optional[int] = Field(
        default=None, ge=100, le=_MAX_HAPROXY_TIMEOUT_MS,
    )
    timeout_http_request: Optional[int] = Field(
        default=None, ge=100, le=_MAX_HAPROXY_TIMEOUT_MS,
    )
    # Bulgu #46 (round-17 audit) — DoS-shaped maxconn / rate_limit.
    # HAProxy parses these as uint, but practical limits are bounded
    # by the agent's `ulimit -n`. 1M is a defensive ceiling well above
    # any realistic production value.
    maxconn: Optional[int] = Field(
        default=None, ge=1, le=_MAX_HAPROXY_CONN_LIMIT,
    )
    rate_limit: Optional[int] = Field(
        default=None, ge=0, le=_MAX_HAPROXY_CONN_LIMIT,
        description="Per-frontend rate limit (req/sec)",
    )
    compression: bool = Field(default=False, description="Enable HAProxy gzip compression")
    log_separate: bool = Field(default=False, description="Use a dedicated log section for this frontend")
    monitor_uri: Optional[str] = Field(default=None, max_length=255, description="HAProxy `monitor-uri` for health probes")
    # Header injection
    request_headers: Optional[str] = Field(default=None, max_length=8192)
    response_headers: Optional[str] = Field(default=None, max_length=8192)
    # Internal: server-side injects backend.name as default_backend before
    # delegating to frontend_service.create_frontend_row. Always None on the
    # API surface — clients should NOT set it.
    default_backend: Optional[str] = Field(default=None, max_length=255)

    @field_validator("name")
    @classmethod
    def reject_system_prefix(cls, v: str) -> str:
        if v.startswith("_"):
            raise ValueError(
                "Frontend name must not start with '_' (reserved for system-managed entities)"
            )
        # Bulgu #43 (round-17 audit) — section keyword check.
        return _validate_not_haproxy_keyword(v, "frontend.name")

    @field_validator("bind_address")
    @classmethod
    def _validate_bind_address(cls, v: str) -> str:
        """Bulgu #44 (round-17 audit) — `bind_address` is interpolated
        verbatim into the rendered `bind <addr>:<port>` line. Pre-fix
        the only constraint was `max_length=64`, which accepted:

          * `'foo bar'`  → renders `bind foo bar:80` (HAProxy parses
            `bar:80` and SILENTLY discards `foo` — operator's IP
            allocation is wrong without any error);
          * `'$(...)'`   → potential shell-metacharacter confusion in
            tooling that pipes the rendered config through `sh -c`;
          * `'-r'`       → looks like an HAProxy CLI flag in admin
            grep output;
          * `'/etc/x'`   → path-style nonsense.

        Constrain to the HAProxy `bind` host syntax (covers `*`, IPv4
        dotted, IPv6 raw or bracketed, hostnames, and HAProxy env
        references `@<varname>`). The result is a strict-but-complete
        positive list."""
        if v is None:
            return v
        stripped = v.strip()
        if not stripped:
            raise ValueError(
                "frontend.bind_address must not be empty or whitespace-only "
                "(use '*' for all interfaces)"
            )
        if stripped != v:
            raise ValueError(
                "frontend.bind_address must not contain leading or trailing "
                "whitespace"
            )
        if any(ch.isspace() for ch in stripped):
            raise ValueError(
                "frontend.bind_address must not contain whitespace "
                f"(got {v!r}). HAProxy's `bind` parser splits at the first "
                "space, so an embedded space silently truncates the address."
            )
        # Reject leading hyphen up-front so the operator never gets
        # confused with HAProxy / shell CLI flag tokens (`-r`,
        # `-d`, …) in admin grep output.
        if stripped.startswith("-"):
            raise ValueError(
                f"frontend.bind_address={v!r} must not start with '-' "
                "(would shadow HAProxy / shell CLI flag tokens in admin "
                "grep output)."
            )
        if not _BIND_ADDRESS_REGEX.match(stripped):
            raise ValueError(
                f"frontend.bind_address={v!r} is not a valid HAProxy bind "
                "host. Accepted forms: '*' (all), '0.0.0.0' / '127.0.0.1' "
                "(IPv4), '[::]' / '[::1]' (IPv6 bracketed), '<hostname>', "
                "'@<varname>' (HAProxy env reference)."
            )
        return stripped

    @field_validator("monitor_uri")
    @classmethod
    def _validate_monitor_uri(cls, v: Optional[str]) -> Optional[str]:
        """Bulgu #16 (round-6 audit): HAProxy's `monitor-uri` directive
        expects an absolute path beginning with `/`. Pre-fix the wizard
        accepted `monitor_uri='hel'` (no leading slash) and emitted
        `monitor-uri hel` into the frontend block. HAProxy then treats
        the value as a relative match and the operator's health-probe
        URL silently returns 503.

        Additional reject criteria:
          * embedded whitespace breaks the directive at the parser
            (everything after the first space becomes an unknown
            keyword);
          * embedded `\n` would smuggle a second directive into the
            block (we already reject newlines in `acl_rules` via
            `_validate_haproxy_directive_string`, but `monitor_uri`
            was a separate code path).
        """
        if v is None:
            return v
        s = v.strip()
        if not s:
            return None
        if not s.startswith('/'):
            raise ValueError(
                "frontend.monitor_uri must start with '/' "
                "(HAProxy `monitor-uri` requires an absolute path, "
                f"got {v!r})"
            )
        # Reject any whitespace including \t, \r, \n.
        if any(ch.isspace() for ch in s):
            raise ValueError(
                "frontend.monitor_uri must not contain whitespace "
                "(HAProxy's `monitor-uri` parser splits the line at "
                f"the first space, got {v!r})"
            )
        return s

    @field_validator("acl_rules", mode="before")
    @classmethod
    def _validate_acl_rules(cls, v: Any) -> List[str]:
        """Phase K: enforce string-only contract + manual-API security
        parity (newline reject, danger pattern reject, length bound).
        """
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("acl_rules must be a list of HAProxy directive strings")
        return [_validate_haproxy_directive_string(el, "acl_rules") for el in v]

    @field_validator("use_backend_rules", mode="before")
    @classmethod
    def _validate_use_backend_rules(cls, v: Any) -> List[str]:
        """Phase K: same contract as acl_rules — string only, sanitised.

        Phase K Phase D follow-up (Bulgu #13) — additionally rejects
        self-contradictory conditions (`X AND NOT X`) because those
        produce dead-code routing rules that silently fall through to
        `default_backend`.
        """
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("use_backend_rules must be a list of HAProxy directive strings")
        return [
            _validate_haproxy_directive_string(
                el, "use_backend_rules", check_acl_contradiction=True
            )
            for el in v
        ]

    @field_validator("redirect_rules", mode="before")
    @classmethod
    def _validate_redirect_rules(cls, v: Any) -> List[Union[str, dict]]:
        """Phase K: heterogeneous contract — accept legacy raw-string
        fragments AND structured dicts (matching
        `services/haproxy_config.py::_format_redirect_rule`). Strings
        get the same safety pass as ACL / use_backend; dicts also
        get a `-f` flag rejection on their `condition` /
        `target` fields (Bulgu #12 round 3 extension) since the
        renderer at `_format_redirect_rule` emits those fields
        verbatim into the HAProxy directive string."""
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError(
                "redirect_rules must be a list of HAProxy directive strings or "
                "structured dicts"
            )
        normalised: List[Union[str, dict]] = []
        for el in v:
            if isinstance(el, dict):
                # Phase K Phase D follow-up (Bulgu #12 round 3
                # extension) — dict-shaped redirect rules emit their
                # `condition` / `target` fields VERBATIM into the
                # rendered HAProxy directive. A dict with
                # `condition: "if { src -f /etc/haproxy/x.lst }"`
                # would slip past the string-only validator above
                # and trigger the same operator-reported "failed to
                # open pattern file" rejection at apply time. Reject
                # `-f` in any string-shaped value the dict carries.
                for field_name in ("condition", "target", "type"):
                    val = el.get(field_name)
                    if isinstance(val, str) and _ACL_FILE_FLAG_PATTERN.search(val):
                        raise ValueError(
                            f"redirect_rules.{field_name}: {_ACL_FILE_FLAG_MESSAGE}"
                        )
                # Bulgu #13 extension — same contradiction guard
                # for dict-shaped redirect conditions.
                cond_val = el.get("condition")
                if isinstance(cond_val, str):
                    conflicts = _detect_acl_contradiction(cond_val)
                    if conflicts:
                        raise ValueError(
                            f"redirect_rules.condition: "
                            f"{_ACL_CONTRADICTION_MESSAGE} "
                            f"Conflicting ACL(s): {', '.join(conflicts)}."
                        )
                normalised.append(el)
            elif isinstance(el, str):
                normalised.append(
                    _validate_haproxy_directive_string(
                        el, "redirect_rules", check_acl_contradiction=True
                    )
                )
            else:
                raise ValueError(
                    "redirect_rules entries must be HAProxy directive strings "
                    f"or structured dicts; got {type(el).__name__}"
                )
        return normalised

    @model_validator(mode="after")
    def reject_redirect_conflict(self) -> "FrontendStep":
        # M19: https_redirect (UI sugar) is server-side expanded to a
        # redirect_rules row. Cannot coexist with explicit redirect_rules.
        if self.https_redirect and self.redirect_rules:
            raise ValueError(
                "https_redirect and redirect_rules are mutually exclusive: "
                "set redirect_rules manually OR enable https_redirect, not both"
            )
        return self

    @model_validator(mode="after")
    def reject_tcp_mode_with_https_redirect(self) -> "FrontendStep":
        """Phase K: TCP-mode frontends operate at L4 and cannot inspect
        HTTP headers, so an `http-request redirect` / `redirect scheme`
        directive is meaningless on a TCP frontend. The renderer at
        `services/haproxy_config.py:829-845` does NOT branch on mode
        before emitting redirect lines, so without this guard a
        `mode='tcp' + https_redirect=true` payload would silently
        produce a config that the agent's `haproxy -c` rejects only at
        apply time. Reject it here so the operator gets immediate,
        actionable feedback instead of a post-apply red badge."""
        if self.mode == "tcp" and self.https_redirect:
            raise ValueError(
                "frontend.mode='tcp' is incompatible with "
                "frontend.https_redirect=true: TCP frontends operate at L4 "
                "and cannot inspect HTTP headers. Switch to mode='http' or "
                "disable the HTTP→HTTPS redirect switch."
            )
        # Bulgu #19 (round-9 audit) — generalisation of the
        # https_redirect guard to ANY explicit redirect_rules entry.
        # Pre-fix the operator could submit:
        #
        #     frontend.mode = 'tcp'
        #     frontend.https_redirect = false   ← passes the older check
        #     frontend.redirect_rules = [{...scheme rule...}]
        #
        # and the renderer would happily emit `redirect ...` lines
        # inside a `mode tcp` frontend. The agent's `haproxy -c`
        # then refuses to load the config with the same fatal
        # parse error described above. Reject explicit redirect
        # rules on TCP frontends too. Empty list is fine.
        if self.mode == "tcp" and self.redirect_rules:
            raise ValueError(
                "frontend.mode='tcp' is incompatible with "
                "frontend.redirect_rules: HAProxy `redirect` directives "
                "are HTTP-only. Switch to mode='http' or remove the "
                "redirect_rules entries to continue."
            )
        # Bulgu #19 (round-9 audit) — `acl_rules` / `use_backend_rules`
        # are also HTTP-leaning: the renderer emits them as
        # `acl ...` + `use_backend ...` lines which HAProxy ONLY
        # honors in HTTP frontends (TCP frontends use
        # `tcp-request content use-backend` instead). Pre-fix the
        # wizard accepted these on a TCP frontend and the agent
        # silently routed everything to `default_backend`. We do
        # NOT reject ACL/use_backend on TCP outright (operators may
        # use them via `tcp-request content` snippets in
        # `tcp_request_rules`) — but warn-via-strict-rule shape is
        # outside this audit. Pin only the redirect mismatch.

        # Bulgu #20 (round-10 audit) — additional TCP-mode guards.
        # The renderer in `services/haproxy_config.py` emits the
        # following directives UNCONDITIONALLY (not gated on mode):
        #
        #   * `compression algo gzip` — HAProxy refuses to load a
        #     TCP frontend with a `compression` directive: it can
        #     only operate at L7. Parse error at apply.
        #   * `monitor-uri <path>` — HAProxy 2.4+ rejects this in a
        #     TCP frontend ("monitor-uri requires HTTP mode" parse
        #     error).
        #   * `rate_limit` expands to `stick-table` + a pair of
        #     `http-request track-sc0 src` + `http-request deny`
        #     lines. The `http-request` family is HTTP-only — TCP
        #     parse error.
        #   * `timeout http-request <ms>` — softly accepted by
        #     HAProxy on TCP frontends but emitted as a
        #     "directive ignored in mode tcp" warning, surfacing
        #     in Apply Management as a confusing post-apply
        #     warning on a config that did not need that timeout.
        #
        # Reject each at the model boundary so the operator sees a
        # clear "switch mode or unset X" message instead of an
        # opaque apply-time parse error.
        if self.mode == "tcp":
            tcp_blockers: List[str] = []
            if self.compression:
                tcp_blockers.append("compression=true")
            if self.monitor_uri:
                tcp_blockers.append("monitor_uri")
            if self.rate_limit is not None and self.rate_limit > 0:
                tcp_blockers.append("rate_limit")
            if self.timeout_http_request is not None:
                tcp_blockers.append("timeout_http_request")
            # Bulgu #56 (round-19 audit) — request_headers / response_headers
            # emit `http-request set-header …` / `http-response set-header …`
            # directives via haproxy_config.py:1063-1074 unconditionally
            # (the renderer does NOT branch on mode). HAProxy's parser
            # then refuses to load the config:
            #
            #   [ALERT] : config: 'http-response' is not allowed in
            #            'frontend' section in mode tcp
            #
            # Pre-fix the wizard happily accepted the combo, the agent
            # tried to reload, the parse error blocked ALL subsequent
            # applies on the cluster (the apply queue marks the version
            # as FAILED but cannot move forward without operator
            # intervention). Reject the combination at submit time.
            if self.request_headers:
                tcp_blockers.append("request_headers")
            if self.response_headers:
                tcp_blockers.append("response_headers")
            if tcp_blockers:
                raise ValueError(
                    f"frontend.mode='tcp' is incompatible with the "
                    f"following HTTP-only field(s): {', '.join(tcp_blockers)}. "
                    "HAProxy rejects these directives in a TCP-mode "
                    "frontend at parse time. Switch to mode='http' OR "
                    "unset the listed field(s) and resubmit."
                )
        return self


class SSLChoice(BaseModel):
    """SSL configuration leg of the wizard.

    mode='acme'     -> stage an ACME order, defer HTTPS frontend creation to
                       _complete_certificate's post_completion_actions.
    mode='upload'   -> upload a PEM cert+key now, create HTTPS frontend in
                       the same atomic transaction.
    mode='existing' -> reuse a pre-existing ssl_certificate id (admin
                       previously imported), create HTTPS frontend.
    mode='none'     -> HTTP-only host (no HTTPS frontend, no cert).
    """

    mode: Literal["acme", "upload", "existing", "none"]

    # mode=upload
    name: Optional[str] = Field(default=None, max_length=255)
    # R14 hardening: bound PEM payloads. A real RSA-4096 cert is ~2KB,
    # a typical chain is ~6KB. 64KB per field is a comfortable 10x
    # safety margin while preventing pathological DOS-shaped uploads
    # from inflating request memory and the SSL service downstream.
    certificate_content: Optional[str] = Field(default=None, max_length=65536)
    private_key_content: Optional[str] = Field(default=None, max_length=65536)
    chain_content: Optional[str] = Field(default=None, max_length=65536)

    # mode=existing
    ssl_certificate_id: Optional[int] = None

    # mode=acme
    auto_renew: bool = True
    # NOTE: per-cert renewal-before-days override is NOT yet plumbed
    # through to the renewal scheduler (v1.6.0). We deliberately omit the
    # field from the wizard payload to avoid offering a placebo control
    # in the UI — global `acme.renew_before_days` still applies.
    account_id: Optional[int] = None  # if None, server picks the latest valid account

    # HTTPS frontend overrides (used by upload/existing/acme post-completion):
    https_bind_port: int = Field(default=443, ge=1, le=65535)
    https_frontend_name_suffix: Optional[str] = Field(default="-https", max_length=64)
    # ----- Advanced TLS / HTTPS frontend tuning (HAProxy 2.4+ bind directives)
    # IMPORTANT: defaults are intentionally None so v1.5.0 first-deploy
    # behaviour is preserved unchanged. Setting these defaults to e.g.
    # 'TLSv1.2' or 'h2,http/1.1' would change the cipher/ALPN profile of
    # newly-created HTTPS frontends compared with the first 1.5.0 release —
    # a silent backward-compat regression. The wizard UI populates the
    # form with sensible *form-level* initial values; the model stays
    # neutral so direct API callers and saved drafts behave identically.
    ssl_alpn: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Comma-separated ALPN protocols (e.g. 'h2,http/1.1')",
    )
    ssl_min_ver: Optional[Literal["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]] = Field(
        default=None,
        description="Minimum TLS version (HAProxy `ssl-min-ver`)",
    )
    ssl_max_ver: Optional[Literal["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]] = None
    ssl_ciphers: Optional[str] = Field(
        default=None, max_length=2048,
        description="OpenSSL cipher list (HAProxy `ciphers`)",
    )
    ssl_ciphersuites: Optional[str] = Field(
        default=None, max_length=2048,
        description="TLS 1.3 ciphersuites (HAProxy `ciphersuites`)",
    )
    ssl_strict_sni: bool = Field(
        default=False,
        description="Reject TLS handshakes without matching SNI (HAProxy `strict-sni`)",
    )
    # R17 minimum-parity: client cert verification (mTLS) on the HTTPS bind.
    # Same Literal set as the manual frontend create endpoint (FrontendConfig).
    # Default None (unset) so v1.5.0 first-deploy hosts continue serving
    # anonymous TLS — switching this on is an opt-in security upgrade.
    ssl_verify: Optional[Literal["none", "optional", "required"]] = Field(
        default=None,
        description="mTLS client cert auth on the HTTPS bind: 'none' "
        "(disabled), 'optional' (accept anonymous), or 'required' (reject "
        "anonymous). Default None means the bind directive is omitted.",
    )

    @field_validator("ssl_verify", mode="before")
    @classmethod
    def coerce_ssl_verify_empty_to_none(cls, v):
        """PR-2 (R11.B): UI Select widgets clear to '' (empty string).
        Coerce empty / sentinel values to None so the generator omits
        the directive. Genuine values pass through for Literal check.
        """
        if v is None:
            return None
        if isinstance(v, str):
            stripped = v.strip().lower()
            if stripped in ("", "[]", "{}", "null"):
                return None
            if stripped in ("none", "optional", "required"):
                return stripped
        return v
    hsts_enabled: bool = Field(
        default=False,
        description="Inject HTTP Strict-Transport-Security header on HTTPS responses",
    )
    hsts_max_age: int = Field(
        default=31536000, ge=0, le=63072000,
        description=(
            "HSTS max-age in seconds (default 1 year). Capped at "
            "63072000 (2 years), the largest value the HSTS preload "
            "list currently accepts. R18b audit fix (round 4 #D): "
            "pre-fix the field accepted unbounded ints, which let an "
            "operator emit `Strict-Transport-Security: max-age=10**18` "
            "and effectively pin the host to HTTPS forever in every "
            "browser that observed the response — recovery requires "
            "user-side cache invalidation."
        ),
    )
    hsts_include_subdomains: bool = True
    hsts_preload: bool = False

    @field_validator("name")
    @classmethod
    def _validate_ssl_name_no_path_traversal(cls, v: Optional[str]) -> Optional[str]:
        """Bulgu #21 (round-11 audit): ssl.name is interpolated into the
        on-disk certificate path by haproxy_config.py:

            cert_path = f"/etc/ssl/haproxy/{ssl_cert['name']}.pem"

        and emitted into the rendered HAProxy config. The agent then
        runs `mv "$temp_cert_file" "$cert_file_path"` as root, which
        means a name like '../../tmp/evil' resolves to '/tmp/evil.pem'
        and would let an operator with ssl.create permission overwrite
        arbitrary `*.pem` files on the agent host (privilege-escalation
        vector: ssl-upload-only operator gains arbitrary-file-write).
        The trailing `.pem` suffix mitigates common exploit paths
        (cron.d, profile.d, authorized_keys) but is defense-only — the
        right fix is to constrain `name` to a safe filename character
        class at the wizard boundary.

        Restrict to `[A-Za-z0-9_.-]` and explicitly reject:
          * empty string
          * leading dot (hidden files / `.pem` accidentally collapsing
            to a path component named `.pem`)
          * embedded `..` (path traversal)
          * leading `-` (HAProxy CLI flag confusion when admins inspect
            files; also matches /etc/ssl/haproxy/-rf as accidental rm
            target)
        """
        if v is None:
            return v
        stripped = v.strip()
        if not stripped:
            return v
        if stripped != v:
            raise ValueError(
                "ssl.name must not contain leading or trailing whitespace"
            )
        if len(stripped) > 200:
            raise ValueError("ssl.name must be 200 characters or fewer")
        import re as _re
        if not _re.match(r'^[A-Za-z0-9_.-]+$', stripped):
            raise ValueError(
                f"ssl.name={v!r} contains forbidden characters — only "
                "letters, digits, underscore, hyphen, and dot are allowed "
                "(the certificate name is used as a filename component "
                "under /etc/ssl/haproxy/)."
            )
        if ".." in stripped:
            raise ValueError(
                f"ssl.name={v!r} must not contain '..' (path traversal)"
            )
        if stripped.startswith("."):
            raise ValueError(
                f"ssl.name={v!r} must not start with '.' (hidden filename)"
            )
        if stripped.startswith("-"):
            raise ValueError(
                f"ssl.name={v!r} must not start with '-' (CLI flag confusion)"
            )
        return stripped

    @field_validator("https_frontend_name_suffix")
    @classmethod
    def _validate_https_suffix(cls, v: Optional[str]) -> Optional[str]:
        """Bulgu #16 (round-6 audit): the suffix is appended to the
        HTTP frontend's name to form the HTTPS frontend's name.
        For the result to be a valid HAProxy frontend name (matches
        `^[a-zA-Z][a-zA-Z0-9_-]{0,63}$`) the suffix must:

          * be non-empty (empty suffix would generate an HTTPS
            frontend that collides with the HTTP frontend's name
            and surfaces as a confusing fe-name collision error
            late at submit time);
          * contain ONLY `[a-zA-Z0-9_-]` (the HAProxy frontend-
            name character class) so the composite name doesn't
            break the parser.

        Pre-fix the wizard accepted `https_frontend_name_suffix=""`
        and `"-with spaces "` and only surfaced the error AFTER a
        round-trip through `create_frontend_row`, which by then
        had already created the backend + servers + ACME order.
        """
        if v is None:
            return v
        if v == "":
            raise ValueError(
                "ssl.https_frontend_name_suffix must not be empty — "
                "set a non-empty suffix (default '-https') so the "
                "HTTPS frontend's name does not collide with the "
                "HTTP frontend's name."
            )
        import re as _re
        if not _re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError(
                f"ssl.https_frontend_name_suffix={v!r} must only "
                "contain letters, digits, '_' or '-' (the HAProxy "
                "frontend-name character class). The composite "
                "`<frontend.name><suffix>` must be a valid HAProxy "
                "frontend name."
            )
        return v

    @model_validator(mode="after")
    def reject_hsts_preload_without_hsts(self):
        """R18b audit fix (round 5 #M): an operator can independently
        toggle `hsts_preload`/`hsts_include_subdomains` even with
        `hsts_enabled=False`. The wizard then persists the booleans
        but emits NO Strict-Transport-Security header at all (the
        emit is gated on `hsts_enabled`). Result: the operator sees
        "preload on" and assumes the site is preload-eligible while
        in reality the header is absent, so the preload list will
        reject submission. Surface the contradiction at validation
        time instead of letting the misconfig sit in the DB.
        """
        if self.hsts_preload and not self.hsts_enabled:
            raise ValueError(
                "ssl.hsts_preload=true requires ssl.hsts_enabled=true. "
                "Preload submission also requires include_subdomains and "
                "max-age >= 31536000."
            )
        # The HSTS preload list (https://hstspreload.org) explicitly
        # requires max_age >= 1 year and include_subdomains=true. Reject
        # combinations that would never satisfy submission so we don't
        # mislead operators chasing preload eligibility.
        if self.hsts_preload and self.hsts_max_age < 31536000:
            raise ValueError(
                "ssl.hsts_preload=true requires hsts_max_age >= 31536000 "
                "(1 year) per the HSTS preload list policy."
            )
        if self.hsts_preload and not self.hsts_include_subdomains:
            raise ValueError(
                "ssl.hsts_preload=true requires hsts_include_subdomains=true "
                "per the HSTS preload list policy."
            )
        # R18c audit fix (round 3 #6): refuse TLS 1.0 / 1.1 on the
        # HTTPS frontend bind for the same RFC 8996 reasons as the
        # backend server validator. Operators can still author the
        # frontend through the regular Frontends UI; the wizard
        # surface stays modern.
        for fld in ("ssl_min_ver", "ssl_max_ver"):
            v = getattr(self, fld, None)
            if v in ("TLSv1.0", "TLSv1.1"):
                raise ValueError(
                    f"ssl.{fld}={v} is no longer accepted by the wizard. "
                    "TLS 1.0 / 1.1 are deprecated by RFC 8996. Use TLSv1.2 "
                    "or TLSv1.3."
                )

        # Bulgu #48 (round-17 audit) — ALPN ↔ TLS min-version
        # consistency. RFC 7540 (HTTP/2) section 9.2 makes TLS 1.2
        # the MINIMUM for HTTP/2 over TLS, and major browsers
        # additionally require the `EXTENDED_MASTER_SECRET` + AEAD
        # ciphers introduced at TLS 1.2. An operator who picks
        # `ssl_alpn='h2,http/1.1'` together with `ssl_min_ver=
        # 'TLSv1.0'` (allowed by the Literal) creates a config
        # where TLS 1.0/1.1 clients DOWNGRADE — but the server STILL
        # advertises h2 in the ALPN list. Modern browsers refuse the
        # handshake; old browsers fall back to HTTP/1.1; the operator
        # sees inconsistent breakage with no obvious cause. With the
        # TLS 1.0/1.1 reject above already in place, the practical
        # surface is `ssl_alpn='h2,…'` plumbed alongside an unset
        # `ssl_min_ver` (defaults to whatever HAProxy/OpenSSL
        # negotiates, typically 1.0 on old OS images). Require
        # `ssl_min_ver` to be set to 1.2+ when h2 is advertised so
        # the operator sees a clear "set ssl_min_ver=TLSv1.2"
        # message instead of debugging browser-side ERR_SPDY_…
        # errors weeks later.
        alpn = (self.ssl_alpn or "").lower().strip()
        if alpn and "h2" in [tok.strip() for tok in alpn.split(",")]:
            min_ver = self.ssl_min_ver
            # min_ver=None means "let HAProxy choose" which may
            # negotiate < TLSv1.2 on older agents. Require explicit
            # 1.2+ so HTTP/2 is unambiguously safe.
            if min_ver not in ("TLSv1.2", "TLSv1.3"):
                raise ValueError(
                    f"ssl.ssl_alpn={self.ssl_alpn!r} advertises h2 (HTTP/2) "
                    "but ssl.ssl_min_ver is "
                    f"{min_ver if min_ver else 'unset (HAProxy default)'}. "
                    "RFC 7540 section 9.2 mandates TLS 1.2+ for h2; "
                    "modern browsers refuse the handshake otherwise. "
                    "Set ssl.ssl_min_ver to 'TLSv1.2' or 'TLSv1.3', OR "
                    "remove 'h2' from the ALPN list."
                )
        return self

    @model_validator(mode="after")
    def reject_ssl_verify_without_ca_file(self) -> "SSLChoice":
        """Bulgu #26 (round-12 audit): SSLChoice.ssl_verify accepts
        'optional' and 'required' but the renderer's
        `_resolve_frontend_client_ca_path` always returns None (PR-7
        placeholder), which triggers the safeguard in
        `_apply_bind_ssl_verify` that SILENTLY DROPS the `verify`
        directive to prevent a fatal HAProxy ALERT. Result: an
        operator who selects "required — reject anonymous" in the UI
        gets a cert row with `ssl_verify='required'`, sees no error
        anywhere, but the rendered HAProxy bind has NO `verify` token
        at all. mTLS is silently disabled. The site appears to be
        configured for mTLS in the OpenManager UI / DB / preview, but
        the actual TLS handshake accepts anonymous clients.

        Until the ca-file column (PR-7) is wired through the wizard,
        reject `ssl_verify in ('optional', 'required')` at submit so
        the operator gets a clear, actionable error instead of a
        silent misconfig.
        """
        if self.ssl_verify in ("optional", "required"):
            raise ValueError(
                f"ssl.ssl_verify='{self.ssl_verify}' requires a client-CA "
                "bundle (HAProxy `ca-file`). The Site Wizard does not yet "
                "plumb the ca-file field, so the renderer SILENTLY DROPS "
                "the `verify` directive to avoid a fatal HAProxy parse "
                "error — your mTLS selection would NOT actually be "
                "enforced. Set ssl.ssl_verify to None (or 'none') here "
                "and configure mTLS via Frontend Management → Advanced "
                "TLS once the wizard exposes the client-CA bundle field."
            )
        return self

    @field_validator("ssl_alpn")
    @classmethod
    def _validate_ssl_alpn(cls, v: Optional[str]) -> Optional[str]:
        """Bulgu #27 (round-12 audit): ssl_alpn is emitted verbatim
        into `bind ... alpn <value>`. HAProxy expects a comma-
        separated list of ALPN protocol identifiers (RFC 7301);
        whitespace inside a token or a stray separator triggers
        parse errors at apply time. Pre-fix the wizard accepted
        any string up to 128 chars, so `ssl_alpn='h2, http/1.1'`
        (note the space after the comma) made it through and
        broke apply with a confusing 'no shared cipher' surface.

        Accepted token grammar: `[A-Za-z0-9._/-]+` per token. IANA
        ALPN registry IDs (`h2`, `http/1.1`, `acme-tls/1`, etc.)
        all match this. Tokens are split on `,` and each token is
        stripped before validation so "h2, http/1.1" is the same
        as "h2,http/1.1" — but we re-join with no spaces because
        HAProxy is whitespace-strict.
        """
        if v is None:
            return v
        stripped = v.strip()
        if not stripped:
            return None
        if len(stripped) > 128:
            raise ValueError("ssl.ssl_alpn must be 128 characters or fewer")
        import re as _re
        tokens_raw = [t.strip() for t in stripped.split(",")]
        if any(not t for t in tokens_raw):
            raise ValueError(
                "ssl.ssl_alpn must not contain empty tokens "
                "(e.g. trailing comma or 'h2,,http/1.1')"
            )
        for tok in tokens_raw:
            if not _re.match(r"^[A-Za-z0-9._/-]+$", tok):
                raise ValueError(
                    f"ssl.ssl_alpn token {tok!r} contains invalid characters. "
                    "Each ALPN protocol identifier must match the IANA "
                    "ALPN registry grammar (e.g. 'h2', 'http/1.1', "
                    "'acme-tls/1'); use only letters, digits, '.', '_', "
                    "'/' or '-'."
                )
        return ",".join(tokens_raw)

    @field_validator("ssl_ciphers", "ssl_ciphersuites")
    @classmethod
    def _validate_ssl_cipher_list(
        cls, v: Optional[str], info
    ) -> Optional[str]:
        """Bulgu #33 (round-14 audit): `ssl_ciphers` / `ssl_ciphersuites`
        get interpolated directly into `bind ... ciphers <value>` and
        `bind ... ciphersuites <value>` directives. OpenSSL cipher
        specifications are colon-separated identifiers with optional
        `!` / `+` / `-` / `@` operators (e.g.
        `ECDHE-RSA-AES128-GCM-SHA256:!aNULL:!MD5`). No whitespace,
        no newlines.

        Pre-fix the wizard only enforced `max_length=2048`, so a
        newline-bearing value would split the bind line and inject
        arbitrary HAProxy directives into the frontend block. We
        reject any control character, newline, AND any embedded
        whitespace (HAProxy's bind-line tokenizer splits at the first
        space, so a space inside the cipher spec would shift later
        keywords like `ssl-min-ver` / `alpn` into wrong positions).

        We do NOT validate the cipher-name grammar itself — that's
        OpenSSL's job and the catalogue evolves; the validator's
        scope is strict shape-only (no whitespace, no control chars,
        no newlines).
        """
        if v is None:
            return v
        stripped = v.strip()
        if not stripped:
            return None
        if '\n' in stripped or '\r' in stripped:
            field_name = info.field_name if info else 'cipher field'
            raise ValueError(
                f"ssl.{field_name} must not contain line breaks "
                "(HAProxy bind directives are single-line; embedded "
                "newlines would smuggle additional directives into "
                "the rendered frontend block)"
            )
        if any(ch.isspace() for ch in stripped):
            field_name = info.field_name if info else 'cipher field'
            raise ValueError(
                f"ssl.{field_name} must not contain whitespace "
                f"(got {v!r}). OpenSSL cipher specs are colon-"
                "separated with no embedded spaces; HAProxy's "
                "bind-line tokenizer would otherwise read the rest "
                "of the value as separate keywords."
            )
        return stripped

    @model_validator(mode="after")
    def reject_inverted_tls_versions(self) -> "SSLChoice":
        """Phase K: when both `ssl_min_ver` and `ssl_max_ver` are set,
        require min <= max. HAProxy emits `ssl-min-ver` / `ssl-max-ver`
        bind options independently; if `min > max` the resulting bind
        accepts no TLS handshakes at all (the agent's `haproxy -c`
        accepts the syntax but every TLS handshake fails at runtime
        with a generic "no shared cipher" error, which is surprisingly
        hard to diagnose). Surface the contradiction at the wizard
        boundary instead of letting a saved-and-applied site sit in a
        broken state."""
        order = {
            "TLSv1.0": 0,
            "TLSv1.1": 1,
            "TLSv1.2": 2,
            "TLSv1.3": 3,
        }
        if self.ssl_min_ver and self.ssl_max_ver:
            if order[self.ssl_min_ver] > order[self.ssl_max_ver]:
                raise ValueError(
                    f"ssl.ssl_min_ver={self.ssl_min_ver} cannot be greater "
                    f"than ssl.ssl_max_ver={self.ssl_max_ver}: an inverted "
                    "TLS range causes every handshake to fail at runtime."
                )
        return self


class SiteCreate(BaseModel):
    """Top-level Site Wizard create payload.

    NOTE: This class was renamed from `ProxiedHostCreate` as part of
    the v1.5.x Site rebrand. A backward-compat alias
    `ProxiedHostCreate = SiteCreate` is exported at the bottom of this
    module so existing imports / pickled instances keep working.
    """

    cluster_id: int = Field(..., ge=1)
    domains: List[str] = Field(..., min_length=1, max_length=100)
    backend: BackendStep
    servers: List[ServerStep] = Field(..., min_length=1, max_length=50)
    frontend: FrontendStep
    ssl: SSLChoice
    apply_immediately: bool = False

    @field_validator("servers")
    @classmethod
    def reject_all_zero_weight_servers(cls, v: List["ServerStep"]) -> List["ServerStep"]:
        """Bulgu #50 (round-18 audit) — sibling of Bulgu #49 (all-backup).
        HAProxy uses `weight` to compute each server's share of incoming
        traffic; `weight=0` is the operator's "drain" signal — the
        server keeps existing keep-alive connections but receives ZERO
        new requests. If every server in a backend has weight=0, new
        traffic has nowhere to go: HAProxy returns 503 (or queues
        until queue overflow) for every request that would normally
        round-robin into this backend.

        Pre-fix the wizard's per-server `weight: ge=0` accepted 0 and
        the operator never saw a warning. The all-zero state was
        usually a typo from copy-pasting from an active-active to
        active-passive layout (operator meant to set ONE weight to 0
        as the failover slot).

        The check fires only for 2+ servers: a single-server backend
        with weight=0 is sometimes a legitimate "this backend is
        draining for maintenance" pattern.

        Distinct from Bulgu #49: the operator could mark all servers
        primary (backup_server=false) AND all weight=0 — that combo
        passes #49 but hits #50."""
        if not v or len(v) < 2:
            return v
        non_zero_weight = sum(
            1 for s in v if int(getattr(s, "weight", 100) or 0) > 0
        )
        if non_zero_weight == 0:
            raise ValueError(
                f"All {len(v)} servers have weight=0 (drain). HAProxy "
                "routes new requests by weighted round-robin — with "
                "every weight at 0 the backend silently 503s every "
                "new request. Set at least one server's weight to >0, "
                "or remove the drained server(s) entirely if they are "
                "no longer needed."
            )
        return v

    @field_validator("servers")
    @classmethod
    def reject_all_backup_servers(cls, v: List["ServerStep"]) -> List["ServerStep"]:
        """Bulgu #49 (round-17 audit) — HAProxy's `backup` flag
        designates a server as a fail-over slot: it only receives
        traffic when ALL primary (non-backup) servers in the same
        backend are marked DOWN. If every server in the backend is
        flagged `backup_server=true`, HAProxy considers the backend
        permanently unable to serve traffic — every request lands on
        `default_backend` or hits the cluster's no-server error
        response. The wizard accepts this combination silently because
        per-server validators don't see the rest of the list.

        Pre-fix the operator paste-error of "mark all 3 as backup
        because they're standby" surfaced as a hard-to-debug 503
        cascade post-apply: every health probe succeeds, but no
        request ever reaches a server.

        Reject upfront so the operator either un-marks one as
        primary or drops the backup flag entirely. The check fires
        only when there are 2+ servers (a single backup server is a
        sensible "no traffic during deploy" pattern that the
        operator may intentionally toggle on for short windows)."""
        if not v or len(v) < 2:
            return v
        primary_count = sum(
            1 for s in v if not bool(getattr(s, "backup_server", False))
        )
        if primary_count == 0:
            raise ValueError(
                f"All {len(v)} servers are flagged backup_server=true. "
                "HAProxy's `backup` slot only receives traffic when at "
                "least one PRIMARY (non-backup) server is UP — with no "
                "primaries the backend silently black-holes every "
                "request. Un-flag at least one server, or remove the "
                "backup flag entirely if you want all of them serving."
            )
        return v

    @field_validator("servers")
    @classmethod
    def reject_duplicate_server_names(cls, v: List["ServerStep"]) -> List["ServerStep"]:
        """Bulgu #17 (round-7 audit): HAProxy requires server names to
        be unique within a backend block. Two `server srv1 ...` lines
        in the same backend produce a config the agent's `haproxy -c`
        REJECTS at apply time with:

            [ALERT] ... : Proxy 'be-foo' : duplicate server 'srv1'

        Pre-fix the wizard happily forwarded the duplicate names to
        `create_backend_server_row` which only checks for backend-
        scoped uniqueness at the DB level (UNIQUE constraint), so the
        first server row was created, the second hit a UniqueViolation,
        and the wizard surfaced a generic 500 with the constraint
        name. Catching it here gives the operator a clear, actionable
        message naming the duplicate(s).

        Address+port duplicates are NOT rejected — operators sometimes
        intentionally route the same upstream through two aliases
        (e.g. `srv1-primary` + `srv1-canary`) — but server-name
        duplication is unambiguously a typo.
        """
        if not v:
            return v
        seen: dict = {}
        duplicates: List[str] = []
        for s in v:
            name = (s.server_name or '').strip()
            if not name:
                continue
            if name in seen:
                duplicates.append(name)
            else:
                seen[name] = True
        if duplicates:
            dup_unique = sorted(set(duplicates))
            raise ValueError(
                f"Duplicate server names within the same backend: "
                f"{', '.join(dup_unique)}. HAProxy requires unique "
                f"`server <name>` tokens — rename the duplicate(s)."
            )
        return v

    @field_validator("domains")
    @classmethod
    def normalise_domains(cls, v: List[str]) -> List[str]:
        """Normalize each domain (lowercase, trim) and reject
        duplicates AFTER normalisation.

        Bulgu #16 (round-6 audit): pre-fix the wizard accepted
        `["Site.com", "site.com", "www.SITE.com"]` and forwarded all
        three to:
          * the SSL upload / ACME order — Let's Encrypt rejects
            duplicate identifiers in the same order with an
            opaque error;
          * the HSTS / `domains_handled` JSONB column — duplicates
            inflate audit logs and bypass per-domain rate limits;
          * the ACME-challenge ACL routing — duplicates have no
            effect but bloat the rendered config.

        We dedupe POST-normalisation (case-insensitive) so the
        operator's "Site.com" / "site.com" pair is caught and
        rejected with a clear list of conflicting entries. The
        original ORDER of first occurrence is preserved.
        """
        if not v:
            return v
        normalised = [validate_domain(d) for d in v]
        seen: set = set()
        duplicates: List[str] = []
        unique_in_order: List[str] = []
        for d in normalised:
            if d in seen:
                duplicates.append(d)
            else:
                seen.add(d)
                unique_in_order.append(d)
        if duplicates:
            # De-dup the duplicate list too so the error message is
            # readable when the operator submitted three copies of
            # the same string.
            dup_unique = sorted(set(duplicates))
            raise ValueError(
                f"Duplicate domain entries detected (case-insensitive after "
                f"normalisation): {', '.join(dup_unique)}. Remove the "
                f"duplicate(s) and resubmit."
            )
        return unique_in_order

    @model_validator(mode="after")
    def enforce_acme_apply_and_http(self) -> "SiteCreate":
        """M22: acme mode REQUIRES apply_immediately=true so the agent can
        confirm the bulk-site-create-{ts} version (gating the
        deferred LE API call).

        Round 10 micro-finding: acme mode also REQUIRES frontend.mode='http'
        because HTTP-01 challenge is served on port 80 plain HTTP only.

        Bulgu #31: ssl.mode='upload' MUST carry non-empty PEM payload —
        otherwise create_cert_row would silently insert an unusable cert
        and break HAProxy reload at apply time.

        Bulgu #31b: ssl.mode='existing' MUST carry ssl_certificate_id —
        otherwise the wizard would fall through to the runtime check with
        a confusing 400 instead of a clean 422.
        """
        if self.ssl.mode == "acme":
            if not self.apply_immediately:
                raise ValueError(
                    "ssl.mode='acme' requires apply_immediately=true (the agent must "
                    "confirm the new HTTP frontend before the LE API call can run)"
                )
            if self.frontend.mode != "http":
                raise ValueError(
                    "ssl.mode='acme' requires frontend.mode='http' (HTTP-01 challenge)"
                )
            # Bulgu #34 (round-15 audit) — DO NOT hard-block non-80 ports here.
            #
            # Previously this model validator rejected ANY ACME payload with
            # `frontend.bind_port != 80`. That assumed the wizard's new
            # frontend is the ONLY thing on port 80 — true for solo-site
            # clusters, but FALSE for the canonical enterprise pattern where
            # one shared HTTP frontend on port 80 host-routes traffic to many
            # backends. Operators with such clusters were stuck:
            #
            #   * keep bind_port=80 → `Bind *:80 already used by frontend X`
            #     hard error (the cluster's shared port-80 frontend collides).
            #   * change bind_port → this validator rejected the payload.
            #
            # The actual HTTP-01 routing chain only requires:
            #   1. cluster.acme_enabled = TRUE (renderer injects the
            #      `/.well-known/acme-challenge/` ACL into EVERY HTTP-mode
            #      frontend in the cluster — see haproxy_config.py:974-978).
            #   2. SOME HTTP-mode frontend in the cluster listens on port 80
            #      (so LE's plain-HTTP probe can land somewhere).
            #   3. `_acme_challenge_backend` proxies to OpenManager which
            #      serves the token regardless of which domain LE asked for.
            #
            # When the cluster ALREADY has a port-80 HTTP frontend that is
            # not the wizard's new one, the wizard's new frontend can bind
            # ANY free port — the challenge will still be served by the
            # existing port-80 frontend. The route handler does the
            # cluster-aware check (it needs DB access; model validators
            # don't have it). See `_validate_acme_port80_reachable` in
            # routers/site_wizard.py.
            #
            # We keep the model-level check for the OBVIOUSLY-WRONG case
            # (port < 1 / > 65535 is already covered by FrontendStep field
            # constraints) but defer the cluster-aware "is some port-80
            # frontend reachable?" decision to the route handler.
            # R16 hardening (#R16-1): wildcard domains (e.g. '*.example.com')
            # require the DNS-01 challenge per Let's Encrypt rules — HTTP-01
            # is server-side validation against a single hostname's HTTP
            # endpoint and cannot prove ownership of an entire DNS subtree.
            # Pre-R16 the wizard happily forwarded '*.example.com' to LE,
            # which then rejected the order with "wildcard requires DNS-01"
            # — the user only saw an opaque order error long after submit.
            # Reject upfront with a clear, actionable message.
            wildcard_domains = [d for d in self.domains if d.startswith("*.")]
            if wildcard_domains:
                raise ValueError(
                    f"ssl.mode='acme' (HTTP-01) cannot issue wildcard certs "
                    f"({', '.join(wildcard_domains)}). Let's Encrypt requires "
                    "DNS-01 for wildcards. Either remove the wildcard domain "
                    "or pick ssl.mode='upload' / 'existing' with a wildcard "
                    "cert obtained out-of-band."
                )

            # Bulgu #30 (round-13 audit) — explicit scheme=https redirect_rules
            # entries bypass the auto-generated ACME-safe condition that
            # `_build_redirect_rules` emits for `https_redirect=true`.
            # FrontendStep already rejects the (https_redirect=true,
            # redirect_rules non-empty) combination as mutually exclusive,
            # so operators reach this branch by manually typing a
            # scheme→https redirect into `redirect_rules`. On an ACME
            # site that pattern would 301 the LE HTTP-01 challenge
            # request to the (not-yet-existing) HTTPS endpoint and the
            # order would fail at validation (see Bulgu #29 for the
            # detailed sequence). Reject these rules at the model
            # boundary so the operator gets a clear, actionable
            # message before submit. Allow rules that already encode
            # the `path_beg /.well-known/acme-challenge/` exclusion in
            # their condition — those are operator-curated and safe.
            unsafe_scheme_redirects: List[str] = []
            for _idx, _rule in enumerate(self.frontend.redirect_rules or []):
                if isinstance(_rule, dict):
                    if (_rule.get("type") or "").strip().lower() != "scheme":
                        continue
                    if (_rule.get("scheme") or "").strip().lower() != "https":
                        continue
                    _cond = (_rule.get("condition") or "")
                    if "/.well-known/acme-challenge" not in _cond:
                        unsafe_scheme_redirects.append(
                            f"redirect_rules[{_idx}] (dict)"
                        )
                elif isinstance(_rule, str):
                    # Legacy raw-string entries. Look for the
                    # canonical `scheme https` token; if the rule does
                    # NOT carry the challenge-path exclusion we treat
                    # it as unsafe.
                    _s = _rule.strip().lower()
                    if "scheme https" in _s and "/.well-known/acme-challenge" not in _s:
                        unsafe_scheme_redirects.append(
                            f"redirect_rules[{_idx}] (string)"
                        )
            if unsafe_scheme_redirects:
                raise ValueError(
                    "ssl.mode='acme' rejects explicit scheme=https "
                    "redirect_rules without an ACME HTTP-01 challenge "
                    "exclusion ("
                    + ", ".join(unsafe_scheme_redirects)
                    + "). The HTTP frontend on port 80 must serve "
                    "`/.well-known/acme-challenge/<token>` for Let's "
                    "Encrypt validation; a blanket scheme→https "
                    "redirect would 301 the challenge to an HTTPS "
                    "endpoint that does not exist yet (the HTTPS "
                    "frontend is created AFTER issuance succeeds). "
                    "Use frontend.https_redirect=true instead — the "
                    "wizard renders an ACME-safe condition "
                    "automatically — or add "
                    "`!{ path_beg /.well-known/acme-challenge/ }` to "
                    "your redirect rule's condition."
                )

        # R14 hardening (#R14-2): when SSL is enabled (any of acme / upload /
        # existing) the wizard creates BOTH an HTTP frontend (bind_port) AND
        # an HTTPS frontend (https_bind_port) on the same agent IPs. If the
        # user fat-fingers https_bind_port to match bind_port, HAProxy will
        # refuse to load the config because the same address:port can't be
        # bound by two frontends. Catch it at the wizard layer with a clear
        # ValueError instead of an opaque agent reload failure later.
        if self.ssl.mode in ("acme", "upload", "existing"):
            if self.frontend.bind_port == self.ssl.https_bind_port:
                raise ValueError(
                    f"ssl.https_bind_port={self.ssl.https_bind_port} cannot equal "
                    f"frontend.bind_port={self.frontend.bind_port} — the HTTP and "
                    "HTTPS frontends must bind to different ports on the same agent IPs."
                )

        # Bulgu #28 (round-12 audit): ssl.mode='none' (HTTP-only host)
        # combined with frontend.https_redirect=true (or an explicit
        # scheme=https redirect rule) is a self-bricking configuration:
        # the HTTP frontend emits `redirect scheme https code 301` for
        # every request but the wizard never creates an HTTPS frontend
        # (mode='none' skips the HTTPS bind), so the redirect points
        # at a port that has nothing listening. Browsers loop on the
        # redirect, hit a connection-refused, and the site is
        # effectively offline. Pre-fix the wizard accepted this combo
        # silently and the operator only noticed when their site went
        # dark post-apply.
        if self.ssl.mode == "none":
            scheme_redirects = [
                r for r in (self.frontend.redirect_rules or [])
                if isinstance(r, dict) and (r.get("type") == "scheme"
                                            or (r.get("scheme") or "").lower() == "https")
            ]
            if self.frontend.https_redirect or scheme_redirects:
                raise ValueError(
                    "frontend.https_redirect=true (or an explicit "
                    "scheme→https redirect rule) requires ssl.mode in "
                    "('acme','upload','existing'). With ssl.mode='none' "
                    "the wizard does not create an HTTPS frontend, so "
                    "the redirect would point at a port with nothing "
                    "listening — every visitor would see a "
                    "connection-refused error. Either set ssl.mode to "
                    "issue a cert (acme / upload / existing) or clear "
                    "the https_redirect flag."
                )
        if self.ssl.mode == "upload":
            cert_pem = (self.ssl.certificate_content or "").strip()
            key_pem = (self.ssl.private_key_content or "").strip()
            if not cert_pem or "-----BEGIN" not in cert_pem:
                raise ValueError(
                    "ssl.mode='upload' requires a non-empty PEM-encoded certificate_content "
                    "(if you resumed a draft, PEM fields were stripped at save time and must be re-entered)"
                )
            if not key_pem or "-----BEGIN" not in key_pem:
                raise ValueError(
                    "ssl.mode='upload' requires a non-empty PEM-encoded private_key_content "
                    "(if you resumed a draft, PEM fields were stripped at save time and must be re-entered)"
                )
            if not (self.ssl.name or "").strip():
                raise ValueError("ssl.mode='upload' requires ssl.name (the certificate label)")
        elif self.ssl.mode == "existing":
            if self.ssl.ssl_certificate_id is None:
                raise ValueError("ssl.mode='existing' requires ssl.ssl_certificate_id")

        # Bulgu #17 (round-7 audit): frontend / backend mode MUST
        # match. HAProxy rejects a `mode http` frontend that calls
        # `use_backend <name>` / `default_backend <name>` against a
        # `mode tcp` backend (and vice-versa) — the parser fires:
        #
        #     [ALERT] : Proxy 'fe-foo' : in mode tcp, cannot use
        #              'http' mode backend 'be-foo'.
        #
        # Pre-fix the wizard accepted any combination and the
        # mismatch only surfaced at the agent's `haproxy -c` step
        # AFTER the entities had been created with PENDING status.
        # Catch it at the model boundary so the operator never even
        # reaches Apply Management with a broken pair.
        #
        # ORDERING: this check runs AFTER the ACME-specific
        # `frontend.mode='http'` enforcement above so an ACME
        # payload with a TCP frontend surfaces the ACME-specific
        # message first (which is more actionable — "switch to http
        # OR pick a different ssl.mode"). Generic mismatches that
        # are not ACME-specific land here.
        if self.frontend.mode != self.backend.mode:
            raise ValueError(
                f"frontend.mode='{self.frontend.mode}' must match "
                f"backend.mode='{self.backend.mode}'. HAProxy refuses "
                "to load a config where a `use_backend` / "
                "`default_backend` directive crosses HTTP / TCP "
                "modes. Switch either the frontend or the backend "
                "to the same mode and resubmit."
            )

        # Bulgu #57 (round-19 audit) — HSTS is meaningless on TCP.
        #
        # The HSTS header is emitted by the renderer as
        # `http-response set-header Strict-Transport-Security …`. That
        # directive only exists in HTTP mode — the renderer + parser
        # combo bails at apply time with the same "not allowed in mode
        # tcp" parse error covered by round-19 Bulgu #56 for the
        # plain header fields. The wizard further auto-injects the
        # HSTS line into the cloned HTTPS frontend payload (see
        # routers/site_wizard.py around the `model_copy(...)` block),
        # so even if the operator's typed payload is clean, the
        # implicit HSTS injection would land on a TCP frontend.
        #
        # Reject the combination at submit time. The two escape
        # hatches mirror Bulgu #51:
        #   * switch frontend.mode to 'http' so a real HTTPS frontend
        #     exists in HTTP mode and can carry the header, OR
        #   * set hsts_enabled=false.
        #
        # The check is ordered AFTER the per-field ACME / mode-match
        # checks so the most specific message fires first; an ACME
        # TCP payload (which already fails the
        # `ssl.mode='acme' requires frontend.mode='http'` check above)
        # never reaches this branch.
        if self.frontend.mode == "tcp" and bool(getattr(self.ssl, "hsts_enabled", False)):
            raise ValueError(
                "frontend.mode='tcp' is incompatible with hsts_enabled=true. "
                "HSTS is delivered via an HTTP response header; HAProxy "
                "refuses to load a TCP frontend with `http-response "
                "set-header` directives. Either switch frontend.mode "
                "to 'http' or set hsts_enabled=false."
            )

        # Bulgu #51 (round-18 audit) — HSTS without HTTPS is a no-op.
        #
        # The wizard renders `http-response set-header
        # Strict-Transport-Security ...` ONLY on the auto-generated
        # HTTPS frontend (see haproxy_config.py - HSTS block guarded
        # by ssl.mode != 'none'). When the operator picks
        # `ssl.mode='none'` (plain HTTP site) but flips
        # `hsts_enabled=true` thinking it will "force HTTPS via the
        # browser pin", the renderer produces ZERO HSTS headers —
        # the wizard accepted the toggle, the preview diff shows
        # nothing about HSTS, and the operator is left with a false
        # sense of security.
        #
        # The fix is to reject the inconsistent payload at submit
        # time with an actionable message. Three escape hatches:
        #   1. Switch ssl.mode to 'upload'/'existing'/'acme' so an
        #      HTTPS frontend actually exists.
        #   2. Toggle hsts_enabled=false (user really only wants
        #      plain HTTP).
        #   3. (Out-of-scope of the wizard) deploy an upstream
        #      HSTS-aware proxy — the wizard cannot help with this.
        #
        # We only fire when hsts_enabled is explicitly truthy on
        # the SSLChoice payload, so legacy/None values do not
        # regress.
        if self.ssl.mode == "none" and bool(getattr(self.ssl, "hsts_enabled", False)):
            raise ValueError(
                "ssl.mode='none' is incompatible with hsts_enabled=true. "
                "HSTS headers are emitted only on the HTTPS frontend; "
                "with ssl.mode='none' the wizard does not create one, so "
                "the toggle has no effect (silent misconfiguration). "
                "Either set hsts_enabled=false or switch ssl.mode to "
                "'upload', 'existing', or 'acme' so an HTTPS frontend "
                "exists to carry the header."
            )

        return self


class SitePreflightAcme(BaseModel):
    """Body for POST /api/sites/preflight-acme."""

    cluster_id: int = Field(..., ge=1)
    domains: List[str] = Field(..., min_length=1, max_length=100)

    @field_validator("domains")
    @classmethod
    def normalise(cls, v: List[str]) -> List[str]:
        return [validate_domain(d) for d in v]


class SiteDraftCreate(BaseModel):
    """Body for POST /api/sites/drafts.

    M14/M9: PEM (private_key_content / certificate_content) is server-side
    stripped before persistence to avoid storing keys at rest in the
    wizard_drafts.payload JSONB.

    R14 hardening: bound the persisted payload size. Without an upper
    bound, an authenticated user could POST 10MB of arbitrary JSON,
    inflate the wizard_drafts.payload JSONB column, and (over time)
    fill enterprise storage. The wizard itself produces ~5–20KB of
    JSON for a richly-configured host, so a 256KB cap is generous and
    still bounded. The retention task (30 days) provides a second
    layer of cleanup.
    """

    title: Optional[str] = Field(default=None, max_length=255)
    payload: dict

    @model_validator(mode="after")
    def reject_oversized_payload(self):
        """Hard cap the JSON-serialised payload at 256KB."""
        try:
            import json as _json

            serialised = _json.dumps(self.payload, default=str)
        except Exception as exc:  # pragma: no cover — JSON serialisation failure
            raise ValueError(f"draft.payload is not JSON-serialisable: {exc}")
        if len(serialised.encode("utf-8")) > 256 * 1024:
            raise ValueError(
                "draft.payload exceeds the 256KB size limit. Trim large blobs "
                "(certificate_content / private_key_content / oversized rule "
                "lists) before saving as draft."
            )
        return self


def _strip_pem_from_payload(payload: Any) -> Any:
    """Recursively scrub any keys that look like PEM-bearing fields."""
    sensitive_keys = {
        "private_key_content",
        "certificate_content",
        "chain_content",
        "private_key",
    }
    if isinstance(payload, dict):
        out = {}
        for k, v in payload.items():
            if k in sensitive_keys:
                # Replace with a placeholder so the wizard knows the field
                # was scrubbed and prompts the user to re-enter it.
                out[k] = ""
            else:
                out[k] = _strip_pem_from_payload(v)
        return out
    if isinstance(payload, list):
        return [_strip_pem_from_payload(x) for x in payload]
    return payload


# ---------------------------------------------------------------------------
# Backward-compat aliases (Phase C of the Site rebrand).
#
# The Pydantic model classes were renamed:
#   ProxiedHostCreate          -> SiteCreate
#   ProxiedHostPreflightAcme   -> SitePreflightAcme
#   ProxiedHostDraftCreate     -> SiteDraftCreate
#
# We keep module-level aliases pointing at the new classes so any
# existing import (`from models.site_wizard import ProxiedHostCreate`)
# or pickled object continues to work without churn. The aliases are
# direct references (not subclasses) so OpenAPI / JSON-Schema only sees
# the canonical `SiteCreate` etc. names — external API consumers don't
# get a second ghost schema.
# ---------------------------------------------------------------------------
ProxiedHostCreate = SiteCreate
ProxiedHostPreflightAcme = SitePreflightAcme
ProxiedHostDraftCreate = SiteDraftCreate
