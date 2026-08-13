"""Validation and resolution for the ACME HTTP-01 challenge backend URL.

This URL tells HAProxy where to proxy ``/.well-known/acme-challenge/*``. It is
rendered into ``backend _acme_challenge_backend`` as ``server _acme_mgmt host:port``
and — this is the part that makes it unlike every other URL in the product —
**resolved on the HAProxy node, not on the management host**. A value that works
when pasted into the management server's own browser can be completely dead from
the data plane.

Two entry points, deliberately asymmetric:

``validate_acme_backend_url``
    Called at the WRITE BOUNDARY (cluster PUT, settings PUT). Rejects values that
    cannot express a reachable target. Strict here is safe: it only ever affects a
    value an operator is typing right now, and the error text can teach.

``resolve_acme_backend_target``
    Called at RENDER TIME. Never raises, never rejects. Strictness here would be a
    catastrophe: the shipped defaults (``config.py`` ``http://localhost:8000``,
    ``docker-compose.yml`` ``http://localhost:8080``) mean essentially every
    existing install resolves to loopback today, and refusing to render would make
    every ``acme_enabled`` cluster unappliable — including for urgent changes that
    have nothing to do with ACME. It reports problems instead of enforcing them.

Two conscious departures from ``utils/ssrf_guard.py``, whose policy is the exact
opposite of what is needed here:

* **RFC1918 is allowed, and is usually the correct answer.** The guard exists to
  stop the server being tricked into dialling internal space. Here the operator is
  deliberately naming their own management host, which on a split deployment is
  private by definition.
* **No DNS resolution.** Resolving from the management host would re-introduce the
  very wrong-vantage-point mistake this work exists to remove: what this box can
  resolve says nothing about what the HAProxy node can reach.
"""
import ipaddress
import re
from typing import List, NamedTuple, Optional
from urllib.parse import urlparse

# `haproxy_clusters.acme_backend_url` / `system_settings.value` are VARCHAR(500).
# Without this check asyncpg raises 22001 and the operator gets an opaque 500.
MAX_URL_LENGTH = 500

ALLOWED_SCHEMES = ("http", "https")

# Port assumed when the URL omits one. NOT the scheme's default: the bundled
# docker-compose publishes nginx on 8080 (`nginx/nginx.conf` listens 8080,
# `docker-compose.yml` maps 8080:8080), so an operator who wrote a bare
# `http://10.0.0.5` has a WORKING path today that resolves to :8080. Changing this
# to 80 would break those installs silently — the first symptom would be the
# unattended renewal loop failing months later. The value is kept and the omission
# is surfaced as a warning instead.
DEFAULT_HTTP_PORT = 8080
DEFAULT_HTTPS_PORT = 443

# RFC 1123 host label set. Deliberately not a full IDN implementation: an operator
# naming their management host in a config file pushed to HAProxy nodes should use
# ASCII, and HAProxy itself would not accept anything else on a `server` line.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
)

_CONTROL_CHARS = frozenset("\t\n\r\v\f\x00")


class AcmeBackendUrlError(ValueError):
    """A value that cannot express a usable challenge backend target.

    ``code`` is stable and machine-readable so the UI can map it to help text;
    ``args[0]`` is operator-facing prose.
    """

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AcmeBackendTarget(NamedTuple):
    """What the renderer should emit, plus everything worth telling the operator."""

    host: str
    port: int
    ssl_flag: str
    #: Non-fatal observations. Rendered anyway; surfaced in logs and the panel.
    warnings: List[str]
    #: Set when the value could not be parsed at all and the caller must not emit
    #: a `server` line. None on success.
    error_code: Optional[str]
    error_message: Optional[str]


def _classify_host(host: str) -> Optional[str]:
    """Return a rejection code for hosts that cannot be a management address."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        lowered = host.rstrip(".").lower()
        # `localhost` is loopback by name and is the single most likely wrong value
        # here — it is what both shipped defaults contain. Catching only the numeric
        # form would let the exact failure this module exists to prevent straight
        # through. RFC 6761 also reserves the whole `.localhost` tree.
        if lowered == "localhost" or lowered.endswith(".localhost"):
            return "loopback"
        return None if _HOSTNAME_RE.match(host) else "invalid_host"

    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "unspecified"
    # Includes 169.254.169.254, the cloud metadata endpoint.
    if ip.is_link_local:
        return "link_local"
    if ip.is_multicast:
        return "multicast"
    # NOTE: private (RFC1918) addresses fall through on purpose — see module docstring.
    return None


_REJECTION_PROSE = {
    "too_long": f"URL must be at most {MAX_URL_LENGTH} characters.",
    "whitespace": (
        "URL must not contain spaces or line breaks. A trailing space survives parsing "
        "and would be written into haproxy.cfg as part of the address."
    ),
    "no_scheme": (
        "URL must start with http:// or https://. Without a scheme the value cannot be "
        "parsed as an address and silently falls back to localhost, which on a HAProxy "
        "node means the node itself."
    ),
    "bad_scheme": "URL scheme must be http or https.",
    "userinfo": "URL must not contain credentials.",
    "has_path": (
        "Enter only the scheme, host and port — no path, query or fragment. The "
        "challenge path is appended by HAProxy."
    ),
    "bad_port": "Port must be a number between 1 and 65535.",
    "no_host": "URL must contain a host.",
    "invalid_host": "Host is not a valid IP address or hostname.",
    "loopback": (
        "Loopback addresses cannot work here. HAProxy resolves this address on the "
        "HAProxy node, so 127.0.0.1 means the node itself, not the management server. "
        "Use the management server's routable address."
    ),
    "unspecified": (
        "0.0.0.0 is a listen address, not a destination. Use the management server's "
        "routable address."
    ),
    "link_local": "Link-local addresses cannot be used as a management address.",
    "multicast": "Multicast addresses cannot be used as a management address.",
}


def validate_acme_backend_url(value: Optional[str]) -> Optional[str]:
    """Validate an operator-supplied URL at the write boundary.

    Returns the normalised value (stripped), or ``None`` for empty input, which
    legitimately means "inherit from the next level of the resolution chain".
    Raises :class:`AcmeBackendUrlError` otherwise.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise AcmeBackendUrlError("invalid_host", _REJECTION_PROSE["invalid_host"])

    stripped = value.strip()
    if not stripped:
        return None

    if len(stripped) > MAX_URL_LENGTH:
        raise AcmeBackendUrlError("too_long", _REJECTION_PROSE["too_long"])
    if any(c in _CONTROL_CHARS for c in stripped) or " " in stripped:
        raise AcmeBackendUrlError("whitespace", _REJECTION_PROSE["whitespace"])

    parsed = urlparse(stripped)

    if not parsed.scheme:
        raise AcmeBackendUrlError("no_scheme", _REJECTION_PROSE["no_scheme"])
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        # `10.0.0.5:8080` parses as scheme='10.0.0.5' with no netloc, and
        # `localhost:8080` as scheme='localhost'. Both are the same operator mistake,
        # so point at the missing scheme rather than the nonsense one.
        if not parsed.netloc:
            raise AcmeBackendUrlError("no_scheme", _REJECTION_PROSE["no_scheme"])
        raise AcmeBackendUrlError("bad_scheme", _REJECTION_PROSE["bad_scheme"])

    if parsed.username is not None or parsed.password is not None:
        raise AcmeBackendUrlError("userinfo", _REJECTION_PROSE["userinfo"])
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise AcmeBackendUrlError("has_path", _REJECTION_PROSE["has_path"])

    try:
        port = parsed.port
    except ValueError:
        # urlparse defers port parsing to attribute access; an out-of-range or
        # non-numeric port raises here. Unguarded, this exception reaches the config
        # generator's blanket `except` and collapses the cluster's whole config.
        raise AcmeBackendUrlError("bad_port", _REJECTION_PROSE["bad_port"]) from None
    if port is not None and not (1 <= port <= 65535):
        raise AcmeBackendUrlError("bad_port", _REJECTION_PROSE["bad_port"])

    host = parsed.hostname
    if not host:
        raise AcmeBackendUrlError("no_host", _REJECTION_PROSE["no_host"])

    code = _classify_host(host)
    if code is not None:
        raise AcmeBackendUrlError(code, _REJECTION_PROSE[code])

    return stripped


def resolve_acme_backend_target(url: Optional[str]) -> AcmeBackendTarget:
    """Resolve a stored URL into what the renderer emits. Never raises.

    Values already in the database predate validation (and the shipped defaults are
    themselves loopback), so anything unparseable or discouraged is reported through
    ``warnings`` / ``error_code`` rather than refused.
    """
    warnings: List[str] = []
    raw = (url or "").strip()

    if not raw:
        return AcmeBackendTarget(
            "", 0, "", warnings, "empty", "No challenge backend URL configured."
        )

    if any(c in _CONTROL_CHARS for c in raw) or " " in raw:
        # Must never reach haproxy.cfg: a newline here writes attacker- or
        # accident-chosen directives into a file pushed to every node.
        return AcmeBackendTarget(
            "", 0, "", warnings, "whitespace", _REJECTION_PROSE["whitespace"]
        )

    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()

    try:
        port = parsed.port
    except ValueError:
        return AcmeBackendTarget("", 0, "", warnings, "bad_port", _REJECTION_PROSE["bad_port"])

    host = parsed.hostname
    if not host or scheme not in ALLOWED_SCHEMES:
        return AcmeBackendTarget(
            "", 0, "", warnings, "no_scheme", _REJECTION_PROSE["no_scheme"]
        )

    if port is None:
        port = DEFAULT_HTTPS_PORT if scheme == "https" else DEFAULT_HTTP_PORT
        warnings.append(
            f"No port given, assuming {port}. State the port explicitly — the assumed "
            f"value is the bundled reverse proxy's port, not the scheme's default."
        )

    code = _classify_host(host)
    if code == "invalid_host":
        return AcmeBackendTarget("", 0, "", warnings, code, _REJECTION_PROSE[code])
    if code is not None:
        warnings.append(_REJECTION_PROSE[code])

    ssl_flag = " ssl verify none" if scheme == "https" else ""
    return AcmeBackendTarget(host, port, ssl_flag, warnings, None, None)
