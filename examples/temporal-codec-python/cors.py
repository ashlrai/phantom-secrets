"""Opt-in, exact-origin CORS policy for the codec server sketch.

Default: no origins, so the server sends no CORS headers and a browser page
on another origin cannot read its responses. To let the Temporal Web UI call
it, list each origin exactly, for example:

    PHANTOM_TEMPORAL_CODEC_CORS_ORIGINS=http://localhost:8233

An origin is scheme, host and port only. Wildcards and patterns (`*`, `?`,
regex characters), paths, queries, fragments and user info are rejected at
startup. Matching compares (scheme, host, effective port) exactly.

Only what the Temporal codec protocol needs is allowed: POST to /encode and
/decode, the OPTIONS preflight, and the request headers Content-Type and
X-Namespace. Authorization is added only when the server is configured to
check it, matching Temporal's guidance that it belongs in the CORS
configuration when you enable codec server authorization.
"""

import re
from typing import FrozenSet, Iterable, Mapping, NamedTuple, Optional, Tuple
from urllib.parse import urlsplit

ORIGINS_ENV = "PHANTOM_TEMPORAL_CODEC_CORS_ORIGINS"
CODEC_PATHS = frozenset({"/encode", "/decode"})
ALLOWED_METHOD = "POST"
BASE_HEADERS = ("content-type", "x-namespace")
MAX_AGE_SECONDS = "600"

_DEFAULT_PORTS = {"http": 80, "https": 443}
_HOSTNAME = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
_IPV6 = re.compile(r"^\[[0-9a-f:.]+\]$")
_PATTERN_CHARS = set("*?^$[]{}()|\\+ ")


class CorsConfigError(ValueError):
    """The configured origin list is not a list of exact origins."""


Origin = Tuple[str, str, int]


def _parse_origin(text: str) -> Optional[Origin]:
    """Parse `scheme://host[:port]` exactly. Returns None if it is anything else."""
    if not text or any(c in _PATTERN_CHARS for c in text) or text != text.strip():
        return None
    try:
        parts = urlsplit(text)
        port = parts.port
    except ValueError:
        return None
    scheme = parts.scheme
    if scheme not in _DEFAULT_PORTS:
        return None
    # Exactly scheme://netloc: no path (not even "/"), query, fragment or user info.
    if text != f"{scheme}://{parts.netloc}" or "@" in parts.netloc:
        return None
    host = (parts.hostname or "").lower()
    if parts.netloc.startswith("["):
        host = f"[{host}]"
        if not _IPV6.match(host):
            return None
    elif not _HOSTNAME.match(host):
        return None
    return (scheme, host, port if port is not None else _DEFAULT_PORTS[scheme])


def parse_allowed_origins(value: Optional[str]) -> FrozenSet[Origin]:
    """Parse a comma-separated origin list. Empty or unset means none.

    Raises CorsConfigError on any entry that is not one exact origin.
    """
    if value is None or not value.strip():
        return frozenset()
    out = set()
    for raw in value.split(","):
        entry = raw.strip()
        if entry == "null":
            raise CorsConfigError("the 'null' origin cannot be allowed")
        parsed = _parse_origin(entry)
        if parsed is None:
            raise CorsConfigError(
                f"{ORIGINS_ENV} entries must be exact origins like https://host:port "
                "with no wildcard, pattern, path, query or user info"
            )
        out.add(parsed)
    return frozenset(out)


class CorsDecision(NamedTuple):
    allowed: bool
    headers: Tuple[Tuple[str, str], ...]


REFUSED = CorsDecision(False, ())


class CorsPolicy:
    def __init__(self, origins: Iterable[Origin] = (), allow_authorization: bool = False):
        self._origins = frozenset(origins)
        names = list(BASE_HEADERS) + (["authorization"] if allow_authorization else [])
        self._allowed_headers = frozenset(names)
        self._allow_headers_value = ", ".join(
            {"content-type": "Content-Type", "x-namespace": "X-Namespace", "authorization": "Authorization"}[n]
            for n in names
        )

    @classmethod
    def from_env(cls, environ: Mapping[str, str], allow_authorization: bool = False) -> "CorsPolicy":
        return cls(parse_allowed_origins(environ.get(ORIGINS_ENV)), allow_authorization)

    def origin_allowed(self, origin: Optional[str]) -> bool:
        if origin is None:
            return False
        parsed = _parse_origin(origin)
        return parsed is not None and parsed in self._origins

    def for_request(self, origin: Optional[str]) -> CorsDecision:
        """CORS headers for an actual POST. No Origin header: allowed, no headers."""
        if origin is None:
            return CorsDecision(True, ())
        if not self.origin_allowed(origin):
            return REFUSED
        return CorsDecision(True, (("Access-Control-Allow-Origin", origin), ("Vary", "Origin")))

    def for_preflight(
        self, path: str, origin: Optional[str], method: Optional[str], request_headers: Optional[str]
    ) -> CorsDecision:
        """Answer an OPTIONS preflight. Anything outside the protocol is refused."""
        if path not in CODEC_PATHS or not self.origin_allowed(origin):
            return REFUSED
        if (method or "").strip().upper() != ALLOWED_METHOD:
            return REFUSED
        requested = {h.strip().lower() for h in (request_headers or "").split(",") if h.strip()}
        if not requested <= self._allowed_headers:
            return REFUSED
        return CorsDecision(
            True,
            (
                ("Access-Control-Allow-Origin", origin),
                ("Access-Control-Allow-Methods", f"{ALLOWED_METHOD}, OPTIONS"),
                ("Access-Control-Allow-Headers", self._allow_headers_value),
                ("Access-Control-Max-Age", MAX_AGE_SECONDS),
                ("Vary", "Origin"),
            ),
        )
