"""
config.py — shared settings for all scanners.

Set via environment variables so you don't hard-code your target:

    export TARGET_URL="https://your-app.com"
    export TARGET_HOST="your-app.com"     # optional, derived from URL if blank
"""
import os
from urllib.parse import urlparse

TARGET_URL: str = os.getenv("TARGET_URL", "https://example.com").rstrip("/")

_env_host = os.getenv("TARGET_HOST", "").strip()

TIMEOUT: float = float(os.getenv("SCAN_TIMEOUT", "10"))
THREADS: int = int(os.getenv("SCAN_THREADS", "100"))
VERIFY_TLS: bool = os.getenv("VERIFY_TLS", "1") == "1"
USER_AGENT: str = os.getenv(
    "SCAN_UA", "AuthorizedSecurityAudit/1.0 (+contact: you@example.com)"
)
MAX_CRAWL_PAGES: int = int(os.getenv("MAX_CRAWL_PAGES", "25"))

# Safety switch: time-based SQLi payloads actually make the DB sleep.
ENABLE_TIME_BASED_SQLI: bool = os.getenv("ENABLE_TIME_SQLI", "0") == "1"


def target_host() -> str:
    """Return the hostname to scan (no scheme, no port)."""
    if _env_host:
        return _env_host
    return urlparse(TARGET_URL).hostname or ""


def target_port() -> int:
    """Return the explicit port from the URL, or 443/80 by default."""
    parsed = urlparse(TARGET_URL)
    if parsed.port:
        return parsed.port
    return 443 if parsed.scheme == "https" else 80


def verify_tls():
    """requests `verify` value."""
    return VERIFY_TLS