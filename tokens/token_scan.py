#!/usr/bin/env python3
"""
tokens/token_scan.py

Token / session security checks:

  * Finds JWTs in HTML, JS bundles, cookies and URLs
  * Decodes header + payload and flags weak config
        - alg: none
        - alg: HS256 with a brute-forceable secret (small built-in wordlist)
        - missing / expired `exp`
        - missing `iss` / `aud`
        - sensitive data inside the payload (password, email, ssn, ...)
  * Audits cookie flags (Secure, HttpOnly, SameSite, Domain, Path)
  * Flags tokens leaked in URLs / Referer-able locations
  * Flags tokens stored in localStorage / sessionStorage

Usage
-----
    python -m tokens.token_scan --url https://your-app.com
    python -m tokens.token_scan --url https://your-app.com --jwt <token>
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

try:
    import config
except ImportError:  # pragma: no cover
    config = None

JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{0,}"
)

# Tiny wordlist for HS256 secret cracking. Extend for real audits.
WEAK_SECRETS = [
    "secret", "secretkey", "secret_key", "password", "123456", "12345678",
    "changeme", "jwt", "jwtsecret", "jwt_secret", "mysecret", "test",
    "dev", "development", "production", "admin", "key", "private",
    "supersecret", "topsecret", "your-256-bit-secret", "your_jwt_secret",
    "default", "root", "qwerty", "letmein", "token", "auth",
    "shhhh", "supersecretkey", "s3cr3t", "s3cret", "jwtkey", "app_secret",
]

SENSITIVE_CLAIMS = [
    "password", "passwd", "pwd", "secret", "ssn", "social_security",
    "credit_card", "card_number", "cvv", "api_key", "apikey",
    "private_key", "pin", "dob", "bank_account",
]


# --------------------------------------------------------------------------
# JWT helpers
# --------------------------------------------------------------------------
def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def decode_jwt(token: str) -> dict | None:
    """Decode a JWT without verifying. Returns {'header', 'payload', 'signature'}."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except (ValueError, json.JSONDecodeError):
        return None
    return {"header": header, "payload": payload, "signature": parts[2]}


def crack_hs256(token: str, wordlist: list[str]) -> str | None:
    """Try to brute-force an HS256 signature. Returns the secret or None."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    try:
        target = _b64url_decode(parts[2])
    except Exception:
        return None

    for candidate in wordlist:
        digest = hmac.new(
            candidate.encode(), signing_input, hashlib.sha256
        ).digest()
        if hmac.compare_digest(digest, target):
            return candidate
    return None


def analyze_jwt(token: str, source: str) -> dict:
    """Static + dynamic analysis of a single JWT."""
    result: dict = {
        "token_preview": token[:40] + "..." if len(token) > 40 else token,
        "source": source,
        "issues": [],
    }

    decoded = decode_jwt(token)
    if not decoded:
        result["issues"].append({"severity": "info", "issue": "Not a valid JWT"})
        return result

    header, payload = decoded["header"], decoded["payload"]
    result["header"] = header
    result["payload"] = payload

    alg = str(header.get("alg", "")).lower()

    # --- alg: none ---
    if alg == "none":
        result["issues"].append({
            "severity": "critical",
            "issue": "alg is 'none' — signature is not verified. Anyone can forge tokens.",
        })

    # --- weak HS256 secret ---
    elif alg == "hs256":
        found = crack_hs256(token, WEAK_SECRETS)
        if found:
            result["issues"].append({
                "severity": "critical",
                "issue": f"HS256 secret cracked with built-in wordlist: '{found}'",
                "secret": found,
            })
        else:
            result["issues"].append({
                "severity": "info",
                "issue": "HS256 signature not in the built-in weak-secret wordlist "
                         "(does NOT mean it is strong — test with a real wordlist).",
            })

    # --- alg confusion / deprecated algs ---
    elif alg in ("hs384", "hs512", "rs256", "rs384", "rs512", "es256", "ps256"):
        pass  # fine, but see algorithm-confusion note below
    elif alg:
        result["issues"].append({
            "severity": "medium",
            "issue": f"Unusual signing algorithm: '{header.get('alg')}'",
        })

    if header.get("alg", "").upper() == "RS256":
        result["issues"].append({
            "severity": "low",
            "issue": "RS256 in use — verify the server rejects alg=HS256 signed "
                     "with the public key (algorithm-confusion attack).",
        })

    # --- exp / nbf / iat ---
    now = datetime.now(timezone.utc).timestamp()

    if "exp" not in payload:
        result["issues"].append({
            "severity": "medium",
            "issue": "No 'exp' claim — the token never expires.",
        })
    else:
        exp = payload["exp"]
        try:
            exp_f = float(exp)
            lifetime = exp_f - float(payload.get("iat", exp_f))
            if exp_f < now:
                result["issues"].append({
                    "severity": "low",
                    "issue": f"Token already expired ({datetime.fromtimestamp(exp_f, timezone.utc).isoformat()}).",
                })
            if lifetime > 60 * 60 * 24 * 7:
                result["issues"].append({
                    "severity": "medium",
                    "issue": f"Very long token lifetime: {lifetime / 86400:.1f} days.",
                })
        except (TypeError, ValueError):
            result["issues"].append({
                "severity": "low",
                "issue": "Non-numeric 'exp' claim.",
            })

    if "iss" not in payload:
        result["issues"].append({
            "severity": "low", "issue": "Missing 'iss' (issuer) claim.",
        })
    if "aud" not in payload:
        result["issues"].append({
            "severity": "low", "issue": "Missing 'aud' (audience) claim.",
        })

    # --- sensitive data in payload ---
    def walk(obj, path=""):
        if isinstance(obj, dict):
            for k, v in obj.items():
                yield from walk(v, f"{path}.{k}" if path else k)
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                yield from walk(v, f"{path}[{i}]")
        else:
            yield path, obj

    for key, value in walk(payload):
        low_key = str(key).lower()
        if any(s in low_key for s in SENSITIVE_CLAIMS):
            result["issues"].append({
                "severity": "high",
                "issue": f"Sensitive claim in payload: '{key}' = {str(value)[:60]}",
            })

    # --- JWT in URL ---
    if source.startswith("url:"):
        result["issues"].append({
            "severity": "high",
            "issue": "Token transmitted in a URL — leaks via logs, Referer header, "
                     "browser history and proxies.",
        })

    return result


# --------------------------------------------------------------------------
# Cookie audit
# --------------------------------------------------------------------------
def audit_cookies(resp: requests.Response) -> list[dict]:
    issues: list[dict] = []
    for cookie in resp.cookies:
        flags = {
            "name": cookie.name,
            "secure": bool(cookie.secure),
            "httponly": bool(cookie.has_nonstandard_attr("HttpOnly")
                              or cookie._rest.get("HttpOnly")),
            "samesite": cookie._rest.get("SameSite", "Not set"),
            "domain": cookie.domain,
            "path": cookie.path,
            "expires": cookie.expires,
        }
        # requests exposes HttpOnly via _rest only for some cases;
        # fall back to raw Set-Cookie header parsing.
        raw = resp.headers.get("Set-Cookie", "")
        if "httponly" in raw.lower():
            flags["httponly"] = True

        cookie_issues = []
        if not flags["secure"]:
            cookie_issues.append("Missing Secure flag — can be sent over plain HTTP.")
        if not flags["httponly"]:
            cookie_issues.append("Missing HttpOnly flag — readable by JavaScript (XSS → session theft).")
        if str(flags["samesite"]).lower() in ("not set", "none", ""):
            cookie_issues.append("SameSite not set to Lax/Strict — CSRF risk.")

        issues.append({"cookie": flags, "issues": cookie_issues})
    return issues


# --------------------------------------------------------------------------
# Crawl & scan
# --------------------------------------------------------------------------
def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": config.USER_AGENT if config else "AuthorizedSecurityAudit/1.0",
    })
    return s


def scan_page(session: requests.Session, url: str, timeout: float) -> dict:
    """Fetch a page and collect JWTs, cookies and storage usage."""
    out: dict = {
        "url": url,
        "jwt_findings": [],
        "cookies": [],
        "storage_hits": [],
        "url_token_hits": [],
    }

    try:
        resp = session.get(url, timeout=timeout, verify=config.verify_tls() if config else True)
    except requests.RequestException as exc:
        print(f"  [!] {url}: {exc}", file=sys.stderr)
        return out

    body = resp.text
    out["cookies"] = audit_cookies(resp)

    # --- JWTs in body / scripts ---
    for m in set(JWT_RE.findall(body)):
        out["jwt_findings"].append(analyze_jwt(m, f"body:{url}"))

    # --- JWTs in URLs on the page ---
    soup = BeautifulSoup(body, "html.parser")
    for tag, attr in (("a", "href"), ("script", "src"), ("link", "href"),
                      ("img", "src"), ("form", "action")):
        for node in soup.find_all(tag):
            val = node.get(attr) or ""
            if "token=" in val.lower() or "jwt=" in val.lower() or "access_token" in val.lower():
                out["url_token_hits"].append(urljoin(url, val))

    # --- Tokens shoved into localStorage/sessionStorage ---
    storage_patterns = [
        r"localStorage\.setItem\(\s*['\"]([^'\"]+)['\"]",
        r"sessionStorage\.setItem\(\s*['\"]([^'\"]+)['\"]",
        r"localStorage\.([A-Za-z_$][\w$]*)\s*=",
    ]
    for pat in storage_patterns:
        for key in re.findall(pat, body):
            if any(k in key.lower() for k in ("token", "jwt", "auth", "session", "key")):
                out["storage_hits"].append(key)

    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="JWT / token / cookie security scanner")
    ap.add_argument("--url", required=True, help="Base URL")
    ap.add_argument("--jwt", action="append", default=[],
                    help="Analyze a specific JWT (repeatable)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--pages", type=int, default=10, help="Max pages to crawl")
    ap.add_argument("--json", metavar="FILE")
    args = ap.parse_args()

    session = _session()
    results: list[dict] = []

    # Explicit tokens passed on the CLI
    for token in args.jwt:
        results.append({"url": "(cli)", "jwt_findings": [analyze_jwt(token, "cli")],
                        "cookies": [], "storage_hits": [], "url_token_hits": []})

    # Crawl
    base = args.url.rstrip("/")
    queue = [base]
    visited: set[str] = set()
    host = urlparse(base).netloc

    print(f"[*] Crawling {base} ...", file=sys.stderr)
    while queue and len(visited) < args.pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        print(f"  -> {url}", file=sys.stderr)
        page = scan_page(session, url, args.timeout)
        results.append(page)

        # Follow same-host links
        try:
            resp = session.get(
                url, timeout=args.timeout,
                verify=config.verify_tls() if config else True,
            )
            soup = BeautifulSoup(resp.text, "html.parser")
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"]).split("#")[0]
                if urlparse(link).netloc == host and link not in visited:
                    queue.append(link)
        except requests.RequestException:
            pass

    # ------------------------------------------------------------------
    # Report
    # ------------------------------------------------------------------
    print("\n" + "=" * 72)
    print("TOKEN & SESSION SECURITY REPORT")
    print("=" * 72)

    total_issues = 0

    for page in results:
        if page["jwt_findings"]:
            print(f"\n--- JWTs on {page['url']} ---")
            for jwt_res in page["jwt_findings"]:
                total_issues += len(jwt_res["issues"])
                print(f"\n  Token: {jwt_res['token_preview']}")
                print(f"  Header : {jwt_res.get('header')}")
                print(f"  Payload: {str(jwt_res.get('payload'))[:200]}")
                for issue in jwt_res["issues"]:
                    print(f"    [{issue['severity'].upper():<8}] {issue['issue']}")

        if page["cookies"]:
            print(f"\n--- Cookies on {page['url']} ---")
            for entry in page["cookies"]:
                total_issues += len(entry["issues"])
                print(f"\n  {entry['cookie']['name']}")
                print(f"    Secure={entry['cookie']['secure']}  "
                      f"HttpOnly={entry['cookie']['httponly']}  "
                      f"SameSite={entry['cookie']['samesite']}")
                for issue in entry["issues"]:
                    print(f"    [!] {issue}")

        if page["url_token_hits"]:
            total_issues += len(page["url_token_hits"])
            print(f"\n--- Tokens in URLs on {page['url']} ---")
            for hit in page["url_token_hits"]:
                print(f"    [!] {hit}")

        if page["storage_hits"]:
            total_issues += len(page["storage_hits"])
            print(f"\n--- Auth-ish keys written to Web Storage on {page['url']} ---")
            for key in set(page["storage_hits"]):
                print(f"    [!] {key}")

    if total_issues == 0:
        print("\n[+] No token/session issues detected.")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "scanner": "token_scan",
                "target": args.url,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "pages": results,
            }, fh, indent=2)
        print(f"\n[*] JSON report written to {args.json}")

    return 1 if total_issues else 0


if __name__ == "__main__":
    raise SystemExit(main())