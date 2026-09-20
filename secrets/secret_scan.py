#!/usr/bin/env python3
"""
secrets/secret_scan.py

Scans a live website (and optionally a local repo) for leaked secrets:
API keys, tokens, private keys, JWTs, credentials in HTML/JS/source maps.

It will:
  * fetch the homepage, robots.txt, sitemap.xml, common config paths
  * follow <script src="..."> bundles and .map source maps
  * run a large regex ruleset + a Shannon-entropy heuristic
  * (optionally) walk a local directory

Usage
-----
    python -m secrets.secret_scan --url https://your-app.com
    python -m secrets.secret_scan --url https://your-app.com --local ./dist
    python -m secrets.secret_scan --url https://your-app.com --json secrets.json
"""
from __future__ import annotations

import argparse
import json
import math
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

# --------------------------------------------------------------------------
# Detection rules: (rule_id, description, regex, severity)
# --------------------------------------------------------------------------
RULES: list[tuple[str, str, re.Pattern, str]] = [
    ("aws-access-key", "AWS Access Key ID",
     re.compile(r"\b(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), "critical"),
    ("aws-secret-key", "AWS Secret Access Key (contextual)",
     re.compile(r"""(?i)aws.{0,20}?['"][0-9a-zA-Z/+]{40}['"]"""), "critical"),
    ("google-api-key", "Google API Key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("google-oauth", "Google OAuth Client Secret",
     re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b"), "high"),
    ("stripe-live-secret", "Stripe Live Secret Key",
     re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "critical"),
    ("stripe-test-secret", "Stripe Test Secret Key",
     re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b"), "medium"),
    ("stripe-restricted", "Stripe Restricted Key",
     re.compile(r"\brk_live_[0-9a-zA-Z]{24,}\b"), "critical"),
    ("github-token", "GitHub Token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "critical"),
    ("github-pat-fine", "GitHub Fine-grained PAT",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "critical"),
    ("gitlab-token", "GitLab Personal Access Token",
     re.compile(r"\bglpat-[A-Za-z0-9\-_]{20,}\b"), "critical"),
    ("slack-token", "Slack Token",
     re.compile(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,}\b"), "critical"),
    ("slack-webhook", "Slack Webhook URL",
     re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/+]{40,}"), "high"),
    ("twilio-key", "Twilio API Key",
     re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("sendgrid-key", "SendGrid API Key",
     re.compile(r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b"), "critical"),
    ("mailgun-key", "Mailgun API Key",
     re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "high"),
    ("mailchimp-key", "Mailchimp API Key",
     re.compile(r"\b[0-9a-f]{32}-us\d{1,2}\b"), "high"),
    ("heroku-key", "Heroku API Key",
     re.compile(r"""(?i)heroku.{0,20}?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"""),
     "high"),
    ("firebase-url", "Firebase Database URL",
     re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"), "medium"),
    ("firebase-server-key", "Firebase Cloud Messaging Server Key",
     re.compile(r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b"), "high"),
    ("openai-key", "OpenAI API Key",
     re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9\-_]{20,}\b"), "critical"),
    ("anthropic-key", "Anthropic API Key",
     re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b"), "critical"),
    ("private-key", "Private Key Block",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
     "critical"),
    ("jwt", "JSON Web Token",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "medium"),
    ("basic-auth-url", "Credentials Embedded in URL",
     re.compile(r"https?://[^/\s:@]{3,}:[^/\s:@]{3,}@[^\s/]+"), "critical"),
    ("generic-secret", "Generic Hard-coded Secret",
     re.compile(
         r"""(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|"""
         r"""auth[_-]?token|client[_-]?secret|private[_-]?key|passwd|password|"""
         r"""db[_-]?pass|bearer)['"]?\s*[:=]\s*['"]([^'"\s]{8,120})['"]"""
     ), "high"),
    ("npm-token", "npm Access Token",
     re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "critical"),
    ("pypi-token", "PyPI Upload Token",
     re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,}\b"), "critical"),
    ("digitalocean-token", "DigitalOcean Token",
     re.compile(r"\bdop_v1_[0-9a-f]{64}\b"), "critical"),
    ("shopify-token", "Shopify Access Token",
     re.compile(r"\bshpat_[0-9a-fA-F]{32}\b"), "critical"),
    ("discord-webhook", "Discord Webhook",
     re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9\-_]+"),
     "medium"),
]

# Files commonly left behind on web roots
PROBE_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/config.json",
    "/config.js",
    "/package.json",
    "/composer.json",
    "/.well-known/security.txt",
    "/api/config",
    "/debug",
    "/.DS_Store",
    "/backup.zip",
    "/.aws/credentials",
]

# Ignore-list: placeholder / example values that are not real leaks
FALSE_POSITIVES = re.compile(
    r"(?i)(your[_-]?api[_-]?key|example|placeholder|changeme|xxxx+|"
    r"<[^>]+>|\{\{[^}]+\}\}|process\.env|import\.meta\.env|"
    r"REPLACE_ME|TODO|dummy|test[_-]?key|0000000000)"
)

_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_\-]{24,}")
_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")


def shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


def _line_of(text: str, index: int) -> tuple[int, str]:
    """Return (line_number, trimmed_line) for a character offset."""
    line_no = text.count("\n", 0, index) + 1
    start = text.rfind("\n", 0, index) + 1
    end = text.find("\n", index)
    if end == -1:
        end = len(text)
    return line_no, text[start:end].strip()[:300]


def scan_text(text: str, source: str) -> list[dict]:
    """Run every rule + entropy check over a blob of text."""
    findings: list[dict] = []

    for rule_id, desc, pattern, severity in RULES:
        for match in pattern.finditer(text):
            value = match.group(0)
            if FALSE_POSITIVES.search(value):
                continue
            line_no, line = _line_of(text, match.start())
            findings.append({
                "rule": rule_id,
                "description": desc,
                "severity": severity,
                "source": source,
                "line": line_no,
                "match": value[:120],
                "context": line,
            })

    # Entropy heuristic — catches unknown-format keys
    for match in _ENTROPY_RE.finditer(text):
        token = match.group(0)
        if not set(token) <= _B64_CHARS:
            continue
        if len(set(token)) < 12:
            continue
        entropy = shannon_entropy(token)
        if entropy >= 4.3 and not FALSE_POSITIVES.search(token):
            line_no, line = _line_of(text, match.start())
            findings.append({
                "rule": "high-entropy-string",
                "description": "High-entropy string (possible unknown secret)",
                "severity": "low",
                "source": source,
                "line": line_no,
                "match": token[:120],
                "context": line,
                "entropy": round(entropy, 2),
            })

    return findings


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": config.USER_AGENT if config else "AuthorizedSecurityAudit/1.0",
        "Accept": "*/*",
    })
    return s


def fetch(session: requests.Session, url: str, timeout: float) -> str | None:
    """GET a URL and return the body as text, or None on failure."""
    try:
        verify = config.verify_tls() if config else True
        resp = session.get(url, timeout=timeout, verify=verify, allow_redirects=True)
        if resp.status_code >= 400:
            return None
        ctype = resp.headers.get("Content-Type", "")
        if not any(t in ctype for t in ("text", "json", "javascript", "xml", "html")):
            return None
        return resp.text
    except requests.RequestException:
        return None


def discover_assets(session: requests.Session, base_url: str, timeout: float) -> list[str]:
    """Find JS bundles, source maps, and inline script URLs on the homepage."""
    html = fetch(session, base_url, timeout)
    if not html:
        return []

    urls: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")

    for tag, attr in (("script", "src"), ("link", "href")):
        for node in soup.find_all(tag):
            val = node.get(attr)
            if val:
                urls.add(urljoin(base_url, val))

    # Source maps referenced by //# sourceMappingURL=
    for m in re.finditer(r"sourceMappingURL=([^\s*]+)", html):
        urls.add(urljoin(base_url, m.group(1).strip()))

    return sorted(urls)


def scan_remote(
    url: str, timeout: float = 10.0, max_assets: int = 40
) -> list[dict]:
    """Crawl a live site and scan everything for secrets."""
    session = _session()
    findings: list[dict] = []
    seen: set[str] = set()

    targets = [url] + [urljoin(url, p) for p in PROBE_PATHS]

    print(f"[*] Probing {len(targets)} known paths...", file=sys.stderr)
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        body = fetch(session, target, timeout)
        if body:
            print(f"    [+] {target}", file=sys.stderr)
            findings.extend(scan_text(body, target))

    print("[*] Discovering JS bundles & source maps...", file=sys.stderr)
    assets = discover_assets(session, url, timeout)[:max_assets]
    for asset in assets:
        if asset in seen:
            continue
        seen.add(asset)
        body = fetch(session, asset, timeout)
        if body:
            findings.extend(scan_text(body, asset))

    # De-duplicate
    unique, keys = [], set()
    for f in findings:
        key = (f["rule"], f["match"], f["source"])
        if key not in keys:
            keys.add(key)
            unique.append(f)

    return unique


def scan_local(root: str, max_bytes: int = 2_000_000) -> list[dict]:
    """Walk a local directory (your build output / repo) for secrets."""
    import os

    findings: list[dict] = []
    skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist_bak"}
    text_ext = {
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".env",
        ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".html", ".htm",
        ".xml", ".txt", ".md", ".py", ".rb", ".go", ".java", ".php", ".sh",
        ".properties", ".map",
    }

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for name in filenames:
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            if ext not in text_ext and not name.startswith(".env"):
                continue
            try:
                if os.path.getsize(path) > max_bytes:
                    continue
                with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except OSError:
                continue
            findings.extend(scan_text(content, path))

    return findings


def print_report(findings: list[dict]) -> None:
    if not findings:
        print("\n[+] No secrets detected.")
        return

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    print(f"\n[!] {len(findings)} potential secret(s) found:\n")
    for f in findings:
        print(f"  [{f['severity'].upper():<8}] {f['description']}")
        print(f"             source : {f['source']}")
        print(f"             line   : {f.get('line', '?')}")
        print(f"             match  : {f['match'][:100]}")
        print()


def main() -> int:
    ap = argparse.ArgumentParser(description="Secret / token scanner for web apps")
    ap.add_argument("--url", help="Base URL to scan")
    ap.add_argument("--local", help="Local directory to scan")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--json", metavar="FILE")
    args = ap.parse_args()

    if not args.url and not args.local:
        ap.error("provide at least one of --url or --local")

    findings: list[dict] = []

    if args.url:
        print(f"[*] Remote scan of {args.url}", file=sys.stderr)
        findings += scan_remote(args.url, args.timeout)

    if args.local:
        print(f"[*] Local scan of {args.local}", file=sys.stderr)
        findings += scan_local(args.local)

    print_report(findings)

    if args.json:
        report = {
            "scanner": "secret_scan",
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "url": args.url,
            "local": args.local,
            "finding_count": len(findings),
            "findings": findings,
        }
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[*] JSON report written to {args.json}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())