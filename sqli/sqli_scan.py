#!/usr/bin/env python3
"""
sqli/sqli_scan.py

Non-destructive SQL-injection detector.

Techniques
----------
1. Error-based   — inject quote/backslash variants, grep the response for
                   database error signatures.
2. Boolean-based — send logically-true and logically-false payloads and
                   compare response length / similarity against the baseline.
3. Time-based    — (OFF by default, set ENABLE_TIME_SQLI=1) measures whether
                   the server actually sleeps.

It deliberately avoids destructive payloads (no DROP/INSERT/UPDATE/DELETE).

Usage
-----
    python -m sqli.sqli_scan --url https://your-app.com
    python -m sqli.sqli_scan --url https://your-app.com --crawl 15
    ENABLE_TIME_SQLI=1 python -m sqli.sqli_scan --url https://your-app.com
"""
from __future__ import annotations

import argparse
import difflib
import json
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup

try:
    import config
except ImportError:  # pragma: no cover
    config = None

# --------------------------------------------------------------------------
# Detection signatures
# --------------------------------------------------------------------------
ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "supplied argument is not a valid mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "microsoft ole db provider for sql server",
    "odbc sql server driver",
    "sqlserver jdbc driver",
    "system.data.sqlclient.sqlexception",
    "incorrect syntax near",
    "pg_query()",
    "pg_exec()",
    "postgresql query failed",
    "warning: pg_",
    "syntax error at or near",
    "sqlite3.operationalerror",
    "sqlite_error",
    "sqlite/jdbcdriver",
    "ora-01756",
    "ora-00933",
    "ora-00921",
    "oracle error",
    "quoted string not properly terminated",
    "sqlstate[",
    "pdoexception",
    "doctrine\\dbalfaxception",
    "org.hibernate.exception",
    "javax.persistence.persistenceexception",
    "column count doesn't match value count",
    "unknown column",
    "table doesn't exist",
    "no such table",
    "sql command not properly ended",
    "unterminated string literal",
]

# Error-triggering payloads (harmless — they only break the query)
ERROR_PAYLOADS = [
    "'",
    "\"",
    "')",
    "\")",
    "'--",
    "';",
    "\\",
    "' OR ''='",
    "1'",
]

# (true_payload, false_payload) — a difference in response implies injection
BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' OR '1'='1", "' OR '1'='2"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
    ("') AND ('1'='1", "') AND ('1'='2"),
]

# (payload_template, expected_delay_seconds)
TIME_PAYLOADS = [
    ("' AND SLEEP({d})-- -", 5),
    ("'; SELECT SLEEP({d})-- -", 5),
    ("' AND pg_sleep({d})-- -", 5),
    ("'; WAITFOR DELAY '0:0:{d}'-- -", 5),
    ("' AND {d}=DBMS_PIPE.RECEIVE_MESSAGE('a',{d})-- -", 5),
]

# Response bodies that indicate a WAF blocked us — not a vulnerability.
WAF_SIGNATURES = [
    "access denied",
    "request blocked",
    "web application firewall",
    "mod_security",
    "cloudflare",
    "incapsula",
    "sucuri",
    "forbidden",
    "captcha",
]

USER_AGENT = (
    config.USER_AGENT if config else "AuthorizedSecurityAudit/1.0"
)
TIMEOUT = config.TIMEOUT if config else 10.0
VERIFY = config.verify_tls() if config else True
ENABLE_TIME = config.ENABLE_TIME_BASED_SQLI if config else False


def _session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s


def _looks_like_waf(body: str) -> bool:
    low = body[:5000].lower()
    return any(sig in low for sig in WAF_SIGNATURES)


def _looks_like_sql_error(body: str) -> str | None:
    low = body.lower()
    for sig in ERROR_SIGNATURES:
        if sig in low:
            return sig
    return None


def _similarity(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def inject_query(url: str, param: str, payload: str) -> str:
    """Rebuild `url` with `param` set to `payload`."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def test_parameter(
    session: requests.Session,
    url: str,
    param: str,
    method: str = "GET",
    form_data: dict | None = None,
) -> list[dict]:
    """Run all non-destructive tests against a single parameter."""
    findings: list[dict] = []

    # ---- Baseline ---------------------------------------------------------
    try:
        if method.upper() == "POST":
            data = dict(form_data or {})
            data[param] = "1"
            baseline = session.post(url, data=data, timeout=TIMEOUT, verify=VERIFY)
        else:
            baseline = session.get(
                inject_query(url, param, "1"), timeout=TIMEOUT, verify=VERIFY
            )
    except requests.RequestException as exc:
        print(f"    [!] baseline failed for {param}: {exc}", file=sys.stderr)
        return findings

    baseline_body = baseline.text
    if _looks_like_waf(baseline_body):
        print(f"    [~] WAF/block page detected on {url} — skipping", file=sys.stderr)
        return findings

    # ---- 1. Error-based ---------------------------------------------------
    for payload in ERROR_PAYLOADS:
        try:
            if method.upper() == "POST":
                data = dict(form_data or {})
                data[param] = payload
                resp = session.post(url, data=data, timeout=TIMEOUT, verify=VERIFY)
            else:
                resp = session.get(
                    inject_query(url, param, payload), timeout=TIMEOUT, verify=VERIFY
                )
        except requests.RequestException:
            continue

        sig = _looks_like_sql_error(resp.text)
        if sig:
            findings.append({
                "type": "error-based",
                "confidence": "high",
                "url": url,
                "parameter": param,
                "method": method.upper(),
                "payload": payload,
                "evidence": f"DB error signature: '{sig}'",
                "status_code": resp.status_code,
            })
            break

    # ---- 2. Boolean-based -------------------------------------------------
    for true_payload, false_payload in BOOLEAN_PAIRS:
        try:
            if method.upper() == "POST":
                d1 = dict(form_data or {}); d1[param] = true_payload
                d2 = dict(form_data or {}); d2[param] = false_payload
                r_true = session.post(url, data=d1, timeout=TIMEOUT, verify=VERIFY)
                r_false = session.post(url, data=d2, timeout=TIMEOUT, verify=VERIFY)
            else:
                r_true = session.get(
                    inject_query(url, param, true_payload),
                    timeout=TIMEOUT, verify=VERIFY,
                )
                r_false = session.get(
                    inject_query(url, param, false_payload),
                    timeout=TIMEOUT, verify=VERIFY,
                )
        except requests.RequestException:
            continue

        sim_true = _similarity(baseline_body, r_true.text)
        sim_false = _similarity(baseline_body, r_false.text)
        diff_between = _similarity(r_true.text, r_false.text)

        # True payload behaves like baseline; false payload diverges.
        if sim_true > 0.95 and sim_false < 0.85 and diff_between < 0.85:
            findings.append({
                "type": "boolean-based",
                "confidence": "medium",
                "url": url,
                "parameter": param,
                "method": method.upper(),
                "payload": f"TRUE: {true_payload}  |  FALSE: {false_payload}",
                "evidence": (
                    f"similarity baseline/true={sim_true:.3f}, "
                    f"baseline/false={sim_false:.3f}, true/false={diff_between:.3f}"
                ),
                "status_code": r_true.status_code,
            })
            break

    # ---- 3. Time-based (opt-in) ------------------------------------------
    if ENABLE_TIME:
        try:
            t0 = time.perf_counter()
            session.get(inject_query(url, param, "1"), timeout=TIMEOUT, verify=VERIFY)
            baseline_time = time.perf_counter() - t0
        except requests.RequestException:
            baseline_time = 1.0

        for template, delay in TIME_PAYLOADS:
            payload = template.format(d=delay)
            try:
                t0 = time.perf_counter()
                resp = session.get(
                    inject_query(url, param, payload),
                    timeout=TIMEOUT + delay + 5,
                    verify=VERIFY,
                )
                elapsed = time.perf_counter() - t0
            except requests.RequestException:
                continue

            if elapsed > baseline_time + (delay * 0.8):
                findings.append({
                    "type": "time-based",
                    "confidence": "high",
                    "url": url,
                    "parameter": param,
                    "method": "GET",
                    "payload": payload,
                    "evidence": (
                        f"baseline={baseline_time:.2f}s, injected={elapsed:.2f}s "
                        f"(expected delay {delay}s)"
                    ),
                    "status_code": resp.status_code,
                })
                break

    return findings


def discover_targets(
    session: requests.Session, base_url: str, max_pages: int = 15
) -> tuple[list[tuple[str, str]], list[tuple[str, str, dict]]]:
    """Crawl the site. Returns (param_urls, forms)."""
    param_urls: set[tuple[str, str]] = set()
    forms: list[tuple[str, str, dict]] = []

    visited: set[str] = set()
    queue: list[str] = [base_url]
    host = urlparse(base_url).netloc

    while queue and len(visited) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = session.get(url, timeout=TIMEOUT, verify=VERIFY)
        except requests.RequestException:
            continue

        if "html" not in resp.headers.get("Content-Type", ""):
            continue

        # Query parameters
        parsed = urlparse(url)
        if parsed.query:
            for p in parse_qs(parsed.query):
                param_urls.add((urlunparse(parsed._replace(query="")), p))

        soup = BeautifulSoup(resp.text, "html.parser")

        # Links to crawl + their params
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            lp = urlparse(link)
            if lp.netloc != host:
                continue
            for p in parse_qs(lp.query):
                param_urls.add((urlunparse(lp._replace(query="")), p))
            if link not in visited and len(queue) < max_pages * 3:
                queue.append(link)

        # Forms
        for form in soup.find_all("form"):
            action = urljoin(url, form.get("action") or url)
            method = (form.get("method") or "GET").upper()
            data: dict[str, str] = {}
            for field in form.find_all(["input", "textarea", "select"]):
                name = field.get("name")
                if not name:
                    continue
                ftype = (field.get("type") or "text").lower()
                if ftype in ("submit", "button", "image", "file", "reset"):
                    continue
                if ftype == "checkbox":
                    continue
                data[name] = field.get("value") or "1"
            if data:
                forms.append((action, method, data))

    return sorted(param_urls), forms


def main() -> int:
    ap = argparse.ArgumentParser(description="Non-destructive SQL injection scanner")
    ap.add_argument("--url", required=True, help="Base URL of your app")
    ap.add_argument("--crawl", type=int, default=15, help="Max pages to crawl")
    ap.add_argument("--param", action="append", help="Force-test this param name")
    ap.add_argument("--json", metavar="FILE")
    args = ap.parse_args()

    session = _session()

    print(f"[*] Crawling {args.url} (max {args.crawl} pages)...", file=sys.stderr)
    param_urls, forms = discover_targets(session, args.url, args.crawl)

    print(f"[*] Found {len(param_urls)} URL param(s) and {len(forms)} form(s).\n",
          file=sys.stderr)

    findings: list[dict] = []

    if args.param:
        for p in args.param:
            print(f"[*] Testing forced param '{p}' on {args.url}", file=sys.stderr)
            findings += test_parameter(session, args.url, p)
    else:
        for url, param in param_urls:
            print(f"[*] Testing GET  {url}  ?{param}=", file=sys.stderr)
            findings += test_parameter(session, url, param, "GET")

        for action, method, data in forms:
            for param in data:
                print(f"[*] Testing {method:<4} {action}  ({param})", file=sys.stderr)
                findings += test_parameter(session, action, param, method, data)

    print()
    if not findings:
        print("[+] No SQL injection indicators found.")
    else:
        print(f"[!] {len(findings)} potential SQL injection issue(s):\n")
        for f in findings:
            print(f"  [{f['confidence'].upper()}] {f['type']}")
            print(f"     URL       : {f['url']}")
            print(f"     Parameter : {f['parameter']}  ({f['method']})")
            print(f"     Payload   : {f['payload']}")
            print(f"     Evidence  : {f['evidence']}")
            print()

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "scanner": "sqli_scan",
                "target": args.url,
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "time_based_enabled": ENABLE_TIME,
                "finding_count": len(findings),
                "findings": findings,
            }, fh, indent=2)
        print(f"[*] JSON report written to {args.json}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())