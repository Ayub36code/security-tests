#!/usr/bin/env python3
"""
headers/header_check.py

Checks HTTP security headers and TLS-ish basics on your deployed app.

Usage
-----
    python -m headers.header_check --url https://your-app.com
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

import requests

try:
    import config
except ImportError:  # pragma: no cover
    config = None

# header -> (severity_if_missing, recommended value, why it matters)
EXPECTED = {
    "Strict-Transport-Security": (
        "high",
        "max-age=31536000; includeSubDomains; preload",
        "Forces HTTPS, prevents SSL-strip downgrade attacks.",
    ),
    "Content-Security-Policy": (
        "high",
        "default-src 'self'; object-src 'none'; base-uri 'self'",
        "Mitigates XSS and data injection.",
    ),
    "X-Content-Type-Options": (
        "medium",
        "nosniff",
        "Stops MIME-type sniffing.",
    ),
    "X-Frame-Options": (
        "medium",
        "DENY",
        "Prevents clickjacking (superseded by CSP frame-ancestors).",
    ),
    "Referrer-Policy": (
        "medium",
        "strict-origin-when-cross-origin",
        "Prevents leaking URLs/tokens to third parties.",
    ),
    "Permissions-Policy": (
        "low",
        "geolocation=(), camera=(), microphone=()",
        "Restricts powerful browser features.",
    ),
    "Cross-Origin-Opener-Policy": (
        "low",
        "same-origin",
        "Isolates your browsing context.",
    ),
    "Cross-Origin-Resource-Policy": (
        "low",
        "same-origin",
        "Blocks cross-origin reads of your resources.",
    ),
    "X-XSS-Protection": (
        "info",
        "0",
        "Legacy header — set to 0 if you rely on CSP.",
    ),
}

# Headers that leak information
LEAKY = [
    "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Runtime", "X-Varnish",
]


def check(url: str, timeout: float) -> dict:
    result: dict = {"url": url, "missing": [], "present": {}, "leaky": [], "info": {}}

    try:
        resp = requests.get(
            url, timeout=timeout,
            verify=config.verify_tls() if config else True,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        result["error"] = str(exc)
        return result

    hdrs = {k.lower(): v for k, v in resp.headers.items()}
    result["status_code"] = resp.status_code
    result["final_url"] = resp.url

    for header, (sev, rec, why) in EXPECTED.items():
        if header.lower() in hdrs:
            result["present"][header] = hdrs[header.lower()]
        else:
            result["missing"].append({
                "header": header, "severity": sev,
                "recommended": rec, "why": why,
            })

    for header in LEAKY:
        if header.lower() in hdrs:
            result["leaky"].append({
                "header": header,
                "value": hdrs[header.lower()],
                "severity": "low",
                "issue": "Reveals server/framework details to attackers.",
            })

    # Redirect chain HTTP -> HTTPS
    result["info"]["https"] = resp.url.startswith("https://")
    if not result["info"]["https"]:
        result["missing"].append({
            "header": "HTTPS",
            "severity": "critical",
            "recommended": "Serve over TLS only",
            "why": "Traffic is plaintext and can be read/modified on the wire.",
        })

    # CORS wildcard with credentials
    acao = hdrs.get("access-control-allow-origin", "")
    acac = hdrs.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        result["missing"].append({
            "header": "CORS",
            "severity": "critical",
            "recommended": "Do not combine '*' with credentials",
            "why": "Any origin can read authenticated responses.",
        })
    elif acao == "*":
        result["present"]["Access-Control-Allow-Origin"] = "*"

    return result


def print_report(r: dict) -> None:
    print("=" * 72)
    print(f"SECURITY HEADER REPORT — {r['url']}")
    print("=" * 72)

    if r.get("error"):
        print(f"[!] Request failed: {r['error']}")
        return

    print(f"Status      : {r['status_code']}")
    print(f"Final URL   : {r['final_url']}\n")

    if r["missing"]:
        print("MISSING / WEAK:")
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for m in sorted(r["missing"], key=lambda x: order.get(x["severity"], 9)):
            print(f"  [{m['severity'].upper():<8}] {m['header']}")
            print(f"             set to   : {m['recommended']}")
            print(f"             why      : {m['why']}")
    else:
        print("[+] All expected security headers present.")

    if r["present"]:
        print("\nPRESENT:")
        for k, v in r["present"].items():
            print(f"  {k}: {v[:110]}")

    if r["leaky"]:
        print("\nINFORMATION DISCLOSURE:")
        for l in r["leaky"]:
            print(f"  [!] {l['header']}: {l['value']}")


def main() -> int:
    ap = argparse.ArgumentParser(description="HTTP security header checker")
    ap.add_argument("--url", required=True)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--json", metavar="FILE")
    args = ap.parse_args()

    result = check(args.url, args.timeout)
    print_report(result)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "scanner": "header_check",
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                **result,
            }, fh, indent=2)
        print(f"\n[*] JSON report written to {args.json}")

    return 1 if result.get("missing") else 0


if __name__ == "__main__":
    raise SystemExit(main())