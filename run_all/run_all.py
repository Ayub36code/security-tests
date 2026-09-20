#!/usr/bin/env python3
"""
run_all.py — orchestrator driven by a target JSON.

Pipeline
--------
1. Load target JSON (targets/<name>.json)
2. Run every scanner (ports, secrets, sqli, tokens, headers, endpoints)
3. Save individual + combined reports to reports/<timestamp>_<name>/
4. Merge new findings into data/registry.json
5. Print the FULL persistent registry every run (so nothing is forgotten)

Usage
-----
    python run_all.py --target targets/myapp.json
    python run_all.py --target targets/myapp.json --skip sqli
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

import config
import registry

from portscan.portscan import scan_ports, parse_ports, COMMON_PORTS
from secrets.secret_scan import scan_remote as scan_secrets
from sqli.sqli_scan import _session as sqli_session, discover_targets, test_parameter
from tokens.token_scan import scan_page as token_scan_page
from headers.header_check import check as check_headers
from endpoints.endpoint_scan import scan as scan_endpoints

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


BANNER = r"""
 ___  ___  ___  ___  ___  ___  ___  ___
|  _|| __|| __||  _||  _|| __|| __||  _|
|___||___||___||___||___||___||___||___|
     Authorized Security Self-Audit
"""


def _short(s: str, n: int = 120) -> str:
    return s if len(s) <= n else s[: n - 1] + "…"


# --------------------------------------------------------------------------
# Module wrappers — each returns (summary_dict, findings_for_registry)
# --------------------------------------------------------------------------
def run_portscan(target: dict) -> tuple[dict, list]:
    print("\n" + "=" * 72)
    print("1/6  PORT SCAN")
    print("=" * 72)
    opts = target.get("scan_options") or {}
    port_spec = opts.get("ports") or ",".join(str(p) for p in sorted(COMMON_PORTS))
    ports = parse_ports(port_spec)
    report = scan_ports(target["host"], ports, config.THREADS, config.TIMEOUT, True)
    return report, []  # ports don't go into registry (they change per scan)


def run_secrets(target: dict) -> tuple[dict, list]:
    print("\n" + "=" * 72)
    print("2/6  SECRET / TOKEN LEAK SCAN")
    print("=" * 72)
    findings = scan_secrets(target["url"], config.TIMEOUT)
    for f in findings:
        print(f"  [{f['severity'].upper():<8}] {_short(f['description'], 40):<40} "
              f"{f['source']}")
    return {"finding_count": len(findings), "findings": findings}, findings


def run_sqli(target: dict) -> tuple[dict, list]:
    print("\n" + "=" * 72)
    print("3/6  SQL INJECTION SCAN")
    print("=" * 72)
    opts = target.get("scan_options") or {}
    crawl = int(opts.get("crawl_pages", config.MAX_CRAWL_PAGES))
    session = sqli_session()
    # apply auth
    auth = target.get("auth") or {}
    session.cookies.update(auth.get("cookies") or {})
    session.headers.update(auth.get("headers") or {})
    if auth.get("bearer_token"):
        session.headers["Authorization"] = f"Bearer {auth['bearer_token']}"

    param_urls, forms = discover_targets(session, target["url"], crawl)
    findings: list[dict] = []
    for u, p in param_urls:
        findings += test_parameter(session, u, p, "GET")
    for action, method, data in forms:
        for p in data:
            findings += test_parameter(session, action, p, method, data)

    for f in findings:
        print(f"  [{f['confidence'].upper()}] {f['type']} — "
              f"{f['parameter']} @ {f['url']}")
    return {"finding_count": len(findings), "findings": findings}, findings


def run_tokens(target: dict) -> tuple[dict, list]:
    print("\n" + "=" * 72)
    print("4/6  TOKEN & COOKIE SCAN")
    print("=" * 72)
    from tokens.token_scan import _session as tok_session
    session = tok_session()
    auth = target.get("auth") or {}
    session.cookies.update(auth.get("cookies") or {})
    session.headers.update(auth.get("headers") or {})
    if auth.get("bearer_token"):
        session.headers["Authorization"] = f"Bearer {auth['bearer_token']}"

    page = token_scan_page(session, target["url"], config.TIMEOUT)

    token_items: list[dict] = []
    for jwt_res in page["jwt_findings"]:
        print(f"  JWT {jwt_res['token_preview']}")
        for issue in jwt_res["issues"]:
            print(f"     [{issue['severity'].upper():<8}] {issue['issue']}")
        token_items.append({
            "token_preview": jwt_res["token_preview"],
            "source": jwt_res["source"],
            "issues": jwt_res["issues"],
        })

    for c in page["cookies"]:
        if c["issues"]:
            print(f"  Cookie {c['cookie']['name']}: {'; '.join(c['issues'])}")

    print(f"\n  JWTs: {len(page['jwt_findings'])}  "
          f"Cookies: {len(page['cookies'])}  "
          f"Storage hits: {len(page['storage_hits'])}")

    return page, token_items


def run_headers(target: dict) -> tuple[dict, list]:
    print("\n" + "=" * 72)
    print("5/6  SECURITY HEADERS")
    print("=" * 72)
    result = check_headers(target["url"], config.TIMEOUT)
    for m in result.get("missing", []):
        print(f"  [{m['severity'].upper():<8}] missing {m['header']}")
    return result, []


def run_endpoints(target: dict) -> tuple[dict, list]:
    print("\n" + "=" * 72)
    print("6/6  FULL ENDPOINT / ADMIN ENUMERATION")
    print("=" * 72)
    report = scan_endpoints(target)

    endpoint_items = []
    for r in report["interesting"]:
        endpoint_items.append({
            "url": r["url"],
            "status": r["status"],
            "is_admin": r["is_admin"],
            "accessible_without_auth": r["accessible_without_auth"],
            "notes": r["notes"],
        })
    return report, endpoint_items


# --------------------------------------------------------------------------
# Report writing
# --------------------------------------------------------------------------
def write_reports(target: dict, modules: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
    name = target.get("name", "target")
    folder = os.path.join(REPORTS_DIR, f"{ts}_{name}")
    os.makedirs(folder, exist_ok=True)

    for mod, data in modules.items():
        with open(os.path.join(folder, f"{mod}.json"), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)

    # Human-readable summary
    lines: list[str] = [
        f"# Security Audit — {name}",
        "",
        f"- Target URL : {target['url']}",
        f"- Target host: {target['host']}",
        f"- Scanned at : {datetime.now(timezone.utc).isoformat()}",
        "",
    ]

    lines += ["## Summary", ""]
    for mod, data in modules.items():
        if mod == "secrets":
            lines.append(f"- Secrets found: **{data.get('finding_count', 0)}**")
        elif mod == "sqli":
            lines.append(f"- SQL injection indicators: **{data.get('finding_count', 0)}**")
        elif mod == "tokens":
            lines.append(f"- JWTs found: **{len(data.get('jwt_findings', []))}**")
        elif mod == "headers":
            lines.append(f"- Missing security headers: **{len(data.get('missing', []))}**")
        elif mod == "portscan":
            lines.append(f"- Open ports: **{len(data.get('open_ports', []))}**")
        elif mod == "endpoints":
            lines.append(f"- Endpoints probed: **{data.get('total_probed', 0)}**, "
                         f"interesting: **{len(data.get('interesting', []))}**")
    lines.append("")

    # Repeat the secrets + tokens here so the summary alone is useful
    if "secrets" in modules:
        lines += ["## Secrets / Tokens Found", ""]
        findings = modules["secrets"].get("findings", [])
        if not findings:
            lines.append("_None._")
        else:
            for f in findings:
                lines.append(f"- **[{f['severity'].upper()}]** {f['description']}")
                lines.append(f"  - source : `{f['source']}`")
                lines.append(f"  - match  : `{_short(f['match'], 100)}`")
        lines.append("")

    if "tokens" in modules:
        lines += ["## JWTs Found", ""]
        jwts = modules["tokens"].get("jwt_findings", [])
        if not jwts:
            lines.append("_None._")
        for j in jwts:
            lines.append(f"- `{j['token_preview']}`")
            for i in j["issues"]:
                lines.append(f"  - [{i['severity'].upper()}] {i['issue']}")
        lines.append("")

    if "endpoints" in modules:
        lines += ["## Interesting Endpoints", ""]
        for e in modules["endpoints"].get("interesting", []):
            flag = " `[ADMIN]`" if e["is_admin"] else ""
            pub = " **PUBLIC**" if e["accessible_without_auth"] else ""
            lines.append(f"- `{e['status']}` {e['url']}{flag}{pub}")
            for n in e["notes"]:
                lines.append(f"  - {n}")
        lines.append("")

    with open(os.path.join(folder, "summary.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    return folder


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="Full security audit")
    ap.add_argument("--target", required=True, help="Path to targets/<name>.json")
    ap.add_argument(
        "--skip", default="",
        help="Comma list: portscan,secrets,sqli,tokens,headers,endpoints",
    )
    ap.add_argument("--yes", action="store_true", help="Skip authorization prompt")
    args = ap.parse_args()

    with open(args.target, "r", encoding="utf-8") as fh:
        target = json.load(fh)

    target.setdefault("host", (target["url"].replace("https://", "")
                                .replace("http://", "").split("/")[0]))
    target.setdefault("name", target["host"])

    # Apply TLS verify from target config
    opts = target.get("scan_options") or {}
    if "verify_tls" in opts:
        os.environ["VERIFY_TLS"] = "1" if opts["verify_tls"] else "0"

    print(BANNER)
    print(f"Target     : {target['name']}")
    print(f"URL        : {target['url']}")
    print(f"Host       : {target['host']}")
    print(f"Auth       : {'yes' if target.get('auth') else 'no'}")

    if not args.yes:
        print("\n[!] Active scanning sends real requests to the target.")
        print("[!] Only proceed if you OWN this system or have WRITTEN permission.")
        if input("Type 'yes' to continue: ").strip().lower() != "yes":
            print("Aborted.")
            return 2

    skip = {s.strip().lower() for s in args.skip.split(",") if s.strip()}
    modules: dict = {}

    # 1..6
    secret_items: list[dict] = []
    token_items: list[dict] = []
    endpoint_items: list[dict] = []

    if "portscan" not in skip:
        modules["portscan"], _ = run_portscan(target)
    if "secrets" not in skip:
        modules["secrets"], secret_items = run_secrets(target)
    if "sqli" not in skip:
        modules["sqli"], _ = run_sqli(target)
    if "tokens" not in skip:
        modules["tokens"], token_items = run_tokens(target)
    if "headers" not in skip:
        modules["headers"], _ = run_headers(target)
    if "endpoints" not in skip:
        modules["endpoints"], endpoint_items = run_endpoints(target)

    # Persist into reports/
    folder = write_reports(target, modules)
    print(f"\n[*] Reports written to {folder}")

    # Persist into registry
    if secret_items:
        delta = registry.record(target["name"], "secrets", secret_items)
        if delta["new"]:
            print(f"[+] {len(delta['new'])} NEW secret(s) added to registry.")
    if token_items:
        delta = registry.record(target["name"], "tokens", token_items)
        if delta["new"]:
            print(f"[+] {len(delta['new'])} NEW token(s) added to registry.")
    if endpoint_items:
        delta = registry.record(target["name"], "endpoints", endpoint_items)
        if delta["new"]:
            print(f"[+] {len(delta['new'])} NEW endpoint(s) added to registry.")

    # ALWAYS re-print the entire known state for this target
    registry.print_known(target["name"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())