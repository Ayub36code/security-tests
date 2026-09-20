#!/usr/bin/env python3
"""
endpoints/endpoint_scan.py

Enumerate EVERY reachable endpoint on the target, including admin panels.

What it does
------------
1. Crawls same-host links (breadth-first, up to `pages`)
2. Parses JS bundles for API path strings ("/api/v1/users" etc.)
3. Probes a built-in wordlist of admin / sensitive paths + any extra
   paths you supplied in the target JSON
4. Detects soft-404s by comparing each response against a baseline 404
5. Uses your auth (cookies/headers/bearer) so it can reach the
   authenticated parts of the app
6. Flags endpoints that:
     - are admin paths and return 200/302 WITHOUT auth   → auth bypass
     - return directory listings ("Index of /")
     - expose stack traces / debug info
     - return JSON with obvious secrets

Usage
-----
    python -m endpoints.endpoint_scan --target targets/myapp.json
    python -m endpoints.endpoint_scan --url https://app.com
"""
from __future__ import annotations

import argparse
import concurrent.futures
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


# Built-in admin / sensitive path wordlist (merged with target JSON's admin_paths)
BUILTIN_ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/dashboard", "/admin/users",
    "/admin/settings", "/admin/config", "/administrator", "/administrator/",
    "/wp-admin", "/wp-admin/", "/wp-login.php", "/wp-json/wp/v2/users",
    "/dashboard", "/manage", "/management", "/console", "/cpanel",
    "/phpmyadmin", "/pma", "/adminer.php", "/adminer",
    "/.env", "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/server-status", "/server-info",
    "/actuator", "/actuator/health", "/actuator/env", "/actuator/mappings",
    "/_debug", "/debug", "/debug/pprof",
    "/graphql", "/graphiql", "/api/graphql",
    "/swagger", "/swagger-ui.html", "/swagger-ui/", "/api-docs",
    "/openapi.json", "/v2/api-docs", "/v3/api-docs",
    "/metrics", "/health", "/healthz", "/status",
    "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/.well-known/security.txt",
    "/user", "/users", "/profile", "/me", "/account",
    "/api", "/api/v1", "/api/v2", "/api/users", "/api/admin",
    "/robots.txt", "/sitemap.xml",
]

API_PATH_RE = re.compile(r"""['"](\/(?:api|v\d+|graphql|rest|internal)\/[A-Za-z0-9_\-./{}$:]+)['"]""")
DEBUG_SIGNATURES = [
    "traceback (most recent call last)",
    "stack trace",
    "whitelabel error page",
    "whoops, looks like something went wrong",
    "laravel",
    "django debug",
    "werkzeug debugger",
    "symfony\\component",
]
DIR_LIST_RE = re.compile(r"<title>\s*Index of /", re.I)


def _session(auth: dict) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": config.USER_AGENT if config else "AuthorizedSecurityAudit/1.0",
        "Accept": "*/*",
    })
    s.cookies.update(auth.get("cookies") or {})
    s.headers.update(auth.get("headers") or {})
    if auth.get("bearer_token"):
        s.headers["Authorization"] = f"Bearer {auth['bearer_token']}"
    return s


def _classify(url: str, status: int, body: str, headers: dict,
              baseline_404_len: int | None, used_auth: bool) -> dict:
    """Return per-endpoint metadata; decides if it's interesting."""
    result = {
        "url": url,
        "status": status,
        "length": len(body),
        "content_type": headers.get("Content-Type", ""),
        "is_admin": False,
        "accessible_without_auth": False,
        "notes": [],
    }

    low_url = url.lower()
    result["is_admin"] = any(
        seg in low_url for seg in
        ("/admin", "/wp-admin", "/wp-login", "/manage", "/console",
         "/cpanel", "/phpmyadmin", "/dashboard", "/administrator")
    )

    # Auth-bypass heuristic
    if result["is_admin"] and not used_auth and status in (200, 204, 301, 302, 307, 308):
        result["accessible_without_auth"] = True
        result["notes"].append("Admin path reachable WITHOUT auth.")

    # Soft-404 detection (status 200 with 404-length body)
    if status == 200 and baseline_404_len and abs(len(body) - baseline_404_len) < 50:
        result["notes"].append("Looks like a soft-404 (matches baseline 404 length).")
        result["status"] = "soft-404"

    # Directory listing
    if DIR_LIST_RE.search(body[:2000]):
        result["notes"].append("Directory listing enabled.")

    # Debug page
    low_body = body[:4000].lower()
    for sig in DEBUG_SIGNATURES:
        if sig in low_body:
            result["notes"].append(f"Debug/stack info leaked ({sig}).")
            break

    # Interesting status codes
    if status in (401, 403):
        result["notes"].append(f"Protected ({status}) — exists but requires auth.")
    if status == 500:
        result["notes"].append("Server error — may leak internals.")

    return result


def _baseline_404(session: requests.Session, base: str, timeout: float) -> int | None:
    """Get the length of the site's 404 page so we can detect soft-404s."""
    probe = urljoin(base, "/__this_path_should_not_exist__" + str(id(base)))
    try:
        r = session.get(probe, timeout=timeout,
                        verify=config.verify_tls() if config else True,
                        allow_redirects=False)
        if r.status_code == 404:
            return len(r.text)
    except requests.RequestException:
        pass
    return None


def _probe_one(session: requests.Session, url: str, timeout: float,
               used_auth: bool, baseline_404_len: int | None) -> dict | None:
    try:
        r = session.get(url, timeout=timeout,
                        verify=config.verify_tls() if config else True,
                        allow_redirects=False)
    except requests.RequestException:
        return None

    info = _classify(url, r.status_code, r.text, r.headers, baseline_404_len, used_auth)
    return info


def _discover_from_js(session: requests.Session, base: str, timeout: float,
                      max_scripts: int = 20) -> set[str]:
    """Fetch JS bundles and pull API paths out of them."""
    paths: set[str] = set()
    try:
        r = session.get(base, timeout=timeout,
                        verify=config.verify_tls() if config else True)
    except requests.RequestException:
        return paths

    soup = BeautifulSoup(r.text, "html.parser")
    scripts = [urljoin(base, s["src"]) for s in soup.find_all("script", src=True)]

    for src in scripts[:max_scripts]:
        try:
            js = session.get(src, timeout=timeout,
                             verify=config.verify_tls() if config else True).text
        except requests.RequestException:
            continue
        for m in API_PATH_RE.findall(js):
            # Skip templated paths like /api/users/{id}
            if "{" in m or "$" in m:
                continue
            paths.add(m)
    return paths


def _crawl_links(session: requests.Session, base: str, max_pages: int,
                 timeout: float) -> set[str]:
    """Same-host BFS crawl."""
    seen_urls: set[str] = set()
    queue = [base]
    host = urlparse(base).netloc

    while queue and len(seen_urls) < max_pages:
        url = queue.pop(0)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        try:
            r = session.get(url, timeout=timeout,
                            verify=config.verify_tls() if config else True)
        except requests.RequestException:
            continue

        if "html" not in r.headers.get("Content-Type", ""):
            continue

        soup = BeautifulSoup(r.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"]).split("#")[0]
            if urlparse(link).netloc == host and link not in seen_urls:
                queue.append(link)
        for form in soup.find_all("form", action=True):
            action = urljoin(url, form["action"])
            if urlparse(action).netloc == host:
                seen_urls.add(action)

    return seen_urls


def scan(target: dict) -> dict:
    """Main entry point. `target` is a loaded target JSON."""
    name = target.get("name", "target")
    base = target["url"].rstrip("/")
    auth = target.get("auth") or {}
    opts = target.get("scan_options") or {}

    timeout = float(opts.get("timeout", config.TIMEOUT if config else 10))
    pages = int(opts.get("crawl_pages", 40))
    threads = int(opts.get("endpoint_threads", 40))

    used_auth = bool(auth.get("cookies") or auth.get("headers") or auth.get("bearer_token"))
    session = _session(auth)

    print(f"[*] Endpoint scan on {base}  (auth={'yes' if used_auth else 'no'})",
          file=sys.stderr)

    # 1. Baseline
    baseline_404_len = _baseline_404(session, base, timeout)
    print(f"    baseline 404 length: {baseline_404_len}", file=sys.stderr)

    # 2. Crawl
    print(f"    crawling up to {pages} pages...", file=sys.stderr)
    crawled = _crawl_links(session, base, pages, timeout)
    print(f"    found {len(crawled)} link(s)", file=sys.stderr)

    # 3. JS-derived API paths
    print("    mining JS bundles for API paths...", file=sys.stderr)
    api_paths = _discover_from_js(session, base, timeout)
    print(f"    found {len(api_paths)} API path(s)", file=sys.stderr)

    # 4. Wordlist
    wordlist = list(BUILTIN_ADMIN_PATHS) + list(target.get("admin_paths") or [])
    wordlist_urls = {urljoin(base, p) for p in wordlist}

    # 5. Union
    all_urls = crawled | {urljoin(base, p) for p in api_paths} | wordlist_urls
    print(f"    probing {len(all_urls)} URL(s) with {threads} threads...",
          file=sys.stderr)

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = [
            pool.submit(_probe_one, session, u, timeout, used_auth, baseline_404_len)
            for u in all_urls
        ]
        for fut in concurrent.futures.as_completed(futures):
            r = fut.result()
            if r:
                results.append(r)

    # Sort: interesting first, then by URL
    def score(r):
        return (
            0 if r["accessible_without_auth"] else
            1 if r["notes"] else
            2
        )

    results.sort(key=lambda r: (score(r), r["url"]))

    interesting = [r for r in results if r["notes"] or r["is_admin"]]

    print(f"\n[*] {len(results)} endpoint(s) responded, "
          f"{len(interesting)} interesting:", file=sys.stderr)
    for r in interesting[:50]:
        flag = "ADMIN" if r["is_admin"] else "     "
        pub = " <-- PUBLIC" if r["accessible_without_auth"] else ""
        note = f"  ({'; '.join(r['notes'])})" if r["notes"] else ""
        print(f"    {str(r['status']):>5} [{flag}] {r['url']}{pub}{note}",
              file=sys.stderr)

    return {
        "scanner": "endpoint_scan",
        "target": name,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "auth_used": used_auth,
        "total_probed": len(all_urls),
        "total_responded": len(results),
        "interesting": interesting,
        "all_results": results,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Full endpoint + admin enumeration")
    ap.add_argument("--target", help="Path to target JSON")
    ap.add_argument("--url", help="Or just a URL (no auth, defaults)")
    ap.add_argument("--pages", type=int, default=40)
    ap.add_argument("--json", metavar="FILE")
    args = ap.parse_args()

    if args.target:
        with open(args.target, "r", encoding="utf-8") as fh:
            target = json.load(fh)
    elif args.url:
        target = {"name": urlparse(args.url).netloc, "url": args.url}
    else:
        ap.error("provide --target or --url")

    target.setdefault("scan_options", {})["crawl_pages"] = args.pages

    report = scan(target)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)
        print(f"\n[*] JSON report written to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())