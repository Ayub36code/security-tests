"""
registry.py — persistent store of everything we've ever found.
Location: data/registry.json
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone

REGISTRY_PATH = os.path.join(os.path.dirname(__file__), "data", "registry.json")


def _empty() -> dict:
    return {"targets": {}}


def load() -> dict:
    if not os.path.exists(REGISTRY_PATH):
        return _empty()
    try:
        with open(REGISTRY_PATH, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return _empty()


def save(reg: dict) -> None:
    os.makedirs(os.path.dirname(REGISTRY_PATH), exist_ok=True)
    with open(REGISTRY_PATH, "w", encoding="utf-8") as fh:
        json.dump(reg, fh, indent=2, default=str)


def _key_for(kind: str, item: dict) -> str:
    if kind == "secrets":
        return "|".join(str(item.get(k, "")) for k in ("rule", "match", "source"))
    if kind == "tokens":
        return str(item.get("token_preview") or item.get("source") or "")
    if kind == "endpoints":
        return str(item.get("url") or "")
    return json.dumps(item, sort_keys=True, default=str)


def record(target_name: str, kind: str, items: list[dict]) -> dict:
    """Merge new items into the registry. Returns {new: [...], already_known: [...]}."""
    reg = load()
    tgt = reg["targets"].setdefault(target_name, {
        "secrets": [], "tokens": [], "endpoints": [], "last_scan": None,
    })

    existing = {_key_for(kind, it): it for it in tgt.get(kind, [])}
    new_items, known_items = [], []

    now = datetime.now(timezone.utc).isoformat()
    for it in items:
        k = _key_for(kind, it)
        if k in existing:
            existing[k]["last_seen"] = now
            existing[k]["times_seen"] = existing[k].get("times_seen", 1) + 1
            known_items.append(existing[k])
        else:
            it["first_seen"] = now
            it["last_seen"] = now
            it["times_seen"] = 1
            existing[k] = it
            new_items.append(it)

    tgt[kind] = list(existing.values())
    tgt["last_scan"] = now
    save(reg)

    return {"new": new_items, "already_known": known_items}


def known(target_name: str, kind: str) -> list[dict]:
    reg = load()
    return reg.get("targets", {}).get(target_name, {}).get(kind, [])


def print_known(target_name: str) -> None:
    """Print every secret/token/endpoint ever seen for this target."""
    print("\n" + "=" * 72)
    print(f"PERSISTENT REGISTRY — {target_name}")
    print("=" * 72)

    secrets = known(target_name, "secrets")
    tokens = known(target_name, "tokens")
    endpoints = known(target_name, "endpoints")

    print(f"\n--- KNOWN SECRETS ({len(secrets)}) ---")
    if not secrets:
        print("  (none)")
    for s in sorted(secrets, key=lambda x: x.get("severity", "z")):
        print(f"  [{s.get('severity','?').upper():<8}] {s.get('description','?')}")
        print(f"             match  : {s.get('match','')[:100]}")
        print(f"             source : {s.get('source','')}")
        print(f"             seen   : {s.get('times_seen',1)}x  last {s.get('last_seen','')[:19]}")

    print(f"\n--- KNOWN TOKENS / JWTs ({len(tokens)}) ---")
    if not tokens:
        print("  (none)")
    for t in tokens:
        print(f"  token  : {t.get('token_preview','')}")
        print(f"  source : {t.get('source','')}")
        issues = t.get("issues", [])
        for i in issues:
            print(f"     [{i.get('severity','?').upper():<8}] {i.get('issue','')}")
        print(f"  seen   : {t.get('times_seen',1)}x  last {t.get('last_seen','')[:19]}")
        print()

    print(f"\n--- KNOWN ENDPOINTS ({len(endpoints)}) ---")
    for e in endpoints:
        flag = "ADMIN" if e.get("is_admin") else "     "
        acc = e.get("accessible_without_auth")
        note = "  <-- PUBLIC" if acc else ""
        print(f"  {e.get('status', '?'):>4}  [{flag}]  {e.get('url','')}{note}")