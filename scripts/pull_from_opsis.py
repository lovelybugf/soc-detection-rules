#!/usr/bin/env python3
"""Copy the rules written on an Opsis server's Detection rules page into rules/custom/, so they can be reviewed and kept here.

    python scripts/pull_from_opsis.py --url http://opsis.example --user soc-admin [--all] [--dry-run]

The password is read from OPSIS_PASSWORD, or asked for; a token from OPSIS_TOKEN is used instead when it is set. The Detection rules
routes are for administrators only (an API key is refused), so the account must be an admin.

- Only custom rules (made or duplicated on the page) are pulled; built-in rules already come from this repository.
- Enabled rules only, unless --all.
- A rule whose id is already in rules/ updates that file when its text differs; a new one becomes rules/custom/<title>.yml.
- Nothing is committed: read the diff, run scripts/check_rules.py and scripts/test_rules.py, add a test, open a pull request.

After the rule is merged and tagged and the server runs that tag, delete the page's copy (Detection rules -> the rule -> Delete):
the detector would otherwise run both, and alerts carry the same rule id.
Standard library plus PyYAML.
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"


def call(base: str, method: str, path: str, token: str | None = None, form: dict | None = None):
    headers, data = {}, None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(base.rstrip("/") + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        sys.exit(f"{method} {path} -> HTTP {exc.code}: {exc.read()[:200].decode(errors='replace')}")


def slug(title: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", title.lower()).strip("_")[:80] or "rule"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True, help="the Opsis address, e.g. http://192.168.54.53")
    parser.add_argument("--user", help="an administrator account (not needed with OPSIS_TOKEN)")
    parser.add_argument("--all", action="store_true", help="also pull rules that are switched off")
    parser.add_argument("--dry-run", action="store_true", help="say what would change, write nothing")
    args = parser.parse_args()

    token = os.environ.get("OPSIS_TOKEN")
    if not token:
        if not args.user:
            sys.exit("give --user (and OPSIS_PASSWORD, or type it) or set OPSIS_TOKEN")
        password = os.environ.get("OPSIS_PASSWORD") or getpass.getpass(f"password for {args.user}: ")
        token = call(args.url, "POST", "/api/auth/login", form={"username": args.user, "password": password})["access_token"]

    by_id: dict[str, Path] = {}
    for path in list(RULES.glob("*.yml")) + list((RULES / "custom").glob("*.yml")):
        document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if document.get("id"):
            by_id[str(document["id"]).lower()] = path

    counts = {"new": 0, "changed": 0, "same": 0, "off": 0}
    for item in call(args.url, "GET", "/api/detection-rules", token):
        if item.get("origin") != "custom":
            continue
        if not item.get("enabled") and not args.all:
            counts["off"] += 1
            continue
        detail = call(args.url, "GET", f"/api/detection-rules/{urllib.parse.quote(item['key'])}", token)
        text = detail["content"].replace("\r\n", "\n").rstrip("\n") + "\n"
        rule_id = str((yaml.safe_load(text) or {}).get("id", "")).lower()
        target = by_id.get(rule_id) or RULES / "custom" / f"{slug(item['title'])}.yml"
        if target.parent == RULES:
            print(f"SKIP {item['title']}: its id is a SigmaHQ rule's; duplicate it on the page under a new id first")
            continue
        if target.exists() and target.read_text(encoding="utf-8").replace("\r\n", "\n") == text:
            counts["same"] += 1
            print(f"same     {target.relative_to(ROOT).as_posix()}")
            continue
        state = "changed" if target.exists() else "new"
        counts[state] += 1
        print(f"{state:8} {target.relative_to(ROOT).as_posix()}  ({item['title']}, {'enabled' if item.get('enabled') else 'off'})")
        if not args.dry_run:
            target.write_text(text, encoding="utf-8", newline="\n")

    print(f"{counts['new']} new, {counts['changed']} changed, {counts['same']} unchanged, {counts['off']} switched off and left out"
          + (" (dry run: nothing written)" if args.dry_run else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
