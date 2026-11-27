#!/usr/bin/env python3
"""Pull the SigmaHQ rules listed in sigmahq.yml into rules/, verbatim, and rewrite rules/rules.lock.json.

    python scripts/sync_sigmahq.py                 # the commit in sigmahq.yml (reproduces the repository)
    python scripts/sync_sigmahq.py --ref master    # resolve a branch or tag to its newest commit, pin it in sigmahq.yml
    python scripts/sync_sigmahq.py --check         # change nothing; exit 1 if rules/ differs from what the pin gives

Standard library plus PyYAML. Files are stored with LF endings; the sha256 in the lock is taken over that text, which is what
Opsis checks. A file that was synced before and is no longer listed is removed. Nothing under rules/custom/ is touched.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SELECTION = ROOT / "sigmahq.yml"
RULES = ROOT / "rules"
LOCK = RULES / "rules.lock.json"
NOTE = "sha256 is taken over the file with LF line endings"


def fetch(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "soc-detection-rules-sync"})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        raise SystemExit(f"{url} -> HTTP {exc.code}") from None


def resolve(repository: str, ref: str) -> str:
    data = json.loads(fetch(f"https://api.github.com/repos/{repository}/commits/{ref}"))
    return data["sha"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ref", help="branch or tag of SigmaHQ to move to (its newest commit is pinned)")
    parser.add_argument("--check", action="store_true", help="only compare rules/ with the pinned commit")
    args = parser.parse_args()

    selection = yaml.safe_load(SELECTION.read_text(encoding="utf-8"))
    repository, commit, paths = selection["repository"], selection["commit"], selection["rules"]
    names = [Path(p).name for p in paths]
    if len(set(names)) != len(names):
        raise SystemExit("two selected rules share a file name; rules/ is flat, so rename is not possible: pick one")
    if args.ref:
        if args.check:
            raise SystemExit("--check compares with the pinned commit; do not pass --ref with it")
        commit = resolve(repository, args.ref)
        print(f"{args.ref} -> {commit}")

    wanted: dict[str, str] = {}
    files: dict[str, dict[str, str]] = {}
    for path in paths:
        text = fetch(f"https://raw.githubusercontent.com/{repository}/{commit}/{path}").decode("utf-8").replace("\r\n", "\n")
        name = Path(path).name
        wanted[name] = text
        files[name] = {"path": path, "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest()}
    lock = {"source": f"https://github.com/{repository}", "commit": commit, "note": NOTE, "files": files}

    old = json.loads(LOCK.read_text(encoding="utf-8")) if LOCK.exists() else {"files": {}}
    if args.check:
        drift = [n for n, t in wanted.items() if not (RULES / n).exists() or (RULES / n).read_text(encoding="utf-8") != t]
        drift += [n for n in old.get("files", {}) if n not in wanted]
        if old.get("commit") != commit:
            drift.append(f"lock commit {old.get('commit')} != {commit}")
        print("in step with the pin" if not drift else "differs: " + ", ".join(drift))
        return 1 if drift else 0

    for name in old.get("files", {}):
        if name not in wanted and (RULES / name).exists():
            (RULES / name).unlink()
            print(f"removed {name}")
    for name, text in wanted.items():
        target = RULES / name
        before = target.read_text(encoding="utf-8") if target.exists() else None
        target.write_bytes(text.encode("utf-8"))
        print(f"{'unchanged' if before == text else 'updated' if before else 'added'} {name}")
    LOCK.write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8", newline="\n")
    if args.ref:
        SELECTION.write_text(SELECTION.read_text(encoding="utf-8").replace(selection["commit"], commit), encoding="utf-8", newline="\n")
    print(f"{len(wanted)} SigmaHQ rule(s) at {commit[:12]}; review the diff, run scripts/check_rules.py, then commit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
