#!/usr/bin/env python3
"""Check every rule under rules/ before it is merged or tagged.

    python scripts/check_rules.py

1. Each file is a YAML mapping with id, title, level, logsource and detection; level is one Sigma knows.
2. No two rules share an id (Opsis keys built-in rules by their id).
3. rules.lock.json lists exactly the files at the top of rules/, and each one still has the sha256 of its SigmaHQ original.
   A changed SigmaHQ rule is refused: copy it to rules/custom/ under a new id and change the copy.
4. No file in rules/custom/ is in the lock.
5. Every rule compiles with pySigma's Lucene backend, the versions Opsis pins (requirements.txt). Correlation rules are refused,
   as the backend refuses them.

What this does not check: the meaning of the Opsis-only keys soc_threshold and soc_pattern. The server runs Opsis's own loader
over a tag before it switches to it (see README, "On the Opsis server").
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
LEVELS = {"informational", "low", "medium", "high", "critical"}
REQUIRED = ("id", "title", "level", "logsource", "detection")


def main() -> int:
    problems: list[str] = []
    lock = json.loads((RULES / "rules.lock.json").read_text(encoding="utf-8"))
    pinned = lock.get("files", {})
    top = sorted(RULES.glob("*.yml"))
    custom = sorted((RULES / "custom").glob("*.yml"))
    seen: dict[str, str] = {}
    backend = LuceneBackend()

    if set(pinned) != {p.name for p in top}:
        extra, missing = sorted({p.name for p in top} - set(pinned)), sorted(set(pinned) - {p.name for p in top})
        if extra:
            problems.append(f"rules/ has files the lock does not list (own rules belong in rules/custom/): {', '.join(extra)}")
        if missing:
            problems.append(f"the lock lists files that are not in rules/: {', '.join(missing)}")
    for path in top:
        entry = pinned.get(path.name)
        if entry and hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest() != entry["sha256"]:
            problems.append(f"{path.name}: differs from SigmaHQ ({entry['path']}); copy it to rules/custom/ with a new id to change it")
    for path in custom:
        if path.name in pinned:
            problems.append(f"custom/{path.name}: a custom rule must not be in rules.lock.json")

    for path in top + custom:
        label = path.relative_to(RULES).as_posix()
        text = path.read_text(encoding="utf-8")
        try:
            document = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            problems.append(f"{label}: not valid YAML ({exc})")
            continue
        if not isinstance(document, dict):
            problems.append(f"{label}: not a YAML mapping")
            continue
        missing = [key for key in REQUIRED if not document.get(key)]
        if missing:
            problems.append(f"{label}: missing {', '.join(missing)}")
            continue
        if str(document["level"]) not in LEVELS:
            problems.append(f"{label}: level '{document['level']}' is not one of {', '.join(sorted(LEVELS))}")
        rule_id = str(document["id"]).lower()
        if rule_id in seen:
            problems.append(f"{label}: id {rule_id} is also used by {seen[rule_id]}")
        seen[rule_id] = label
        if "correlation" in document:
            problems.append(f"{label}: Sigma correlation rules are not supported; write a soc_threshold or soc_pattern rule in custom/")
            continue
        try:
            for query in backend.convert(SigmaCollection.from_yaml(text)):
                if not str(query).strip():
                    problems.append(f"{label}: compiles to an empty query")
        except Exception as exc:  # pySigma raises many types; the message is what the author needs
            problems.append(f"{label}: does not compile ({type(exc).__name__}: {str(exc).splitlines()[0]})")

    for line in problems:
        print(f"FAIL {line}")
    print(f"{len(top)} SigmaHQ rule(s), {len(custom)} custom rule(s), {len(problems)} problem(s)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
