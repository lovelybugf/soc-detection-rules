# SOC detection rules

The detection rules of the Opsis (Agentic SOC) platform: a pinned selection of [SigmaHQ](https://github.com/SigmaHQ/sigma) rules and the
project's own rules. The Opsis detector reads `rules/` exactly as laid out here.

```
sigmahq.yml              which SigmaHQ rules to carry, and the SigmaHQ commit they come from
rules/*.yml              SigmaHQ rules, verbatim (never edit them here)
rules/rules.lock.json    path and sha256 of each SigmaHQ file, written by the sync script
rules/custom/*.yml       the project's own rules (plain Sigma, plus the Opsis keys soc_threshold / soc_pattern / signal)
scripts/sync_sigmahq.py  pulls the selection from SigmaHQ and rewrites the lock
scripts/check_rules.py   validates every rule; CI runs it on each push and pull request
```

## Set up

```bash
python -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Add or update SigmaHQ rules (by hand)

1. Add the rule's path in the SigmaHQ repository to `rules:` in `sigmahq.yml`.
2. `python scripts/sync_sigmahq.py` pulls it at the pinned commit; `python scripts/sync_sigmahq.py --ref master` moves every rule to the
   newest SigmaHQ commit and pins it.
3. `python scripts/check_rules.py`, read the diff, commit, open a pull request.

Only plain Sigma detection rules work. Sigma correlation rules are refused by the Lucene backend Opsis uses; write those as a custom
rule with `soc_threshold` or `soc_pattern`. The detector reads Windows logs (Mordor replay and Winlogbeat); a Linux rule compiles but
matches nothing until Opsis has a Linux log source.

## Add a custom rule

Put it in `rules/custom/` with a new UUID as `id`. To change a SigmaHQ rule, copy it there under a new id and change the copy; the check
refuses an edited SigmaHQ file.

## Release

A tag is what servers run. After the change is merged and CI is green:

```bash
git tag -a v2026.11.27 -m "what changed" && git push origin v2026.11.27
```

## On the Opsis server

`/opt/opsis/rules-update.sh <tag>` fetches the tag, checks it with Opsis's own loader (which also understands `soc_threshold` and
`soc_pattern`), and only then switches `/opt/opsis/rules/current` to it and restarts the detector and the backend. The detector and the
Detection rules page read that folder through `DETECTOR_RULES_DIR`. Rules added on the Detection rules page stay in the Opsis database;
they are not in this repository.
