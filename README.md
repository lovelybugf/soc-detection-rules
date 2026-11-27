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
tests/*.yml              sample events per rule, and whether the rule must alert on them
scripts/test_rules.py    runs those tests in a real Elasticsearch; CI runs it on each push and pull request
scripts/pull_from_opsis.py  copies the rules written on an Opsis server's Detection rules page into rules/custom/
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
rule with `soc_threshold` or `soc_pattern`. The detector reads the indices of its `DETECTOR_SOURCES`: Windows logs (Mordor replay and
Winlogbeat) and, on a server that has one, Linux logs in `logs-linux-*` (Filebeat on /var/log/secure, parsed by the Opsis ingest pipeline
`soc-linux` into `event.action`, `event.outcome`, `user.name`, `source.ip`). Linux rules use those ECS field names.

## Add a custom rule

Put it in `rules/custom/` with a new UUID as `id`. To change a SigmaHQ rule, copy it there under a new id and change the copy; the check
refuses an edited SigmaHQ file.

## Test a rule on sample logs

Every new or changed rule should come with a file in `tests/`: a few events it must alert on and a few it must not (see the header of
`scripts/test_rules.py` for the format, and `tests/` for examples). Use real events where you have them, with host names, addresses and
user names replaced (documentation ranges 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

```bash
docker run -d --name rules-es -p 127.0.0.1:9200:9200 -e discovery.type=single-node -e xpack.security.enabled=false   -e ES_JAVA_OPTS="-Xms512m -Xmx512m" elasticsearch:8.13.0
python scripts/test_rules.py                # --es URL for another cluster; --strict fails when a rule has no test
```

The script makes a throwaway index per case with the mapping Opsis uses, runs the rule the way the detector does (plain rules: one match is
an alert; `soc_threshold`: `count` events of one group within `window_seconds`) and deletes the index. `soc_pattern` rules (sequence,
distinct, first_seen, ioc) need the detector itself and are reported as skipped. It lists the rules that have no test yet.

## Bring a rule written on the Opsis page into this repository

Rules made on the Detection rules page live only in that server's database. To keep one here:

```bash
OPSIS_PASSWORD=... python scripts/pull_from_opsis.py --url http://<opsis> --user <admin> --dry-run   # then without --dry-run
```

It writes each enabled custom rule to `rules/custom/` (a rule whose id is already here updates that file). Review the diff, add a test, open a
pull request. Once the server runs a tag that has the rule, delete the page's copy so the detector does not run it twice.

## Release

A tag is what servers run. Every push to `main` whose checks and tests pass is tagged by the workflow `tag.yml` (`vYYYY.MM.DD`, then
`.2`, `.3`... for later ones the same day), so a merged pull request becomes a tag without anyone typing it. To tag by hand instead:

```bash
git tag -a v2026.11.27 -m "what changed" && git push origin v2026.11.27
```

## On the Opsis server

On the Detection rules page (admin), the **Git sync** box does both directions: **Pull from git** switches the server to a tag (same check as
below, no restart), **Push to git** opens a pull request here with the rules written on the page. From the shell,
`deploy/scripts/rules-update.sh <tag>` fetches the tag, checks it with Opsis's own loader (which also understands `soc_threshold` and
`soc_pattern`), and only then switches `/opt/opsis/rules/current` to it and restarts the detector and the backend. The detector and the
Detection rules page read that folder through `DETECTOR_RULES_DIR`. Rules added on the Detection rules page stay in the Opsis database
until someone pushes them (Push to git, or `scripts/pull_from_opsis.py`).
