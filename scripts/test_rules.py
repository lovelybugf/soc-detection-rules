#!/usr/bin/env python3
"""Run the sample-log tests of the rules against a real Elasticsearch.

    python scripts/test_rules.py [--es http://localhost:9200] [--user U --password-env VAR] [--strict]

Each file in tests/ names one rule and lists cases: a few log events and whether the rule must raise an alert on them. For every case the
script makes a throwaway index with the mapping Opsis gives its log indices (strings are lowercase keywords, EventID a number, source.ip an
address), loads the events, runs the rule the way the Opsis detector does and compares the outcome with `expect`. The index is deleted
afterwards. Nothing else in the cluster is read or written, so a lab cluster is fine; CI uses an empty one.

How a rule is run (the parts of the Opsis detector that decide whether it alerts):
- The rule compiles with pySigma's Lucene backend plus the Opsis "raw" pipeline: process_creation rules also require EventID 1 or 4688,
  process_access rules EventID 10, and Provider_Name is read as SourceName. The query runs as a query_string with analyze_wildcard and AND.
- A plain rule alerts when one event or more matches.
- A soc_threshold rule alerts when one group (host.name plus its group_by fields) has `count` matching events or more, all within
  `window_seconds` of each other. Opsis counts in fixed windows aligned to the epoch; a test whose events fit in one window behaves the same.
- soc_pattern rules (sequence, distinct, first_seen, ioc) need the detector itself: their tests are reported as skipped.

Exit 1 when a case fails, or, with --strict, when a rule has no test. Rules without tests are listed either way.

Test file format (tests/<anything>.yml):

    rule: custom/lnx_sshd_password_bruteforce_threshold.yml    # path under rules/
    source: where the events come from
    cases:
      - name: six failures from one address
        expect: alert                # alert | no_alert
        repeat: {count: 6, every_seconds: 10}   # optional: repeat `events`, moving @timestamp forward each time
        events:
          - {"@timestamp": "2026-11-27T03:14:00Z", "event": {"action": "ssh_login", "outcome": "failure"}, ...}
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.processing.pipeline import ProcessingPipeline

ROOT = Path(__file__).resolve().parent.parent
RULES, TESTS = ROOT / "rules", ROOT / "tests"
OPSIS_KEYS = ("soc_threshold", "soc_pattern", "signal")

# The "raw" pipeline of Opsis (apps/server/core_soc/siem/rules.py, _PIPELINE): keep the two in step.
RAW_PIPELINE = """
name: soc-windows-event-ids
priority: 10
transformations:
  - id: process_creation_event_ids
    type: add_condition
    conditions:
      EventID: [1, 4688]
    rule_conditions:
      - type: logsource
        category: process_creation
  - id: process_access_event_id
    type: add_condition
    conditions:
      EventID: 10
    rule_conditions:
      - type: logsource
        category: process_access
  - id: provider_name_is_source_name
    type: field_name_mapping
    mapping:
      Provider_Name: SourceName
"""

# The mapping Opsis gives logs-mordor-* (apps/server/core_soc/siem/templates.py, log_template); logs-linux-* uses the same.
INDEX_BODY = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0, "analysis": {"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}}},
    "mappings": {
        "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": {"type": "keyword", "normalizer": "lc", "ignore_above": 8000}}}],
        "properties": {
            "@timestamp": {"type": "date"},
            "event": {"properties": {"ingested": {"type": "date"}, "code": {"type": "keyword"}}},
            "EventID": {"type": "long"},
            "message": {"type": "text"},
            "Message": {"type": "text"},
            "source": {"properties": {"ip": {"type": "ip"}}},
            "destination": {"properties": {"ip": {"type": "ip"}}},
        },
    },
}


class Elastic:
    def __init__(self, url: str, user: str | None, password: str | None) -> None:
        self.url = url.rstrip("/")
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() if user else None

    def call(self, method: str, path: str, body=None, ndjson: str | None = None, ok=(200, 201)):
        data = ndjson.encode() if ndjson is not None else (json.dumps(body).encode() if body is not None else None)
        headers = {"Content-Type": "application/x-ndjson" if ndjson is not None else "application/json"}
        if self.auth:
            headers["Authorization"] = self.auth
        request = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            if exc.code in ok:
                return json.loads(exc.read() or b"{}")
            raise RuntimeError(f"{method} {path} -> HTTP {exc.code}: {exc.read()[:300].decode(errors='replace')}") from None


def compile_rule(text: str) -> tuple[str, dict | None, bool]:
    """(lucene query, soc_threshold or None, is a soc_pattern rule)"""
    document = yaml.safe_load(text)
    threshold, pattern = document.get("soc_threshold"), document.get("soc_pattern")
    for key in OPSIS_KEYS:
        document.pop(key, None)
    if pattern is not None:
        return "", None, True
    backend = LuceneBackend(processing_pipeline=ProcessingPipeline.from_yaml(RAW_PIPELINE))
    queries = [str(q) for q in backend.convert(SigmaCollection.from_dicts([document]))]
    if len(queries) != 1 or not queries[0].strip():
        raise ValueError(f"expected one query, got {len(queries)}")
    return queries[0], threshold, False


def expand(case: dict) -> list[dict]:
    events = case.get("events") or []
    repeat = case.get("repeat")
    if not repeat:
        return events
    out = []
    for i in range(int(repeat["count"])):
        for event in events:
            e = copy.deepcopy(event)
            start = datetime.fromisoformat(str(e["@timestamp"]).replace("Z", "+00:00"))
            e["@timestamp"] = (start + timedelta(seconds=i * int(repeat.get("every_seconds", 1)))).isoformat()
            out.append(e)
    return out


def field_get(doc: dict, dotted: str):
    value = doc
    for part in dotted.split("."):
        if not isinstance(value, dict) or part not in value:
            return doc.get(dotted)
        value = value[part]
    return value


def run_case(es: Elastic, query: str, threshold: dict | None, events: list[dict]) -> tuple[bool, str]:
    index = f"rule-test-{uuid.uuid4().hex[:12]}"
    es.call("PUT", f"/{index}", INDEX_BODY)
    try:
        now = datetime.now(timezone.utc).isoformat()
        lines = []
        for event in events:
            event = copy.deepcopy(event)
            event.setdefault("event", {}).setdefault("ingested", now)
            lines += [json.dumps({"index": {}}), json.dumps(event)]
        result = es.call("POST", f"/{index}/_bulk?refresh=true", ndjson="\n".join(lines) + "\n")
        if result.get("errors"):
            bad = next(i["index"]["error"] for i in result["items"] if "error" in i["index"])
            raise RuntimeError(f"an event was refused by Elasticsearch: {bad}")
        search = {"size": 1000, "_source": True, "query": {"query_string": {"query": query, "analyze_wildcard": True, "default_operator": "AND"}}}
        hits = [h["_source"] for h in es.call("POST", f"/{index}/_search", search)["hits"]["hits"]]
        if threshold is None:
            return bool(hits), f"{len(hits)} matching event(s)"
        groups: dict[tuple, list[datetime]] = {}
        for hit in hits:
            key = tuple(str(field_get(hit, f)) for f in ["host.name", *threshold["group_by"]])
            groups.setdefault(key, []).append(datetime.fromisoformat(str(hit["@timestamp"]).replace("Z", "+00:00")))
        best = 0
        for times in groups.values():
            times.sort()
            for i in range(len(times)):  # the largest number of events inside any window_seconds span
                j = i
                while j + 1 < len(times) and (times[j + 1] - times[i]).total_seconds() <= threshold["window_seconds"]:
                    j += 1
                best = max(best, j - i + 1)
        return best >= int(threshold["count"]), f"{len(hits)} matching event(s), largest group {best} of {threshold['count']} needed"
    finally:
        es.call("DELETE", f"/{index}", ok=(200, 404))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--es", default=os.environ.get("ES_URL", "http://localhost:9200"))
    parser.add_argument("--user", default=os.environ.get("ES_USER"))
    parser.add_argument("--password-env", default="ES_PASSWORD", help="the environment variable that holds the password")
    parser.add_argument("--strict", action="store_true", help="fail when a rule has no test")
    args = parser.parse_args()
    es = Elastic(args.es, args.user, os.environ.get(args.password_env) if args.user else None)
    print(f"Elasticsearch {es.call('GET', '/')['version']['number']} at {args.es}")

    failures, skipped, tested = 0, 0, set()
    for path in sorted(TESTS.glob("*.yml")):
        spec = yaml.safe_load(path.read_text(encoding="utf-8"))
        rule_path = RULES / spec["rule"]
        tested.add(rule_path.resolve())
        try:
            query, threshold, pattern = compile_rule(rule_path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"FAIL {path.name}: rule {spec['rule']} does not compile ({exc})")
            failures += 1
            continue
        for case in spec["cases"]:
            label = f"{spec['rule']} :: {case['name']}"
            if pattern:
                print(f"SKIP {label} (soc_pattern rules need the Opsis detector)")
                skipped += 1
                continue
            alerted, detail = run_case(es, query, threshold, expand(case))
            want = case["expect"] == "alert"
            print(f"{'ok  ' if alerted == want else 'FAIL'} {label}: expected {case['expect']}, {detail}")
            failures += alerted != want

    all_rules = sorted(RULES.glob("*.yml")) + sorted((RULES / "custom").glob("*.yml"))
    untested = [p.relative_to(RULES).as_posix() for p in all_rules if p.resolve() not in tested]
    print(f"{len(all_rules) - len(untested)} of {len(all_rules)} rule(s) have tests; {failures} failure(s), {skipped} skipped")
    if untested:
        print("no test yet: " + ", ".join(untested))
    return 1 if failures or (args.strict and untested) else 0


if __name__ == "__main__":
    sys.exit(main())
