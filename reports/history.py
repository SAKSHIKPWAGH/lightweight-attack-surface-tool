"""Scan history: store each scan and diff against the previous one for the same target."""
import json
import os
import re
from datetime import datetime


def _dir(outdir):
    d = os.path.join(outdir, "history")
    os.makedirs(d, exist_ok=True)
    return d


def _safe(target):
    return re.sub(r"[^a-z0-9.-]", "_", target.lower())


def load_previous(outdir, target):
    d, prefix = _dir(outdir), _safe(target) + "_"
    files = sorted(f for f in os.listdir(d) if f.startswith(prefix) and f.endswith(".json"))
    if not files:
        return None
    with open(os.path.join(d, files[-1]), encoding="utf-8") as fh:
        return json.load(fh)


def save(outdir, results, findings, summary):
    name = "%s_%s.json" % (_safe(results["target"]), datetime.now().strftime("%Y%m%d_%H%M%S"))
    path = os.path.join(_dir(outdir), name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"results": results, "findings": findings, "summary": summary}, fh)
    return path


def diff(prev, results, findings, summary):
    if not prev:
        return None
    key = lambda f: (f["id"], f["host"])
    old, new = {key(f): f for f in prev["findings"]}, {key(f): f for f in findings}
    old_hosts, new_hosts = set(prev["results"]["hosts"]), set(results["hosts"])
    old_ports = {(h, p["port"]) for h, d in prev["results"]["hosts"].items() for p in d["ports"]}
    new_ports = {(h, p["port"]) for h, d in results["hosts"].items() for p in d["ports"]}
    return {
        "previous_at": prev["results"].get("scanned_at"),
        "new": [new[k] for k in new if k not in old],
        "resolved": [old[k] for k in old if k not in new],
        "unchanged": len([k for k in new if k in old]),
        "new_hosts": sorted(new_hosts - old_hosts), "removed_hosts": sorted(old_hosts - new_hosts),
        "new_ports": sorted("%s:%d" % x for x in new_ports - old_ports),
        "closed_ports": sorted("%s:%d" % x for x in old_ports - new_ports),
        "score_delta": summary["score"] - prev["summary"]["score"],
    }
