#!/usr/bin/env python3
"""Turn one bignet run (out/) into a JSON summary."""
import csv, json, re, sys

out, workers, rate = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
truth = json.load(open(f"{out}/truth.json"))
down = set()
m = re.search(r"down: (\d+) hosts", open(f"{out}/down.log").read())
down_count = int(m.group(1)) if m else 0


def export(name):
    doc = json.load(open(f"{out}/{name}.json"))
    return {h["address"]: h for h in doc.get("hosts", [])}


def score(name, expect_hosts):
    hosts = export(name)
    active = {a for a, h in hosts.items() if h.get("status") == "active"}
    tp = len(active & expect_hosts)
    svc_ok = svc_total = 0
    for a in expect_hosts:
        want = set(truth["hosts"][a]["ports"])
        got = {s["port"] for s in hosts.get(a, {}).get("services", []) if s.get("state", "open") == "open" and s.get("status", "active") == "active"}
        svc_total += len(want)
        svc_ok += len(want & got)
    return {"hosts_expected": len(expect_hosts), "hosts_found": tp, "false_hosts": len(active - set(truth["hosts"])),
            "host_recall": round(tp / max(1, len(expect_hosts)), 4), "services_expected": svc_total, "services_found": svc_ok,
            "service_recall": round(svc_ok / max(1, svc_total), 4), "seconds": int(open(f"{out}/{name}.seconds").read()),
            "addresses_per_second": round(truth["addresses"] / max(1, int(open(f"{out}/{name}.seconds").read())), 1)}


all_hosts = set(truth["hosts"])
d12 = json.load(open(f"{out}/diff-1-2.json")).get("changes", [])
d23 = json.load(open(f"{out}/diff-2-3.json")).get("changes", [])
missing = {c["address"] for c in d12 if c["type"] == "host_missing"}
returned = {c["address"] for c in d23 if c["type"] == "host_returned"}
s1 = score("big-1", all_hosts)
s2 = score("big-2", all_hosts - missing) if missing else score("big-2", all_hosts)
s3 = score("big-3", all_hosts)

rows = list(csv.DictReader(open(f"{out}/rate.csv")))
syn = [int(r["tcp_syn"]) for r in rows]; echo = [int(r["icmp_echo"]) for r in rows]; req = [int(r["http_requests"]) for r in rows]
total = [a + b + c for a, b, c in zip(syn, echo, req)]
busy = [t for t in total if t > 0]


def mem(name):
    peak = 0.0
    for line in open(f"{out}/stats.csv"):
        parts = line.strip().split(",")
        if len(parts) < 2 or name not in parts[0]:
            continue
        m = re.match(r"([\d.]+)([KMG]i?B)", parts[1].split("/")[0].strip())
        if m:
            v = float(m.group(1)) * {"K": 1 / 1024, "M": 1, "G": 1024}[m.group(2)[0]]
            peak = max(peak, v)
    return round(peak, 1)


print(json.dumps({
    "network": truth["network"], "addresses": truth["addresses"], "live_hosts": truth["live"], "workers": workers, "max_rate": rate,
    "run1": s1, "run2": s2, "run3": s3,
    "changes": {"taken_down": down_count, "reported_missing": len(missing), "reported_returned": len(returned),
                "other_changes_1_2": len([c for c in d12 if c["type"] != "host_missing"]),
                "other_changes_2_3": len([c for c in d23 if c["type"] != "host_returned"])},
    "target_side_rate": {"peak_per_second": max(total or [0]), "avg_while_scanning": round(sum(busy) / max(1, len(busy)), 1),
                         "seconds_over_limit": len([t for t in total if t > rate]), "peak_syn": max(syn or [0]), "peak_http": max(req or [0])},
    "peak_memory_mib": {"asi": mem("asi-1"), "postgres": mem("postgres")},
}, indent=2))
