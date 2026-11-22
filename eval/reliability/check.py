#!/usr/bin/env python3
"""Checks used by run.sh. Every subcommand prints one JSON object; exit 0 = the check holds.

    check.py cmp A.json B.json [--identity]   exports equal (timestamps ignored), no duplicate hosts/services
    check.py hostile EXPORT.json              every hostile target recorded as open, export valid UTF-8 JSON, sizes
    check.py changes DIFF.json                number of diff changes (exit 0 when zero)
    check.py clean FILE...                    no panic / stack trace in the files; reports stderr line count of the first
    check.py summary RESULTS_DIR COMMIT       collect <scenario>/result.json into summary.json
"""
import json
import os
import sys

# timestamps and measurements that legitimately differ between two runs of the same network
VOLATILE = {"generated_at", "run", "first_seen", "last_seen", "response_time_ms", "ttfb_ms", "availability"}
SCENARIOS = ["kill-resume", "db-restart", "host-vanishes", "hostile-http", "concurrent-runs", "bad-input",
             "repeat-stability", "key-rotation-and-wrong-key", "port-flap", "sigterm-pause", "recheck-mode"]
SMALL = range(144, 176)   # targets-small.txt
PORTS = [22, 80, 443, 6379, 8000, 8080]


def strip(x):
    if isinstance(x, dict):
        return {k: strip(v) for k, v in x.items() if k not in VOLATILE}
    if isinstance(x, list):
        return [strip(v) for v in x]
    return x


def identity(host):
    return {"address": host["address"], "services": [
        {"port": s["port"], "protocol": s["protocol"], "state": s.get("state"), "service": s.get("service"),
         "product": s.get("product"), "version": s.get("version"),
         "status_code": (s.get("http") or {}).get("status_code"), "title": (s.get("http") or {}).get("title")}
        for s in host.get("services") or []]}


def load(path, ident):
    doc = json.load(open(path, encoding="utf-8"))
    hosts, dups = {}, []
    for h in doc.get("hosts") or []:
        if h["address"] in hosts:
            dups.append(h["address"])
        seen = set()
        for s in h.get("services") or []:
            key = (s["port"], s["protocol"])
            if key in seen:
                dups.append(f"{h['address']}:{s['port']}/{s['protocol']}")
            seen.add(key)
        h = identity(h) if ident else strip(h)
        h["services"] = sorted(h.get("services") or [], key=lambda s: (s["port"], s["protocol"]))
        hosts[h["address"]] = h
    return hosts, dups


def walk(a, b, path, out):
    if len(out) >= 15:
        return
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            walk(a.get(k), b.get(k), f"{path}.{k}", out)
    elif isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            walk(x, y, f"{path}[{i}]", out)
    elif a != b:
        out.append({"path": path, "a": json.dumps(a)[:120], "b": json.dumps(b)[:120]})


def cmp(a, b, ident):
    ha, da = load(a, ident)
    hb, db = load(b, ident)
    diffs = []
    for addr in sorted(set(ha) | set(hb)):
        if addr not in ha or addr not in hb:
            diffs.append({"path": addr, "a": "present" if addr in ha else "missing", "b": "present" if addr in hb else "missing"})
        else:
            walk(ha[addr], hb[addr], addr, diffs)
    out = {"hosts_a": len(ha), "hosts_b": len(hb),
           "services_a": sum(len(h["services"]) for h in ha.values()),
           "services_b": sum(len(h["services"]) for h in hb.values()),
           "duplicates": da + db, "differences": diffs[:15], "equal": not diffs and not da and not db}
    print(json.dumps(out))
    return 0 if out["equal"] else 1


def longest(x):
    if isinstance(x, str):
        return len(x)
    if isinstance(x, dict):
        return max([longest(v) for v in x.values()] + [len(k) for k in x] + [0])
    if isinstance(x, list):
        return max([longest(v) for v in x] + [0])
    return 0


def hostile(path):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import hostile as hz
    out = {"export_bytes": os.path.getsize(path), "valid_utf8": False, "valid_json": False, "missing": [], "not_open": [],
           "no_http": [], "recorded": {}}
    raw = open(path, "rb").read()
    try:
        text = raw.decode("utf-8", "strict")
        out["valid_utf8"] = True
        doc = json.loads(text)
        out["valid_json"] = True
    except Exception as e:
        out["error"] = str(e)[:200]
        print(json.dumps(out))
        return 1
    hosts = {h["address"]: h for h in doc.get("hosts") or []}
    out["longest_string"] = longest(doc)
    for octet, (port, kind) in sorted(hz.TARGETS.items()):
        addr = f"{hz.NET}.{octet}"
        svc = next((s for s in (hosts.get(addr) or {}).get("services") or [] if s["port"] == port), None)
        if addr not in hosts or svc is None:
            out["missing"].append(f"{addr}:{port} {kind}")
            continue
        if svc.get("state") != "open":
            out["not_open"].append(f"{addr}:{port} {kind} state={svc.get('state')}")
        http = svc.get("http") or {}
        if not http:
            out["no_http"].append(kind)
        out["recorded"][kind] = {"service": svc.get("service"), "state": svc.get("state"),
                                 "status_code": http.get("status_code"), "title": (http.get("title") or "")[:60],
                                 "title_len": len(http.get("title") or ""), "headers": len(http.get("headers") or {}),
                                 "redirects": len(http.get("redirect_chain") or []),
                                 "cookie_name_len": max([len(c.get("name", "")) for c in http.get("cookies") or []] + [0])}
        if kind == "offsite":
            blob = json.dumps(http)
            out["offsite_recorded"] = hz.OFFSITE in blob
    out["offsite_in_inventory"] = hz.OFFSITE in hosts
    ok = out["valid_json"] and not out["missing"] and not out["not_open"]
    print(json.dumps(out))
    return 0 if ok else 1


def changes(path):
    doc = json.load(open(path, encoding="utf-8"))
    ch = doc.get("changes") or []
    print(json.dumps({"changes": len(ch), "sample": ch[:5]}))
    return 0 if not ch else 1


def clean(paths):
    bad = []
    for p in paths:
        if not os.path.exists(p):
            continue
        text = open(p, "rb").read().decode("utf-8", "replace")
        for marker in ("panic:", "goroutine ", "runtime error", "SIGSEGV", "\tgo/src/"):
            if marker in text:
                bad.append(f"{os.path.basename(p)}: {marker.strip()}")
    lines = 0
    if paths and os.path.exists(paths[0]):
        lines = len([line for line in open(paths[0], "rb").read().splitlines() if line.strip()])
    print(json.dumps({"stack_trace": bad, "lines": lines}))
    return 0 if not bad else 1


def port_flap(ev):
    out, ok = {}, True
    for d, want in (("diff-p0-p1", "service_missing"), ("diff-p1-p2", "service_returned")):
        try:
            ch = json.load(open(f"{ev}/{d}.json"))["changes"]
        except Exception as e:
            out[d] = f"unreadable: {e}"
            ok = False
            continue
        out[d] = [{k: c.get(k) for k in ("type", "address", "port")} for c in ch]
        ok = ok and out[d] == [{"type": want, "address": "172.29.0.51", "port": 80}]
    try:
        h = [h for h in json.load(open(f"{ev}/p1.json"))["hosts"] if h["address"] == "172.29.0.51"]
        out["p1_record"] = [{"status": x["status"], "services": [{k: s.get(k) for k in ("port", "state", "status", "missed_runs")}
                                                                 for s in x.get("services") or []]} for x in h]
    except Exception as e:
        out["p1_record"] = f"unreadable: {e}"
    out["ok"] = ok
    print(json.dumps(out))
    return 0


def recheck_rules(truth):
    """every (live address, port) of the small target set: one SYN counter each"""
    hosts = json.load(open(truth))["hosts"]
    for addr in sorted(hosts, key=lambda a: int(a.rsplit(".", 1)[1])):
        if int(addr.rsplit(".", 1)[1]) in SMALL:
            for p in PORTS:
                print(addr, p)
    return 0


def recheck_verify(export, counters, neigh, stopped, diff):
    import re
    known = {(h["address"], s["port"]) for h in json.load(open(export))["hosts"] for s in h.get("services") or []}
    known_hosts = {a for a, _ in known}
    syn, icmp = {}, 0
    for line in open(counters):
        f = line.split()
        if not f or not f[0].isdigit():
            continue
        if "icmp" in f:
            icmp = int(f[0])
            continue
        m = re.search(r"dpt:(\d+)", line)
        ips = [x for x in f if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", x)]
        if m and ips:
            syn[(ips[-1], int(m.group(1)))] = int(f[0])
    unknown_hit = sorted(f"{a}:{p}" for (a, p), n in syn.items() if n and (a, p) not in known)
    known_missed = sorted(f"{a}:{p}" for (a, p) in known if a != stopped and not syn.get((a, p)))
    looked_up = set()
    for line in open(neigh):
        f = line.split()
        if f and f[0].startswith("172.29.0.") and int(f[0].rsplit(".", 1)[1]) >= 64:
            looked_up.add(f[0])
    stray = sorted(looked_up - known_hosts, key=lambda a: int(a.rsplit(".", 1)[1]))
    try:
        ch = json.load(open(diff))["changes"]
    except Exception as e:
        ch = [{"type": f"diff unreadable: {e}", "address": ""}]
    other = [c for c in ch if c.get("address") != stopped]
    mine = [{k: c.get(k) for k in ("type", "address", "port") if c.get(k) is not None} for c in ch if c.get("address") == stopped]
    why = []
    if unknown_hit:
        why.append(f"SYN to {len(unknown_hit)} (address, port) pairs without a known service, e.g. {unknown_hit[:3]}")
    if stray:
        why.append(f"neighbour lookups for {len(stray)} addresses without a known service, e.g. {stray[:3]}")
    if icmp:
        why.append(f"{icmp} ICMP echo requests reached the responder")
    if not syn:
        why.append("no SYN counters read")
    if other:
        why.append(f"{len(other)} changes for other hosts, e.g. {json.dumps(other[0])[:160]}")
    if not mine or any(c["type"] not in ("host_missing", "service_missing") for c in mine):
        why.append(f"stopped host reported as {mine}")
    print(json.dumps({"known_services": len(known), "syn_counters": len(syn), "known_services_contacted": sum(1 for k in known if syn.get(k)),
                      "known_services_not_contacted": known_missed, "unknown_pairs_contacted": unknown_hit, "icmp_echo": icmp,
                      "neighbour_entries": len(looked_up), "stray_neighbour_lookups": stray, "changes_stopped_host": mine,
                      "changes_other_hosts": len(other), "why": "; ".join(why)}))
    return 1 if why else 0


def summary(res, commit):
    out = {"product_commit": commit, "scenarios": []}
    for name in SCENARIOS:
        p = os.path.join(res, name, "result.json")
        r = json.load(open(p)) if os.path.exists(p) else {"status": "NOT RUN", "reason": "", "property": "", "measured": {}}
        out["scenarios"].append({"scenario": name, **r, "evidence": os.path.join("eval/results/reliability", os.environ.get("RUN", ""), name) + "/", "product_commit": commit})
    json.dump(out, open(os.path.join(res, "summary.json"), "w"), indent=1)
    for s in out["scenarios"]:
        print(f"{s['status']:8} {s['scenario']}: {s['reason']}")
    return 0


if __name__ == "__main__":
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "cmp":
        sys.exit(cmp(args[0], args[1], "--identity" in args))
    if cmd == "hostile":
        sys.exit(hostile(args[0]))
    if cmd == "changes":
        sys.exit(changes(args[0]))
    if cmd == "clean":
        sys.exit(clean(args))
    if cmd == "port-flap":
        sys.exit(port_flap(args[0]))
    if cmd == "recheck-rules":
        sys.exit(recheck_rules(args[0]))
    if cmd == "recheck-verify":
        sys.exit(recheck_verify(*args[:5]))
    if cmd == "summary":
        sys.exit(summary(args[0], args[1]))
    sys.exit(2)
