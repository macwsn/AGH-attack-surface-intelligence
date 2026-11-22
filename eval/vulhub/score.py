#!/usr/bin/env python3
"""Score a scan of the Vulhub lab against truth.json.

  score.py truth.json export.json            ASI export (asi.export/v1)
  score.py truth.json --baseline nmap.xml    nmap -sV XML, scored the same way
  score.py truth.json --baseline-httpx httpx.json   httpx -td JSON lines, scored the same way
  score.py --truth truth-holdout.json ...    same, truth given as an option

Prints one JSON document: per-service rows and totals.
"""
import json
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import urlsplit


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def matches(name, aliases):
    n = norm(name)
    if not n:
        return False
    padded = " %s " % n
    return any(n == a or " %s " % a in padded for a in aliases)


def version_status(truth, candidates):
    cands = [c.strip() for c in candidates if c and c.strip()]
    if not cands:
        return "missing"
    if truth in cands:
        return "exact"
    mm = truth.split(".")[:2]
    for c in cands:
        if re.split(r"[.\-_ ]", c)[:len(mm)] == mm:
            return "major_minor"
    return "wrong"


def load_nmap(path):
    hosts = []
    for h in ET.parse(path).getroot().findall("host"):
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") == "ipv4"), None)
        services = []
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            sv = p.find("service")
            sv = sv.attrib if sv is not None else {}
            services.append({"port": int(p.get("portid")), "protocol": p.get("protocol"), "state": "open",
                             "service": sv.get("name", ""), "product": sv.get("product", ""),
                             "version": sv.get("version", "")})
        hosts.append({"address": addr, "status": "up", "services": services})
    return {"hosts": hosts}


def load_httpx(path):
    hosts = {}
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        d = json.loads(line)
        u = urlsplit(d.get("url", ""))
        port = u.port or (443 if u.scheme == "https" else 80)
        techs = []
        for t in d.get("tech") or []:
            name, _, ver = t.partition(":")
            techs.append({"name": name, "version": ver, "source": "httpx"})
        hosts.setdefault(u.hostname, []).append(
            {"port": port, "protocol": "tcp", "state": "open", "service": "http", "product": "", "version": "",
             "http": {"title": d.get("title"), "status_code": d.get("status_code")}, "technologies": techs})
    return {"hosts": [{"address": a, "status": "up", "services": s} for a, s in hosts.items()]}


def score(truth, export, tool):
    by_addr = {h.get("address"): h for h in export.get("hosts") or []}
    ignore = [norm(x) for x in truth.get("generic_technologies", []) + truth.get("benign_libraries", [])]
    rows = []
    for t in truth["services"]:
        aliases = [norm(a) for a in [t["product"]] + t.get("aliases", [])]
        host = by_addr.get(t["address"])
        services = [s for s in (host or {}).get("services") or [] if s.get("state", "open") == "open"]
        open_ports = {s.get("port") for s in services}
        names, versions, kinds, false_tech, sources = [], [], set(), [], set()
        for s in services:
            if matches(s.get("product"), aliases):
                names.append(s.get("product"))
                versions.append(s.get("version"))
                sources.add("service.product")
            for tech in s.get("technologies") or []:
                if matches(tech.get("name"), aliases):
                    names.append(tech.get("name"))
                    versions.append(tech.get("version"))
                elif norm(tech.get("name")) not in ignore and tech.get("name") not in false_tech:
                    false_tech.append(tech.get("name"))
                if matches(tech.get("name"), aliases):
                    sources.add(tech.get("source") or "")
            for f in s.get("findings") or []:
                kinds.add(f.get("kind"))
                if matches(f.get("name"), aliases):
                    names.append(f.get("name"))
                    versions.append(f.get("version"))
                    sources.add("finding:%s" % (f.get("signature_id") or ""))
        recognised = bool(names)
        rows.append({
            "service": t["name"], "address": t["address"], "product": t["product"], "version": t["version"],
            "category": t["category"],
            "host_found": host is not None,
            "ports": {str(p): p in open_ports for p in t["ports"]},
            "extra_ports": sorted(p for p in open_ports if p not in t["ports"]),
            "recognised": recognised,
            "matched_names": sorted(set(n for n in names if n)),
            "matched_sources": sorted(sources),
            "version_status": version_status(t["version"], versions) if recognised else "missing",
            "versions_seen": sorted(set(v for v in versions if v)),
            "admin_expected": bool(t.get("admin_panel")),
            "admin_flagged": "admin-panel" in kinds,
            "outdated_expected": bool(t.get("outdated")),
            "outdated_flagged": "outdated" in kinds,
            "false_technologies": false_tech,
        })
    truth_addrs = {t["address"] for t in truth["services"]}
    excluded = set(truth.get("excluded", []))
    n = len(rows)
    totals = {
        "services": n,
        "hosts_found": sum(r["host_found"] for r in rows),
        "ports_found": sum(sum(r["ports"].values()) for r in rows),
        "ports_total": sum(len(r["ports"]) for r in rows),
        "recognised": sum(r["recognised"] for r in rows),
        "version_exact": sum(r["version_status"] == "exact" for r in rows),
        "version_major_minor": sum(r["version_status"] == "major_minor" for r in rows),
        "version_wrong": sum(r["version_status"] == "wrong" for r in rows),
        "version_missing": sum(r["version_status"] == "missing" for r in rows),
        "admin_expected": sum(r["admin_expected"] for r in rows),
        "admin_flagged": sum(r["admin_expected"] and r["admin_flagged"] for r in rows),
        "admin_false_flags": sum(r["admin_flagged"] and not r["admin_expected"] for r in rows),
        "outdated_expected": sum(r["outdated_expected"] for r in rows),
        "outdated_flagged": sum(r["outdated_expected"] and r["outdated_flagged"] for r in rows),
        "false_technologies": sum(len(r["false_technologies"]) for r in rows),
        "unexpected_hosts": sorted(a for a in by_addr if a not in truth_addrs and a not in excluded),
    }
    totals["summary"] = "recognised %d/%d, version exact %d/%d, admin flagged %d/%d, false technologies %d" % (
        totals["recognised"], n, totals["version_exact"], n, totals["admin_flagged"], totals["admin_expected"],
        totals["false_technologies"])
    return {"tool": tool, "totals": totals, "services": rows}


def main(argv):
    args, opts = [], {}
    it = iter(argv[1:])
    for a in it:
        if a in ("--truth", "--baseline", "--baseline-httpx"):
            opts[a] = next(it, None)
        else:
            args.append(a)
    truth = opts.get("--truth") or (args.pop(0) if args else None)
    if truth and opts.get("--baseline") and not args:
        export, tool = load_nmap(opts["--baseline"]), "nmap -sV"
    elif truth and opts.get("--baseline-httpx") and not args:
        export, tool = load_httpx(opts["--baseline-httpx"]), "httpx -td"
    elif truth and len(args) == 1 and len(opts) <= 1:
        export, tool = json.load(open(args[0])), "asi"
    else:
        sys.stderr.write(__doc__)
        return 2
    json.dump(score(json.load(open(truth)), export, tool), sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
