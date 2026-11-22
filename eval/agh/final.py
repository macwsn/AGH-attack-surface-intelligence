#!/usr/bin/env python3
"""ASI vs plain nmap on the organisers' stacks: final.py <results dir> <run sub-dir> <previous run sub-dir> [notes.md]"""
import json, os, sys

RES, RUN, PREV = sys.argv[1:4]
notes = open(sys.argv[4]).read().strip() if len(sys.argv) > 4 and os.path.exists(sys.argv[4]) else ""
cur = json.load(open(os.path.join(RES, RUN, "summary.json"))); prev = json.load(open(os.path.join(RES, PREV, "summary.json")))
nm = cur["extra"].get("nmap", {}); fc = cur["extra"].get("false_changes", {})
cell = lambda s, n=70: (lambda t: t if len(t) <= n else t[: n - 1] + "…")(str(s).replace("|", "/").replace("\n", " "))
yn = lambda v: "-" if v is None else ("Y" if v else "N")
pv = lambda r: "·" if r is None else "%s/%s/%s" % (yn(r["service_ok"]), yn(r["product_recognised"]), yn(r["version_right"]))
SC = {"custom-network": "B", "modern": "C", "modern-proxy": "D", "vulnerable": "E"}
RUNS = {"B": "b1", "C": "c1", "D": "d1", "E": "e1"}
idx = lambda rg: {(r["stack"], r["port"]): r for r in rg}
A, NL, ND = idx(cur["recognition"]), idx(nm.get("light", {}).get("recognition", [])), idx(nm.get("default", {}).get("recognition", []))
sub = lambda rg, st, k: "%d/%d" % (sum(1 for r in rg.values() if r["stack"] == st and r[k]), sum(1 for r in rg.values() if r["stack"] == st and r[k] is not None))
L = ["# ASI (`%s`) vs nmap on the organisers' stacks" % cur["product_commit"][:7],
     "Image built from `git archive %s`. Target `host.docker.internal`, ports published on 127.0.0.1, one stack at a time. nmap: the same binary inside the ASI container, `nmap -Pn -sT -sV [--version-light] -p <same ports>`. Flags are service/product/version right (Y/N, - = no truth)." % cur["product_commit"][:7],
     "", "| Totals | ASI | nmap --version-light | nmap default |", "|---|---|---|---|"]
for k, label in (("service_names_right", "Service names right"), ("products_recognised", "Products recognised"), ("versions_right", "Versions right"), ("admin_panels_flagged", "Admin panels flagged"), ("outdated_flagged", "Outdated flagged")):
    L.append("| %s | %d/%d | %s | %s |" % (label, *cur["score"][k], *("%d/%d" % tuple(nm[m]["score"][k]) if m in nm else "not run" for m in ("light", "default"))))
L += ["", "| Stack | Products ASI / light / default | Versions ASI / light / default | False changes (scan twice) | Wall-clock s: ASI scan 1, 2 / nmap light / nmap default |", "|---|---|---|---|---|"]
for st, sc in SC.items():
    r = cur["runs"].get(sc, {}); run = RUNS[sc]
    L.append("| %s | %s / %s / %s | %s / %s / %s | %s | %s, %s / %s / %s |" % (st, sub(A, st, "product_recognised"), sub(NL, st, "product_recognised"), sub(ND, st, "product_recognised"),
                                                                 sub(A, st, "version_right"), sub(NL, st, "version_right"), sub(ND, st, "version_right"), fc.get(sc, "not run"),
                                                                 r.get(run, {}).get("seconds", "?"), r.get(run + "b", {}).get("seconds", "?"), nm.get("light", {}).get("seconds", {}).get(sc, "?"), nm.get("default", {}).get("seconds", {}).get(sc, "?")))
for st, sc in SC.items():
    L += ["", "| %s: port | Truth | ASI: service / product version; technologies; findings | nmap light | nmap default | ASI | light | default |" % st, "|---|---|---|---|---|---|---|---|"]
    for k, r in A.items():
        if k[0] != st:
            continue
        nmc = lambda x: "not run" if x is None else (cell("%s / %s %s" % (x["service"] or "none", x["product"] or "-", x["version"]), 60) if x["reported"] else "not open")
        asi = "%s / %s %s; %s; %s" % (r["service"] or "none", r["product"] or "-", r["version"], ", ".join(r["technologies"]) or "-", ", ".join(r["findings"]) or "-") if r["reported"] else "not reported"
        L.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % (k[1], cell(r["truth"], 40), cell(asi, 330), nmc(NL.get(k)), nmc(ND.get(k)), pv(r), pv(NL.get(k)), pv(ND.get(k))))
L += ["", "## Against %s (`%s`)" % (PREV, prev["product_commit"][:7])]
L.append("Scores %s -> %s: " % (PREV, RUN) + ", ".join("%s %d/%d -> %d/%d" % (k, *prev["score"][k], *cur["score"][k]) for k in cur["score"]) + ".")
pc = {c["id"]: c for c in prev["checks"]}
reg = [c for c in cur["checks"] if c["status"] not in ("PASS", "SKIPPED") and pc.get(c["id"], {}).get("status") == "PASS"]
L += ["Regressed checks (PASS before, not now):"] + (["- %s %s: expected %s; observed %s; command `%s`; output `%s`" % (c["id"], c["status"], cell(c["expectation"], 110), cell(c["observed"], 300), cell(c["command"], 220), cell(c["evidence"], 250)) for c in reg] or ["- none"])
P = idx(prev["recognition"])
drops = ["%s:%d %s %s -> %s" % (k[0], k[1], f, yn(P[k][f]), yn(r[f])) for k, r in A.items() if k in P for f in ("service_ok", "product_recognised", "version_right", "admin_flagged") if P[k][f] and not r[f]]
L.append("Recognition flags that dropped: " + ("; ".join(drops) or "none") + ".")
fixed = [c["id"] for c in cur["checks"] if c["status"] == "PASS" and pc.get(c["id"], {}).get("status") not in (None, "PASS", "SKIPPED")]
L.append("Checks fixed since %s: %s. Still failing: %s." % (PREV, ", ".join(fixed) or "none", ", ".join("%s (%s)" % (c["id"], c["status"]) for c in cur["checks"] if c["status"] not in ("PASS", "SKIPPED")) or "none"))
L.append("Durations (s) / requests in target logs: " + "; ".join("%s %d/%d (was %s)" % (n, v["seconds"], v["requests"]["total"], prev["runs"].get(sc, {}).get(n, {}).get("seconds", "-")) for sc in sorted(cur["runs"]) for n, v in cur["runs"][sc].items()))
L += ([""] + [notes] if notes else [])
open(os.path.join(RES, "summary-%s.md" % RUN), "w").write("\n".join(L) + "\n")
print("\n".join(L))
