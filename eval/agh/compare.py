#!/usr/bin/env python3
"""Side-by-side of harness runs: compare.py <results dir> <run sub-dir>... [notes.md]
The first run is the top-level results dir; the last sub-dir is the run being reported -> summary-<last>.md"""
import json, os, sys

RES = sys.argv[1]
args = sys.argv[2:]
notes = ""
if args and args[-1].endswith(".md"):
    notes = open(args[-1]).read().strip() if os.path.exists(args[-1]) else ""
    args = args[:-1]
runs = [json.load(open(os.path.join(RES, "summary.json")))] + [json.load(open(os.path.join(RES, r, "summary.json"))) for r in args]
last = runs[-1]
GROUPS = [
    ("No admin-panel / outdated findings out of the box", ("B2c", "C2c", "D7c", "E2c", "E4", "E5")),
    ("No interesting-header / interesting-cookie findings", ("C6",)),
    ("Applications not recognised as product/technology; versions missing", ("B2b", "C2b", "D7b", "E2b", "E3")),
    ("Service not identified (PostgreSQL empty, httpbin tcpwrapped and not probed)", ("B2a",)),
    ("Traefik dual TLS/HTTP ports recorded over https; false diff changes", ("D8", "D9", "D3", "D6")),
    ("nmap sends OPTIONS / non-HTTP probes (not strictly GET/HEAD)", ("E7",)),
    ("top1000 misses the organisers' ports", ("A5",)),
    ("443 (TLS handshake rejected) exported as service https with http null", ("C4",)),
    ("Quickstart scan of 5 ports takes 48 s", ("I1",)),
]
cell = lambda s, n=120: (lambda t: t if len(t) <= n else t[: n - 1] + "…")(str(s).replace("|", "/").replace("\n", " "))
yn = lambda v: "-" if v is None else ("Y" if v else "N")
flags = lambda r: "·" if r is None else "%s/%s/%s/%s/%s" % (yn(r["service_ok"]), yn(r["product_recognised"]), yn(r["version_right"]), yn(r["admin_flagged"]),
                                                              "-" if not r["outdated_flagged"] else "%d/%d" % (sum(r["outdated_flagged"].values()), len(r["outdated_flagged"])))
names = ["Run %d (`%s`)" % (i + 1, r["product_commit"][:7]) for i, r in enumerate(runs)]
L = ["# ASI vs lab-agh: " + " / ".join(names),
     "Scenarios in the last run: %s. Remaps: %s." % (" ".join("%s=%s" % kv for kv in sorted(last["scenarios"].items())), json.dumps({k: v for k, v in last["port_remaps"].items() if v}) or "none"),
     "", "| Score | " + " | ".join(names) + " |", "|---|" + "---|" * len(runs)]
for k, label in (("products_recognised", "Products recognised"), ("versions_right", "Versions right"), ("admin_panels_flagged", "Admin panels flagged"), ("outdated_flagged", "Outdated flagged"), ("service_names_right", "Service names right")):
    L.append("| %s | %s |" % (label, " | ".join("%d/%d" % tuple(r["score"][k]) for r in runs)))
nf = last.get("extra", {}).get("notable_findings_per_stack", {})
L += ["", "Notable header/cookie findings per stack (last run): " + "; ".join("%s: %d interesting-header, %d interesting-cookie" % (s, len(v["interesting-header"]), len(v["interesting-cookie"])) for s, v in nf.items()) + "."]
L += ["", "## Recognition (flags: service/product/version/admin/outdated; · = not scanned)", "| Port | Truth | Last run: service / product version | Technologies | Findings [kind] | " + " | ".join("R%d" % (i + 1) for i in range(len(runs))) + " |", "|---|---|---|---|---|" + "---|" * len(runs)]
idx = [{(r["stack"], r["port"]): r for r in run["recognition"]} for run in runs]
keys = []
for run in runs:
    keys += [(r["stack"], r["port"]) for r in run["recognition"] if (r["stack"], r["port"]) not in keys]
for k in keys:
    r = idx[-1].get(k); t = next(i[k] for i in idx if k in i)
    L.append("| %s | %s | %s | %s | %s | %s |" % (k[1], cell(t["truth"], 42), "not scanned" if r is None else (cell("%s / %s %s" % (r["service"] or "none", r["product"] or "-", r["version"]), 50) if r["reported"] else "not reported"),
                                               "-" if r is None else cell(", ".join(r["technologies"]) or "-", 90), "-" if r is None else cell(", ".join(r["findings"]) or "-", 260), " | ".join(flags(i.get(k)) for i in idx)))
L += ["", "## Earlier defects"]
cs = [{c["id"]: c for c in r["checks"]} for r in runs]
for n, (title, ids) in enumerate(GROUPS, 1):
    have = [x for x in ids if x in cs[-1]]
    prev = lambda x: next((c[x] for c in reversed(cs[:-1]) if x in c), None)
    if not have:
        st = "not re-run"
    elif all(cs[-1][x]["status"] == "PASS" for x in have):
        st = "fixed"
    elif all(prev(x) and cs[-1][x]["status"] == prev(x)["status"] and cs[-1][x]["observed"].split(";")[0] == prev(x)["observed"].split(";")[0] for x in have):
        st = "still present"
    else:
        st = "changed"
    L.append("%d. **%s**: %s. %s" % (n, title, st, cell("; ".join("%s %s (%s)" % (x, "->".join(c[x]["status"] if x in c else "·" for c in cs), cell(cs[-1][x]["observed"], 170)) for x in have), 800)))
L += ["", "## New in the last run"]
before = set().union(*[set(c) for c in cs[:-1]])
new = [c for c in last["checks"] if c["status"] not in ("PASS", "SKIPPED") and (c["id"] not in before or all(p.get(c["id"], {}).get("status", "PASS") == "PASS" for p in cs[:-1]))
       and not any(c["id"] in ids for _, ids in GROUPS)]
L += ["- check %s %s: expected %s; observed %s; command `%s`; output `%s`" % (c["id"], c["status"], cell(c["expectation"], 110), cell(c["observed"], 300), cell(c["command"], 200), cell(c["evidence"], 250)) for c in new]
L += [notes] if notes else []
if not new and not notes:
    L.append("None.")
L += ["", "## Scan durations (s) and requests seen in target logs, last run", "; ".join("%s %ds/%d" % (n, v["seconds"], v["requests"]["total"]) for sc in sorted(last["runs"]) for n, v in last["runs"][sc].items())]
out = os.path.join(RES, "summary-%s.md" % args[-1])
open(out, "w").write("\n".join(L) + "\n")
print("\n".join(L))
