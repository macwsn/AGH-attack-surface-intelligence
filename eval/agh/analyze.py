#!/usr/bin/env python3
"""Turns eval/results/agh/<scenario>/ into summary.json and summary.md (expectation vs observed)."""
import csv, glob, json, os, re, sys

RES = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "..", "results", "agh")
EX = "docker compose -p asi-agh-prod exec -T asi "
checks, sections = [], {}
TITLES = {"A": "A Quickstart", "B": "B custom-network", "C": "C modern", "D": "D modern-proxy (Toxiproxy)",
          "E": "E vulnerable", "H": "H recheck mode", "F": "F custom signature", "G": "G import/export"}


def rd(*p):
    try:
        with open(os.path.join(RES, *p), errors="replace") as f:
            return f.read()
    except OSError:
        return None


def js(*p):
    t = rd(*p)
    try:
        return json.loads(t) if t else None
    except ValueError:
        return None


def portmap(stack):
    m = {}
    for line in (rd("portmap-%s.tsv" % stack) or "").splitlines():
        a, b = line.split("\t")
        m[int(a)] = int(b)
    return m


def scans(sc):
    out = {}
    for line in (rd(sc, "scans.tsv") or "").splitlines():
        f = line.split("\t")
        out[f[0]] = {"seconds": int(f[1]), "exit": int(f[2]) if f[2].lstrip("-").isdigit() else None, "ports": f[3], "cmd": EX + f[4]}
    return out


def services(exp):
    return [s for h in (exp or {}).get("hosts") or [] for s in h.get("services") or []]


def svc(exp, port):
    for s in services(exp):
        if s.get("port") == port:
            return s
    return None


def open_ports(exp):
    return sorted(s["port"] for s in services(exp) if s.get("state") == "open" and s.get("status", "active") == "active")


def brief(s):
    if not s:
        return "not reported"
    h = s.get("http") or {}
    parts = ["%s %s %s" % (s.get("service") or "?", s.get("product") or "-", s.get("version") or "")]
    if h:
        parts.append("HTTP %s '%s' server=%s" % (h.get("status_code"), (h.get("title") or "")[:40], (h.get("headers") or {}).get("server", "-")))
    t = ", ".join("%s %s" % (x["name"], x.get("version") or "") for x in s.get("technologies") or [])
    f = ", ".join("%s[%s]" % (x.get("signature_id"), x.get("kind")) for x in s.get("findings") or [])
    parts.append("tech: " + (t.strip() or "-"))
    parts.append("findings: " + (f or "-"))
    return "; ".join(p.strip() for p in parts)


REQ = re.compile(r'\b(GET|HEAD|POST|PUT|DELETE|OPTIONS|PATCH|PROPFIND|TRACE|CONNECT|SEARCH)\s+(/\S*|\*)')


def requests(sc, scan):
    """Requests seen by the target containers during one scan: {service: [(method, path)]}"""
    out = {}; seen = set()
    for f in sorted(glob.glob(os.path.join(RES, sc, "logs", scan, "*.log"))):
        name = os.path.basename(f).replace(".file.log", "").replace(".log", "")
        with open(f, errors="replace") as fh:
            for line in fh:
                if (name, line) in seen:
                    continue
                seen.add((name, line))
                if "[error]" in line or "healthcheck" in line.lower():
                    continue
                m = REQ.search(line)
                if m:
                    out.setdefault(name, []).append((m.group(1), m.group(2)))
    return out


def reqsummary(sc, scan):
    r = requests(sc, scan)
    return {"total": sum(len(v) for v in r.values()), "per_service": {k: len(v) for k, v in r.items()},
            "methods": sorted({m for v in r.values() for m, _ in v})}


def add(sc, cid, expect, status, observed, cmd="", evidence=""):
    checks.append({"scenario": sc, "id": cid, "expectation": expect, "status": status, "observed": observed,
                   "command": cmd, "evidence": evidence})


def ok(b, partial=False):
    return "PASS" if b else ("PARTIAL" if partial else "FAIL")


def kinds(s, kind):
    return [f for f in (s or {}).get("findings") or [] if f.get("kind") == kind]


def names(s):
    if not s:
        return []
    out = [(s.get("product") or "", s.get("version") or "")]
    out += [(t.get("name") or "", t.get("version") or "") for t in s.get("technologies") or []]
    out += [(f.get("name") or "" + " " + (f.get("signature_id") or ""), f.get("version") or "") for f in s.get("findings") or []]
    return out


def difflines(d):
    return "; ".join("%s %s%s" % (c["type"], c.get("port", "host"), " [" + ",".join(f["field"] for f in c.get("fields") or []) + "]" if c.get("fields") else "")
                     for c in (d or {}).get("changes") or []) or "no changes"


def run_info(sc):
    return {n: dict(v, requests=reqsummary(sc, n)) for n, v in scans(sc).items()}


# ---------------- A ----------------
def scen_A():
    pm = portmap("custom-network"); sn = scans("A")
    if not sn:
        return
    five = sorted(pm.get(p, p) for p in (2223, 3001, 5673, 8787, 15673)); p8787 = pm.get(8787, 8787)
    a1 = js("A", "a1.json"); got = open_ports(a1)
    add("A", "A1", "scan 1 finds 2223, 3001, 5673, 8787, 15673 open", ok(got == five), "open: %s (%d s)" % (got, sn["a1"]["seconds"]), sn["a1"]["cmd"])
    for cid, (a, b), typ in (("A2", ("a1", "a2"), "service_missing"), ("A3", ("a2", "a3"), "service_returned")):
        d = js("A", "diff-%s-%s.json" % (a, b)); ch = (d or {}).get("changes") or []
        good = len(ch) == 1 and ch[0]["type"] == typ and ch[0].get("port") == p8787
        add("A", cid, "diff %s->%s: exactly one change, %s on 8787" % (a, b, typ), ok(good), difflines(d) if d else "no diff file",
            EX + "asi diff --from %s --to %s --format json --out FILE" % (a, b), json.dumps(ch)[:600])
    add("A", "I1", "quickstart scan of 5 explicit ports takes under 20 s (was 48 s)", ok(sn["a1"]["seconds"] < 20), "a1 %d s, a2 %d s, a3 %d s" % tuple(sn[n]["seconds"] for n in ("a1", "a2", "a3")), sn["a1"]["cmd"],
        " | ".join((rd("A", "a1.scan.log") or "").strip().splitlines()[-3:-1])[:300])
    for cid, name, what in (("A4", "a-range", "range list (8000-9000)"), ("A5", "a-top1000", "preset top1000")):
        if name not in sn:
            continue
        got = open_ports(js("A", name + ".json")); mine = [p for p in got if p in five]
        extra = [p for p in got if p not in five]
        add("A", cid, "%s finds the five quickstart ports" % what, ok(mine == five, partial=bool(mine)),
            "found %s, missed %s%s; %d s, exit %s" % (mine, [p for p in five if p not in mine], (", other open: %s" % extra) if extra else "", sn[name]["seconds"], sn[name]["exit"]),
            sn[name]["cmd"], (rd("A", name + ".scan.log") or "")[-400:])


# ---------------- recognition truth ----------------
#        stack, scenario, run, port, truth label, service re, product re, version re, admin?, outdated names
TRUTH = [
    ("custom-network", "B", "b1", 8888, "httpbin 0.9.2 (HTTP, gunicorn 19.9)", "http", r"gunicorn|httpbin", r"^19\.|^0\.9", False, []),
    ("custom-network", "B", "b1", 15432, "PostgreSQL 16", "postgres", r"postgres", r"^16", False, []),
    ("custom-network", "B", "b1", 5673, "RabbitMQ 3.x AMQP", "amqp", r"rabbitmq", r"^3\.", False, []),
    ("custom-network", "B", "b1", 15673, "RabbitMQ management UI (admin)", "http", r"rabbitmq", None, True, []),
    ("custom-network", "B", "b1", 3001, "Gitea (web)", "http", r"gitea", None, False, []),
    ("custom-network", "B", "b1", 2223, "Gitea SSH (OpenSSH)", "ssh", r"openssh", r"^\d+\.\d", False, []),
    ("custom-network", "B", "b1", 8787, "nginx", "http", r"nginx", r"^1\.\d+", False, []),
    ("modern", "C", "c1", 8080, "WordPress (fresh, installer redirect)", "http", r"wordpress", r"^\d+\.\d", False, []),
    ("modern", "C", "c1", 8081, "phpMyAdmin (admin)", "http", r"phpmyadmin", r"^5\.", True, []),
    ("modern", "C", "c1", 6379, "Redis 7", "redis", r"redis", r"^7\.", False, []),
    ("modern", "C", "c1", 80, "Nginx Proxy Manager default site (openresty)", "http", r"openresty|proxy manager", None, False, []),
    ("modern", "C", "c1", 81, "Nginx Proxy Manager admin UI (admin)", "http", r"proxy manager", None, True, []),
    ("modern", "C", "c1", 443, "Nginx Proxy Manager TLS (rejects handshake w/o known SNI)", "http|ssl|tls", None, None, False, []),
    ("modern-proxy", "D", "d1", 8085, "WordPress behind Traefik+Toxiproxy", "http", r"wordpress", None, False, []),
    ("modern-proxy", "D", "d1", 8086, "Traefik 3.1 dashboard (admin)", "http", r"traefik", r"^3\.1", True, []),
    ("modern-proxy", "D", "d1", 8474, "Toxiproxy 2.12 API", "http", r"toxiproxy", r"^2\.12", False, []),
    ("vulnerable", "E", "e1", 21, "FTP vsftpd", "ftp", r"vsftpd", r"^[23]\.", False, []),
    ("vulnerable", "E", "e1", 8088, "WordPress 4.7 on old PHP (outdated)", "http", r"wordpress", r"^4\.7", False, ["wordpress", "php"]),
    ("vulnerable", "E", "e1", 8089, "Adminer (admin)", "http", r"adminer", r"^\d", True, []),
    ("vulnerable", "E", "e1", 8090, "DVWA", "http", r"dvwa|damn vulnerable", None, False, []),
]
recog = []
import xml.etree.ElementTree as ET


def nmap_export(sc, mode):
    """nmap -oX output as a pseudo export (service, product, version only)"""
    t = rd(sc, "nmap-%s.xml" % mode)
    if not t:
        return None
    try:
        root = ET.fromstring(t)
    except ET.ParseError:
        return None
    out = []
    for p in root.iter("port"):
        st = p.find("state"); sv = p.find("service")
        if st is None or st.get("state") != "open":
            continue
        a = sv.attrib if sv is not None else {}
        name = ("ssl/" if a.get("tunnel") == "ssl" else "") + a.get("name", "")
        out.append({"port": int(p.get("portid")), "state": "open", "status": "active", "service": name, "product": a.get("product", ""),
                    "version": (a.get("version", "") + (" (" + a["extrainfo"] + ")" if a.get("extrainfo") else "")).strip(), "http": None, "technologies": [], "findings": []})
    return {"hosts": [{"services": out}]}


def recognition(recog=recog, source=None):
    for stack, sc, run, port, label, sre, pre, vre, admin, outd in TRUTH:
        exp = js(sc, run + ".json") if source is None else nmap_export(sc, source)
        if exp is None or (port == 21 and rd("E", "ftp-skipped.txt")):
            continue
        s = svc(exp, portmap(stack).get(port, port)); nm = names(s)
        prod = None if pre is None else any(re.search(pre, n, re.I) for n, _ in nm)
        ver = None if vre is None else any(re.search(pre, n, re.I) and re.search(vre, v) for n, v in nm)
        adm = None if not admin else bool(kinds(s, "admin-panel"))
        od = {o: any(re.search(o, json.dumps(f), re.I) for f in kinds(s, "outdated")) for o in outd}
        recog.append({"stack": stack, "port": port, "truth": label, "reported": bool(s),
                      "service": (s or {}).get("service", ""), "service_ok": bool(s) and bool(re.search(sre, s.get("service") or "", re.I)),
                      "product": (s or {}).get("product", ""), "version": (s or {}).get("version", ""),
                      "http": {k: ((s or {}).get("http") or {}).get(k) for k in ("status_code", "title")} if (s or {}).get("http") else None,
                      "server": (((s or {}).get("http") or {}).get("headers") or {}).get("server", ""),
                      "technologies": ["%s %s" % (t["name"], t.get("version") or "") for t in (s or {}).get("technologies") or []],
                      "findings": ["%s[%s]" % (f.get("signature_id"), f.get("kind")) for f in (s or {}).get("findings") or []],
                      "product_recognised": prod, "version_right": ver, "admin_flagged": adm, "outdated_flagged": od})


def rc(stack, port):
    for r in recog:
        if r["stack"] == stack and r["port"] == port:
            return r
    return None


def recog_check(sc, cid, stack, ports, run):
    rows = [rc(stack, p) for p in ports]; rows = [r for r in rows if r]
    if not rows:
        return
    n = len(rows); cmd = scans(sc).get(run, {}).get("cmd", "")
    so = [r for r in rows if r["service_ok"]]; rows_p = [r for r in rows if r["product_recognised"] is not None]; po = [r for r in rows_p if r["product_recognised"]]
    add(sc, cid + "a", "service name right on every port", ok(len(so) == n, partial=bool(so)),
        "%d/%d; wrong: %s" % (len(so), n, ", ".join("%d=%s" % (r["port"], r["service"] or "none") for r in rows if not r["service_ok"]) or "-"), cmd,
        "; ".join('{"port": %d, "service": "%s", "product": "%s", "http": %s}' % (r["port"], r["service"], r["product"], "{...}" if r["http"] else "null") for r in rows if not r["service_ok"]))
    add(sc, cid + "b", "product/application recognised on every port", ok(len(po) == len(rows_p), partial=bool(po)),
        "%d/%d; not recognised: %s" % (len(po), len(rows_p), ", ".join("%d (%s; got '%s')" % (r["port"], r["truth"].split(" (")[0], r["product"]) for r in rows_p if not r["product_recognised"]) or "-"), cmd)
    adm = [r for r in rows if r["admin_flagged"] is not None]
    if adm:
        g = [r for r in adm if r["admin_flagged"]]
        add(sc, cid + "c", "admin interfaces flagged (finding kind admin-panel): " + ", ".join(str(r["port"]) for r in adm), ok(len(g) == len(adm), partial=bool(g)),
            "flagged %d/%d; missing: %s" % (len(g), len(adm), ", ".join("%d findings=%s" % (r["port"], r["findings"] or "[]") for r in adm if not r["admin_flagged"]) or "-"), cmd)


false_changes = {}


def twice_check(sc, run):
    if run + "b" not in scans(sc):
        return
    df = js(sc, "diff-%s-%sb.json" % (run, run)); ch = (df or {}).get("changes") or []
    false_changes[sc] = None if df is None else sum(max(1, len(c.get("fields") or [])) for c in ch)
    add(sc, sc + "T", "two consecutive scans of the unchanged stack give an empty diff", ok(df is not None and not ch), ("%d false changes: " % false_changes[sc] + difflines(df)) if df else "no diff file",
        EX + "asi diff --from %s --to %sb --format json --out FILE" % (run, run), json.dumps(ch)[:600])


# ---------------- B ----------------
def scen_B():
    sn = scans("B")
    if not sn:
        return
    pm = portmap("custom-network"); want = sorted(pm.get(p, p) for p in (2223, 3001, 5673, 8787, 8888, 15432, 15673))
    got = open_ports(js("B", "b1.json"))
    twice_check("B", "b1")
    add("B", "B1", "all 7 ports found open", ok(got == want, partial=bool(got)), "open: %s (%d s)" % (got, sn["b1"]["seconds"]), sn["b1"]["cmd"])
    recog_check("B", "B2", "custom-network", (8888, 15432, 5673, 15673, 3001, 2223, 8787), "b1")
    t = rd("B", "b1.csv")
    if t is not None:
        rows = list(csv.DictReader(t.splitlines()))
        need = "address,hostnames,status,port,protocol,service,product,version,scheme,status_code,title,technologies,findings,tags,first_seen,last_seen".split(",")
        miss = [c for c in need if rows and c not in rows[0]]
        add("B", "B3", "CSV export: one row per service with the contract columns", ok(len(rows) == len(got) and not miss), "%d rows, missing columns: %s" % (len(rows), miss or "none"),
            EX + "asi export --format csv --run b1 --out FILE")


# ---------------- C ----------------
def scen_C():
    sn = scans("C")
    if not sn:
        return
    pm = portmap("modern"); want = sorted(pm.get(p, p) for p in (80, 81, 443, 6379, 8080, 8081)); c1 = js("C", "c1.json"); cmd = sn["c1"]["cmd"]
    got = open_ports(c1)
    remap = {a: b for a, b in pm.items() if a != b}
    twice_check("C", "c1")
    add("C", "C1", "ports 80, 81, 443, 6379, 8080, 8081 found open" + (" (host remap %s)" % remap if remap else ""), ok(got == want, partial=bool(got)), "open: %s (%d s)" % (got, sn["c1"]["seconds"]), cmd)
    recog_check("C", "C2", "modern", (8080, 8081, 6379, 80, 81, 443), "c1")
    wp = svc(c1, pm.get(8080, 8080)); h = (wp or {}).get("http") or {}
    add("C", "C3", "8080: redirect to the WordPress installer is followed and recorded", ok(any("install.php" in u for u in h.get("redirect_chain") or [])),
        "status %s, title '%s', redirect_chain %s" % (h.get("status_code"), h.get("title"), h.get("redirect_chain")), cmd)
    s443 = svc(c1, pm.get(443, 443)); h = (s443 or {}).get("http") or {}; tls = h.get("tls") or {}
    truth = rd("C", "truth-443.txt") or ""
    if "exit=35" in truth or "handshake" in truth.lower():
        add("C", "C4", "443 speaks TLS but rejects the handshake without a configured host (no certificate obtainable): recorded as an open TLS service",
            ok(bool(s443) and re.search("https|ssl|tls", (s443.get("service") or "") + (h.get("scheme") or "")) is not None, partial=bool(s443)),
            "service=%s product='%s' http=%s (contract: `service` stays `http`, `http.scheme` = https)" % ((s443 or {}).get("service"), (s443 or {}).get("product"), json.dumps(h)[:120] if h else "null"), cmd, truth.strip().replace("\n", " | ")[-300:])
    else:
        add("C", "C4", "443: scheme https and TLS certificate fields (subject, issuer, validity, sha256, self_signed)",
            ok(h.get("scheme") == "https" and bool(tls.get("sha256")) and bool(tls.get("not_after")), partial=bool(s443)),
            "service=%s scheme=%s tls=%s" % ((s443 or {}).get("service"), h.get("scheme"), json.dumps(tls)[:300]), cmd, truth.strip().replace("\n", " | ")[-300:])
    ck = {s["port"]: [c["name"] for c in (s.get("http") or {}).get("cookies") or []] for s in services(c1) if s.get("http")}
    hd = {s["port"]: {k: v for k, v in ((s.get("http") or {}).get("headers") or {}).items() if k in ("server", "x-powered-by", "x-served-by", "link", "x-redirect-by", "x-frame-options", "content-security-policy", "strict-transport-security")}
          for s in services(c1) if s.get("http")}
    pma = svc(c1, pm.get(8081, 8081))
    add("C", "C5", "cookies and notable headers collected (phpMyAdmin cookie, X-Powered-By on PHP apps)",
        ok(any("phpMyAdmin" in c for c in ck.get(pm.get(8081, 8081), [])) and "x-powered-by" in hd.get(pm.get(8081, 8081), {}), partial=bool(pma)),
        "cookies %s; headers %s" % (json.dumps(ck), json.dumps(hd)[:500]), cmd)
    notable = {s["port"]: [f["signature_id"] for f in s.get("findings") or [] if f.get("kind") in ("interesting-header", "interesting-cookie")] for s in services(c1)}
    sections["C_notable_findings"] = notable
    nn = sum(len(v) for v in notable.values())
    add("C", "C6", "notable headers/cookies are flagged as findings (kind interesting-header / interesting-cookie), e.g. X-Powered-By PHP, phpMyAdmin cookie", ok(nn > 0),
        "%d such findings on %d services" % (nn, len(notable)), cmd)


# ---------------- D ----------------
def scen_D():
    sn = scans("D")
    if not sn:
        return
    pm = portmap("modern-proxy"); p85 = pm.get(8085, 8085)
    d = {n: js("D", n + ".json") for n in ("d1", "d2", "d3")}
    t = {n: (svc(d[n], p85) or {}).get("http") or {} for n in d}
    rt = {n: {k: t[n].get(k) for k in ("ttfb_ms", "response_time_ms")} for n in d}
    add("D", "D1", "export has a response time field for 8085", ok(t["d1"].get("response_time_ms") is not None), "no latency: %s" % rt["d1"], sn["d1"]["cmd"])
    if "d1b" in sn:
        df = js("D", "diff-d1-d1b.json"); ch = (df or {}).get("changes") or []
        false_changes["D"] = None if df is None else sum(max(1, len(c.get("fields") or [])) for c in ch)
        add("D", "D9", "two scans of the unchanged Traefik stack give an empty diff", ok(df is not None and not ch), difflines(df) if df else "no diff file",
            EX + "asi diff --from d1 --to d1b --format json --out FILE", json.dumps(ch)[:500])
    if "d2" in sn:
        v = t["d2"].get("response_time_ms")
        add("D", "D2", "with 500 ms latency the recorded response time is >= 500 ms", ok(v is not None and v >= 500), "latency run: %s (baseline %s); scan %d s vs %d s" % (rt["d2"], rt["d1"], sn["d2"]["seconds"], sn["d1"]["seconds"]), sn["d2"]["cmd"])
        df = js("D", "diff-d1-d2.json"); ch = (df or {}).get("changes") or []
        add("D", "D3", "diff no-latency -> latency reports no change (only slower)", ok(df is not None and not ch), difflines(df) if df else "no diff file",
            EX + "asi diff --from d1 --to d2 --format json --out FILE", json.dumps(ch)[:500])
    if "d3" in sn:
        s = svc(d["d3"], p85)
        add("D", "D4", "with the timeout toxic (1000 ms) the scan still completes", ok(sn["d3"]["exit"] == 0), "exit %s after %d s (baseline %d s)" % (sn["d3"]["exit"], sn["d3"]["seconds"], sn["d1"]["seconds"]), sn["d3"]["cmd"],
            (rd("D", "d3.scan.log") or "")[-300:])
        add("D", "D5", "8085 is still recorded as an open service when its backend times out", ok(bool(s) and s.get("state") == "open" and s.get("status") == "active", partial=bool(s)),
            "8085: " + (("state=%s status=%s; " % (s.get("state"), s.get("status")) + brief(s)) if s else "not in export"), sn["d3"]["cmd"])
        df = js("D", "diff-d1-d3.json"); ch = (df or {}).get("changes") or []
        bad = [c for c in ch if c.get("port") != p85 or c["type"] != "service_changed"]
        add("D", "D6", "diff no-latency -> timeout: no false change (nothing on 8086/8474, no 'missing'; a changed HTTP answer on 8085 is real)", ok(df is not None and not bad),
            difflines(df) if df else "no diff file", EX + "asi diff --from d1 --to d3 --format json --out FILE", json.dumps(ch)[:700])
    sch = {n: {p: ((svc(d[n], pm.get(p, p)) or {}).get("http") or {}).get("scheme") for p in (8085, 8086, 8474)} for n in d if d[n]}
    s86 = svc(d["d1"], pm.get(8086, 8086)); h86 = (s86 or {}).get("http") or {}
    add("D", "D8", "plain-HTTP ports 8085/8086/8474 are fetched over http in every run (8086 = 301 to /dashboard/, title 'Traefik')",
        ok(all(v == "http" for r in sch.values() for v in r.values())),
        "scheme per run: %s; 8086 in d1: %s status %s title '%s' tls.subject_cn '%s'" % (json.dumps(sch), h86.get("url"), h86.get("status_code"), h86.get("title"), (h86.get("tls") or {}).get("subject_cn")),
        sn["d1"]["cmd"], (rd("D", "truth.txt") or rd("..", "..", "agh", "work", "traefik-truth.txt") or "").replace("\n", " ")[:420])
    recog_check("D", "D7", "modern-proxy", (8085, 8086, 8474), "d1")
    sections["D_response_times"] = rt


# ---------------- E ----------------
def scen_E():
    sn = scans("E")
    if not sn:
        return
    pm = portmap("vulnerable"); e1 = js("E", "e1.json"); cmd = sn["e1"]["cmd"]
    skipped = rd("E", "ftp-skipped.txt")
    want = sorted(pm.get(p, p) for p in ((8088, 8089, 8090) if skipped else (21, 8088, 8089, 8090))); got = open_ports(e1)
    if skipped:
        add("E", "E0", "FTP 21 (vsftpd) scanned", "SKIPPED", cell(skipped, 200) if False else skipped.strip().replace("\n", " | ")[:250])
    twice_check("E", "e1")
    add("E", "E1", "21, 8088, 8089, 8090 found open (passive range 21000-21010 has no listener until a transfer)", ok(all(p in got for p in want), partial=bool(got)),
        "open: %s (%d s)" % (got, sn["e1"]["seconds"]), cmd)
    recog_check("E", "E2", "vulnerable", (21, 8088, 8089, 8090), "e1")
    wp = svc(e1, pm.get(8088, 8088)); r = rc("vulnerable", 8088) or {}
    add("E", "E3", "8088: WordPress version 4.7.x detected", ok(bool(r.get("version_right"))), brief(wp), cmd)
    od = r.get("outdated_flagged") or {}
    allod = {s["port"]: ["%s %s (%s)" % (f.get("name"), f.get("version"), f.get("evidence")) for f in kinds(s, "outdated")] for s in services(e1) if kinds(s, "outdated")}
    add("E", "E4", "outdated finding for WordPress 4.7 on 8088", ok(od.get("wordpress", False)), "outdated findings: %s" % (json.dumps(allod) if allod else "none"), cmd)
    php = ((wp or {}).get("http") or {}).get("headers", {}).get("x-powered-by", "")
    add("E", "E5", "outdated finding for the old PHP on 8088", ok(od.get("php", False)), "x-powered-by on 8088: '%s'; outdated findings on 8088: %s" % (php, allod.get(pm.get(8088, 8088), "none")), cmd)
    rq = requests("E", "e1"); web = {k: v for k, v in rq.items() if k in ("wordpress", "adminer", "dvwa")}
    meth = sorted({m for v in web.values() for m, _ in v})
    paths = {k: sorted({p for _, p in v}) for k, v in web.items()}
    bad = [m for m in meth if m not in ("GET", "HEAD")]
    add("E", "E7", "strictly non-intrusive: web access logs show only GET/HEAD from the scanner", ok(bool(web) and not bad, partial=not web),
        "methods %s; %s" % (meth, "; ".join("%s: %d requests, paths %s" % (k, len(rq[k]), paths[k]) for k in web) or "no access-log lines captured"), cmd,
        " | ".join(l.strip() for f in sorted(glob.glob(os.path.join(RES, "E", "logs", "e1", "*.log"))) for l in open(f, errors="replace") if any(" %s " % m in l for m in bad))[:300])
    sections["E_paths"] = paths


# ---------------- H ----------------
def scen_H():
    sn = scans("H")
    if not sn:
        return
    pm = portmap("custom-network"); rq = {n: reqsummary("H", n) for n in sn}
    full = open_ports(js("H", "h1.json")); h2 = js("H", "h2.json")
    if "h2" in sn:
        add("H", "H1", "recheck after a full scan completes and covers the same services", ok(sn["h2"]["exit"] == 0 and open_ports(h2) == full, partial=sn["h2"]["exit"] == 0),
            "full h1 %d s (%d requests in target logs) vs recheck h2 %d s (%d requests: %s), exit %s; open after recheck %s" % (
                sn["h1"]["seconds"], rq["h1"]["total"], sn["h2"]["seconds"], rq["h2"]["total"], json.dumps(rq["h2"]["per_service"]), sn["h2"]["exit"], open_ports(h2)),
            sn["h2"]["cmd"], (rd("H", "h2.scan.log") or "")[-300:])
        df = js("H", "diff-h1-h2.json"); ch = (df or {}).get("changes") or []
        add("H", "H2", "diff full -> recheck is empty", ok(df is not None and not ch), difflines(df) if df else "no diff file", EX + "asi diff --from h1 --to h2 --format json --out FILE", json.dumps(ch)[:500])
        add("H", "H3", "recheck is faster than the full scan", ok(sn["h2"]["seconds"] < sn["h1"]["seconds"], partial=sn["h2"]["seconds"] == sn["h1"]["seconds"]), "%d s vs %d s" % (sn["h2"]["seconds"], sn["h1"]["seconds"]), sn["h2"]["cmd"])
    if "h3" in sn:
        df = js("H", "diff-h2-h3.json"); ch = (df or {}).get("changes") or []
        good = len(ch) == 1 and ch[0]["type"] == "service_missing" and ch[0].get("port") == pm.get(8787, 8787)
        add("H", "H4", "8787 stopped, recheck again: exactly service_missing 8787", ok(good), "%s; recheck h3 %d s, exit %s" % (difflines(df) if df else "no diff file", sn["h3"]["seconds"], sn["h3"]["exit"]),
            sn["h3"]["cmd"], json.dumps(ch)[:500])
    sections["H_requests"] = rq


# ---------------- F ----------------
def scen_F():
    sn = scans("F")
    if not sn:
        return
    pm = portmap("custom-network"); f0 = js("F", "f0.json"); f1 = js("F", "f1.json")
    ids = lambda e: sorted({(s["port"], f["signature_id"], f["kind"]) for s in services(e) for f in s.get("findings") or [] if f["signature_id"].startswith("agh-")})
    want = sorted([(pm.get(15673, 15673), "agh-rabbitmq-management", "admin-panel"), (pm.get(3001, 3001), "agh-gitea-cookie", "interesting-cookie"), (pm.get(3001, 3001), "agh-gitea", "technology")])
    add("F", "F1", "without the signature file: RabbitMQ UI / Gitea produce no finding (baseline)", "PASS" if not ids(f0) else "FAIL",
        "15673: %s | 3001: %s" % (brief(svc(f0, pm.get(15673, 15673))), brief(svc(f0, pm.get(3001, 3001)))), sn["f0"]["cmd"])
    got = ids(f1)
    add("F", "F2", "with --signatures-dir: the 3 custom findings appear (admin-panel, interesting-cookie, technology)", ok(got == want, partial=bool(got)), "findings: %s" % got, sn.get("f1", {}).get("cmd", ""),
        (rd("F", "f1.scan.log") or "")[-300:] if got != want else "")
    tech = [t for t in (svc(f1, pm.get(3001, 3001)) or {}).get("technologies") or [] if t.get("source") == "signature:agh-gitea"]
    add("F", "F3", "technology signature also yields a technologies entry with source signature:<id>", ok(bool(tech)), json.dumps(tech) if tech else "no such technologies entry on 3001", sn.get("f1", {}).get("cmd", ""))
    df = js("F", "diff-f0-f1.json"); ch = (df or {}).get("changes") or []
    good = bool(ch) and all(c["type"] == "service_changed" and {f["field"] for f in c["fields"]} <= {"findings", "technologies"} for c in ch)
    add("F", "F4", "diff before/after reports only findings/technologies changes on 3001 and 15673", ok(good), difflines(df) if df else "no diff file", EX + "asi diff --from f0 --to f1 --format json --out FILE", json.dumps(ch)[:500])
    bad = rd("F", "f-bad.scan.log") or ""
    add("F", "F5", "a signature using POST is rejected with an error naming the rule", ok("exit=0" not in bad and re.search(r"method|GET|HEAD", bad) is not None), " | ".join(bad.strip().splitlines()[1:4])[:300],
        EX + "asi scan run ... --signatures-dir /work/badsig --wait")


# ---------------- G ----------------
def flat(exp):
    out = {}
    for h in (exp or {}).get("hosts") or []:
        for s in h.get("services") or []:
            ht = s.get("http") or {}
            out[(h["address"], s["port"])] = {"service": s.get("service"), "product": s.get("product"), "version": s.get("version"),
                                              "status_code": ht.get("status_code"), "title": ht.get("title"),
                                              "technologies": sorted("%s %s" % (t["name"], t.get("version") or "") for t in s.get("technologies") or []),
                                              "findings": sorted(f["signature_id"] for f in s.get("findings") or []),
                                              "headers": ht.get("headers"), "cookies": sorted(c["name"] for c in ht.get("cookies") or []),
                                              "tls": (ht.get("tls") or {}).get("sha256")}
    return out


def cmp(a, b, fields):
    d = []
    for k in sorted(set(a) | set(b)):
        if k not in a or k not in b:
            d.append("%s:%s only in %s" % (k[0], k[1], "source" if k in a else "re-export"))
            continue
        for f in fields:
            if a[k].get(f) != b[k].get(f):
                d.append("%s %s: %r -> %r" % (k[1], f, a[k].get(f), b[k].get(f)))
    return d


def scen_G():
    log = rd("G", "import.log")
    if log is None:
        return
    src = js("G", "source.json"); re1 = js("G", "reexport.json")
    add("G", "G1", "JSON export imports into a fresh database", ok("exit=0" in log), " | ".join(log.strip().splitlines()[1:3])[:300], EX + "asi import --format json --file /out/G/source.json")
    a, b = flat(src), flat(re1)
    d = cmp(a, b, ("service", "product", "version", "status_code", "title", "technologies", "findings"))
    add("G", "G2", "re-export equals the source: hosts, services, products, versions, technologies, findings", ok(bool(b) and not d, partial=bool(b)),
        "%d hosts/%d services -> %d hosts/%d services; differences: %s" % (len((src or {}).get("hosts") or []), len(a), len((re1 or {}).get("hosts") or []), len(b), "; ".join(d[:6]) or "none"),
        EX + "asi export --format json --out /out/G/reexport.json")
    d2 = cmp(a, b, ("headers", "cookies", "tls"))
    add("G", "G3", "HTTP details (headers, cookie names, TLS) survive the round trip", ok(bool(b) and not d2, partial=bool(b)), "differences: %s" % ("; ".join(d2[:4])[:400] or "none"), EX + "asi export --format json --out /out/G/reexport.json")
    clog = rd("G", "import-csv.log") or ""; c = flat(js("G", "reexport-from-csv.json"))
    d3 = cmp(a, c, ("service", "product", "version", "status_code", "title", "technologies"))
    add("G", "G4", "CSV export imports into a fresh database with the same services/products/technologies", ok("exit=0" in clog and bool(c) and not d3, partial="exit=0" in clog and bool(c)),
        "%s; %d -> %d services; differences: %s" % (" | ".join(clog.strip().splitlines()[1:2])[:160], len(a), len(c), "; ".join(d3[:5])[:400] or "none"), EX + "asi import --format csv --file /out/G/source.csv")


recognition()
for f in (scen_A, scen_B, scen_C, scen_D, scen_E, scen_F, scen_G, scen_H):
    try:
        f()
    except Exception as e:  # a broken scenario must not hide the others
        add(f.__name__[-1], f.__name__[-1] + "!", "analysis of scenario", "FAIL", "analysis error: %r" % e)

scen_status = {}
for c in checks:
    scen_status[c['scenario']] = ''
for sc in scen_status:
    st = [c["status"] for c in checks if c["scenario"] == sc and c["status"] != "SKIPPED"]
    scen_status[sc] = "PASS" if all(s == "PASS" for s in st) else ("FAIL" if all(s == "FAIL" for s in st) else "PARTIAL")

score = {
    "products_recognised": [sum(1 for r in recog if r["product_recognised"]), sum(1 for r in recog if r["product_recognised"] is not None)],
    "service_names_right": [sum(r["service_ok"] for r in recog), len(recog)],
    "versions_right": [sum(1 for r in recog if r["version_right"]), sum(1 for r in recog if r["version_right"] is not None)],
    "admin_panels_flagged": [sum(1 for r in recog if r["admin_flagged"]), sum(1 for r in recog if r["admin_flagged"] is not None)],
    "outdated_flagged": [sum(sum(r["outdated_flagged"].values()) for r in recog), sum(len(r["outdated_flagged"]) for r in recog)],
}
def mkscore(rg):
    return {"products_recognised": [sum(1 for r in rg if r["product_recognised"]), sum(1 for r in rg if r["product_recognised"] is not None)],
            "service_names_right": [sum(r["service_ok"] for r in rg), len(rg)],
            "versions_right": [sum(1 for r in rg if r["version_right"]), sum(1 for r in rg if r["version_right"] is not None)],
            "admin_panels_flagged": [sum(1 for r in rg if r["admin_flagged"]), sum(1 for r in rg if r["admin_flagged"] is not None)],
            "outdated_flagged": [sum(sum(r["outdated_flagged"].values()) for r in rg), sum(len(r["outdated_flagged"]) for r in rg)]}


nmap = {}
for mode in ("light", "default"):
    rg = []; recognition(rg, mode)
    if rg:
        nmap[mode] = {"score": mkscore(rg), "recognition": rg,
                      "seconds": {sc: int(l.split("\t")[1]) for sc in "BCDE" for l in (rd(sc, "nmap.tsv") or "").splitlines() if l.startswith(mode + "\t")}}
sections["nmap"] = nmap
sections["false_changes"] = false_changes
defects = [c for c in checks if c["status"] not in ("PASS", "SKIPPED")]
notable_counts = {}
for stack, sc, run in (("custom-network", "B", "b1"), ("modern", "C", "c1"), ("modern-proxy", "D", "d1"), ("vulnerable", "E", "e1")):
    e = js(sc, run + ".json")
    if e:
        notable_counts[stack] = {k: sorted("%d:%s" % (s["port"], f["signature_id"]) for s in services(e) for f in kinds(s, k)) for k in ("interesting-header", "interesting-cookie")}
sections["notable_findings_per_stack"] = notable_counts
runs = {sc: run_info(sc) for sc in "ABCDEFGH" if scans(sc)}
summary = {"schema": "asi.agh-eval/v1", "product_commit": (rd("commit.txt") or "").strip(), "connection_mode": "host ports via host.docker.internal",
           "port_remaps": {s: {a: b for a, b in portmap(s).items() if a != b} for s in ("custom-network", "modern", "modern-proxy", "vulnerable")},
           "scenarios": scen_status, "score": score, "checks": checks, "defects": defects, "recognition": recog, "runs": runs, "extra": sections}
with open(os.path.join(RES, "summary.json"), "w") as f:
    json.dump(summary, f, indent=1)


def cell(s, n=150):
    s = str(s).replace("|", "/").replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


L = ["# ASI vs the organisers' sample environments (lab-agh)",
     "Commit `%s`; target `host.docker.internal` (host ports published on 127.0.0.1; remaps: %s). Scenarios: %s. Score: products %d/%d, service names %d/%d, versions %d/%d, admin panels %d/%d, outdated %d/%d. Per-run durations and request counts: `summary.json` (`runs`)." % (
         summary["product_commit"][:7], json.dumps({k: v for k, v in summary["port_remaps"].items() if v}) or "none", " ".join("%s=%s" % kv for kv in sorted(scen_status.items())),
         *score["products_recognised"], *score["service_names_right"], *score["versions_right"], *score["admin_panels_flagged"], *score["outdated_flagged"])]
GROUPS = [
    ("No built-in findings: admin panels, outdated versions and notable headers/cookies are never flagged (only custom signatures produce findings)", ("B2c", "C2c", "C6", "D7c", "E2c", "E4", "E5")),
    ("Applications are not recognised as product/technology even when the title names them; versions missing (WordPress 4.7)", ("B2b", "C2b", "D7b", "E2b", "E3")),
    ("Service not identified: nmap runs with `--version-light` (PostgreSQL empty; plain `nmap -sV` says postgresql) and a port nmap calls tcpwrapped gets no HTTP probe (httpbin)", ("B2a", "C2a", "D7a", "E2a")),
    ("Ports that answer both TLS and plain HTTP (Traefik) are recorded over https: wrong content (404 instead of the dashboard) and false changes because the default cert changes on restart", ("D8", "D3", "D6")),
    ("Not strictly GET/HEAD: nmap service detection sends OPTIONS and non-HTTP probes to ports it cannot identify", ("E7",)),
    ("Preset top1000 does not contain most of the organisers' ports", ("A5",)),
]
for sc in "ABCDEFGH":
    cs = [c for c in checks if c["scenario"] == sc]
    if not cs:
        continue
    dur = ", ".join("%s %ds/%s req" % (n, v["seconds"], v["requests"]["total"]) for n, v in runs.get(sc, {}).items())
    L += ["", "| %s: %s (%s) | Observed | Result |" % (TITLES[sc], scen_status[sc], dur or "no scan"), "|---|---|---|"]
    ps = [c for c in cs if c["status"] == "PASS"]
    if len(ps) == 1:
        L.append("| %s %s | %s | PASS |" % (ps[0]["id"], cell(ps[0]["expectation"], 110), cell(ps[0]["observed"], 230)))
    elif ps:
        L.append("| %s | %s | PASS |" % (cell("; ".join("%s %s" % (c["id"], cell(c["expectation"], 60)) for c in ps), 420), cell("; ".join("%s: %s" % (c["id"], cell(c["observed"], 110)) for c in ps), 700)))
    L += ["| %s %s | %s | %s |" % (c["id"], cell(c["expectation"], 110), cell(c["observed"], 260), c["status"]) for c in cs if c["status"] != "PASS"]
L += ["## Defects"]
byid = {c["id"]: c for c in defects}; used = set(); n = 0
grouped = [(t, [byid[i] for i in ids if i in byid]) for t, ids in GROUPS]
grouped += [(c["expectation"], [c]) for c in defects if not any(c["id"] in ids for _, ids in GROUPS)]
for title, cs in grouped:
    if not cs:
        continue
    n += 1; c = next((x for x in cs if x["evidence"]), cs[0])
    L.append("%d. **%s** (checks %s). Expected: %s. Happened: %s. Command: `%s`. Output: `%s`" % (
        n, title, ", ".join(x["id"] for x in cs), cell(c["expectation"], 110), cell("; ".join("%s: %s" % (x["id"], cell(x["observed"], 150)) for x in cs), 420), cell(c["command"], 190), cell(c["evidence"] or c["observed"], 230)))
if not defects:
    L.append("None.")
L += ["## Recognition table (svc/prod/ver/admin/outdated: Y, N, - = not applicable)", "| Port | Truth | ASI: service / product version | Technologies | Findings | svc/prod/ver/admin/outdated |", "|---|---|---|---|---|---|"]
yn = lambda v: "-" if v is None else ("Y" if v else "N")
for r in recog:
    od = "-" if not r["outdated_flagged"] else "%d/%d" % (sum(r["outdated_flagged"].values()), len(r["outdated_flagged"]))
    L.append("| %s | %s | %s | %s | %s | %s/%s/%s/%s/%s |" % (r["port"], cell(r["truth"], 45), cell("%s / %s %s" % (r["service"] or "none", r["product"] or "-", r["version"]), 60) if r["reported"] else "not reported",
                                                          cell(", ".join(r["technologies"]) or "-", 70), cell(", ".join(r["findings"]) or "-", 80),
                                                          yn(r["service_ok"]), yn(r["product_recognised"]), yn(r["version_right"]), yn(r["admin_flagged"]), od))
with open(os.path.join(RES, "summary.md"), "w") as f:
    f.write("\n".join(L) + "\n")
if len(L) > 80:
    print("WARNING: summary.md has %d lines (limit 80)" % len(L))
print("summary: %s | score %s | %d lines in summary.md" % (" ".join("%s=%s" % kv for kv in sorted(scen_status.items())), json.dumps(score), len(L)))
