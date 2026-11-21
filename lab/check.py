#!/usr/bin/env python3
"""Compare the product's exports and diffs (docs/contracts.md) with the lab truth in expected.json.

usage: check.py expected.json <out-dir>     exit 0 = all expectations hold, 1 = failures listed on stdout
"""
import csv
import json
import os
import sys

fails = []


def fail(where, msg):
    fails.append(f"{where}: {msg}")


def load(out, name):
    path = os.path.join(out, name)
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:  # noqa: BLE001
        fail(name, f"cannot read: {e}")
        return None


def eq(where, key, got, want):
    if got != want:
        fail(where, f"{key}: got {got!r}, want {want!r}")


def check_http(where, got, want):
    got = got or {}
    for key in ("scheme", "status_code", "title", "favicon_sha256"):
        if key in want:
            eq(where, f"http.{key}", got.get(key), want[key])
    names = {c.get("name") for c in got.get("cookies") or []}
    for name in want.get("cookies_include", []):
        if name not in names:
            fail(where, f"http.cookies: missing {name!r} (got {sorted(n for n in names if n)})")
    headers = {str(k).lower(): v for k, v in (got.get("headers") or {}).items()}
    for name, sub in want.get("headers_include", {}).items():
        val = headers.get(name)
        val = " ".join(val) if isinstance(val, list) else (val or "")
        if sub not in val:
            fail(where, f"http.headers[{name}]: got {val!r}, want it to contain {sub!r}")
    if "redirect_contains" in want:
        chain = " ".join(str(u) for u in got.get("redirect_chain") or [])
        if want["redirect_contains"] not in chain:
            fail(where, f"http.redirect_chain: {chain!r} does not contain {want['redirect_contains']!r}")
    if "tls" in want:
        tls = got.get("tls") or {}
        for key in ("subject_cn", "self_signed"):
            if key in want["tls"]:
                eq(where, f"http.tls.{key}", tls.get(key), want["tls"][key])
        if "sha256" in want["tls"]:
            eq(where, "http.tls.sha256", str(tls.get("sha256", "")).replace(":", "").lower(), want["tls"]["sha256"])
        for san in want["tls"].get("sans_include", []):
            if san not in (tls.get("sans") or []):
                fail(where, f"http.tls.sans: missing {san!r}")


def has_item(items, want):
    return any(all(str(i.get(k, "")) == str(v) for k, v in want.items()) for i in items or [])


def check_service(where, got, want):
    if "service" in want:
        eq(where, "service", got.get("service"), want["service"])
    if "product_contains" in want and want["product_contains"].lower() not in str(got.get("product", "")).lower():
        fail(where, f"product: got {got.get('product')!r}, want it to contain {want['product_contains']!r}")
    if "http" in want:
        check_http(where, got.get("http"), want["http"])
    for t in want.get("technologies_include", []):
        if not has_item(got.get("technologies"), t):
            fail(where, f"technologies: missing {t} (got {got.get('technologies')})")
    for f in want.get("findings_include", []):
        if not has_item(got.get("findings"), f):
            fail(where, f"findings: missing {f} (got {got.get('findings')})")


def check_export(out, spec):
    doc = load(out, spec["file"])
    if doc is None:
        return
    name = spec["file"]
    eq(name, "schema", doc.get("schema"), "asi.export/v1")
    hosts = {h.get("address"): h for h in doc.get("hosts") or []}
    if spec.get("only_hosts"):
        for extra in sorted(set(hosts) - set(spec["hosts"])):
            fail(name, f"unexpected host {extra} (false positive or excluded address)")
    for addr, want in spec["hosts"].items():
        where = f"{name} {addr}"
        host = hosts.get(addr)
        if host is None:
            fail(where, "host missing")
            continue
        eq(where, "status", host.get("status"), want["status"])
        for tag in want.get("tags_include", []):
            if tag not in (host.get("tags") or []):
                fail(where, f"tags: missing {tag!r}")
        if "notes" in want:
            eq(where, "notes", host.get("notes"), want["notes"])
        services = {
            f"{s.get('port')}/{s.get('protocol')}": s for s in host.get("services") or [] if s.get("state", "open") == "open"
        }
        if want.get("only_services"):
            for extra in sorted(set(services) - set(want.get("services", {}))):
                fail(where, f"unexpected open service {extra}")
        for key, svc_want in want.get("services", {}).items():
            if key not in services:
                fail(where, f"service {key} missing (got {sorted(services)})")
                continue
            check_service(f"{where} {key}", services[key], svc_want)


def check_diff(out, spec):
    doc = load(out, spec["file"])
    if doc is None:
        return
    name = spec["file"]
    eq(name, "schema", doc.get("schema"), "asi.diff/v1")
    changes = doc.get("changes") or []
    for c in changes:
        if c.get("address") not in spec["only_addresses"]:
            fail(name, f"unexpected change on a stable host: {c.get('type')} {c.get('address')}:{c.get('port')}")
    for want in spec["must"]:
        hit = [
            c
            for c in changes
            if c.get("type") == want["type"]
            and c.get("address") == want["address"]
            and ("port" not in want or c.get("port") == want["port"])
        ]
        if not hit:
            fail(name, f"missing change {want}")
            continue
        fields = {f.get("field") for c in hit for f in c.get("fields") or []}
        for field in want.get("fields_include", []):
            if field not in fields:
                fail(name, f"{want['type']} {want['address']}:{want.get('port')}: field {field!r} not reported (got {sorted(fields)})")


def check_csv(out, spec):
    path = os.path.join(out, spec["file"])
    try:
        with open(path, newline="") as f:
            rows = list(csv.DictReader(f))
    except Exception as e:  # noqa: BLE001
        fail(spec["file"], f"cannot read: {e}")
        return
    if len(rows) < spec["min_rows"]:
        fail(spec["file"], f"{len(rows)} rows, want at least {spec['min_rows']}")
    cols = set(rows[0].keys()) if rows else set()
    for col in spec["columns_include"]:
        if col not in cols:
            fail(spec["file"], f"missing column {col!r}")


def main():
    with open(sys.argv[1]) as f:
        expected = json.load(f)
    out = sys.argv[2]
    check_export(out, expected["export_1"])
    check_export(out, expected["export_3"])
    check_diff(out, expected["diff_1_2"])
    check_diff(out, expected["diff_2_3"])
    check_csv(out, expected["csv"])
    for line in fails:
        print("FAIL", line)
    print(f"LAB: {'FAIL' if fails else 'PASS'} ({len(fails)} failures)")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
