#!/usr/bin/env python3
"""Simulated /18: about 3% of 10.99.0.0/18 is "live", each live address gets one service profile.

Addresses are added to eth0 so only live ones answer ARP. Writes the ground truth to /out/truth.json and one line per
second to /out/rate.csv (epoch, tcp_syn, icmp_echo, http_requests) so the scan rate can be checked from the target side.

    responder.py serve            start everything (container entrypoint)
    responder.py down <percent>   take a deterministic share of live hosts offline (stage 2)
    responder.py up               bring them back (stage 3)
"""
import asyncio
import hashlib
import ipaddress
import json
import os
import ssl
import subprocess
import sys
import time

NET = ipaddress.ip_network(os.environ.get("BIGNET", "10.99.0.0/18"))
LIVE_SHARE = float(os.environ.get("LIVE_SHARE", "0.03"))
RESERVED = 16  # .0-.15 of the first /24: gateway, scanner, database, this container
STATE = "/out/down.json"

PROFILES = {
    "wordpress": {80: "wp"},
    "drupal": {8080: "drupal"},
    "admin": {80: "admin", 443: "admin-tls"},
    "staging": {8000: "staging"},
    "camera": {80: "camera"},
    "plain": {80: "plain"},
    "ssh": {22: "ssh"},
    "redis": {6379: "redis"},
    "web+ssh": {80: "plain", 22: "ssh"},
}
ORDER = sorted(PROFILES)
http_requests = 0


def h(addr, salt=""):
    return int(hashlib.sha256(f"{salt}{addr}".encode()).hexdigest(), 16)


def live_hosts():
    out = {}
    for i, a in enumerate(NET.hosts()):
        if i < RESERVED:
            continue
        if (h(a) % 10000) < LIVE_SHARE * 10000:
            out[str(a)] = ORDER[h(a, "p") % len(ORDER)]
    return out


def page(kind, addr):
    extra, status, body = [], "200 OK", ""
    if kind == "wp":
        extra = ["Set-Cookie: wordpress_test_cookie=WP%20Cookie%20check; Path=/"]
        body = '<html><head><title>Campus Blog</title><meta name="generator" content="WordPress 6.4.2"></head><body>blog</body></html>'
    elif kind == "drupal":
        extra = ["X-Generator: Drupal 10 (https://www.drupal.org)"]
        body = "<html><head><title>Campus Portal</title></head><body>portal</body></html>"
    elif kind.startswith("admin"):
        extra = ["X-Powered-By: PHP/7.4.3", "Set-Cookie: PHPSESSID=bignet0001; Path=/; HttpOnly"]
        body = '<html><head><title>Admin Panel - Sign in</title></head><body><form><input type="password" name="password"></form></body></html>'
    elif kind == "staging":
        extra = ["X-Environment: staging", "X-Debug-Token: 4f1c2a"]
        body = "<html><head><title>[STAGING] Rekrutacja</title></head><body>staging</body></html>"
    elif kind == "camera":
        body = "<html><head><title>NETCAM Web Client</title></head><body>Firmware V5.4.1 build 190212</body></html>"
    else:
        body = f"<html><head><title>Host {addr}</title></head><body>ok</body></html>"
    return status, extra, body


async def handle(reader, writer, kind, addr):
    global http_requests
    try:
        if kind == "ssh":
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            await writer.drain()
            await asyncio.sleep(1)
        elif kind == "redis":
            await asyncio.wait_for(reader.read(512), 5)
            writer.write(b"-NOAUTH Authentication required.\r\n")
            await writer.drain()
        else:
            while True:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 10)
                http_requests += 1
                path = head.split(b" ", 2)[1].decode("latin1", "replace") if head.count(b" ") >= 2 else "/"
                status, extra, body = page(kind, addr)
                if path == "/favicon.ico":
                    status, extra, body = "404 Not Found", [], ""
                data = body.encode()
                lines = [f"HTTP/1.1 {status}", "Server: nginx/1.27.5", "Content-Type: text/html; charset=utf-8",
                         f"Content-Length: {len(data)}", "Connection: close", *extra, "", ""]
                writer.write("\r\n".join(lines).encode() + (b"" if head.startswith(b"HEAD") else data))
                await writer.drain()
                break
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


def sh(*cmd):
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def counter(chain_match):
    out = subprocess.run(["iptables", "-L", "INPUT", "-v", "-x", "-n"], capture_output=True, text=True).stdout
    for line in out.splitlines():
        if chain_match in line:
            return int(line.split()[0])
    return 0


async def rate_log():
    sh("iptables", "-I", "INPUT", "-p", "tcp", "--syn", "-m", "comment", "--comment", "syncount")
    sh("iptables", "-I", "INPUT", "-p", "icmp", "--icmp-type", "echo-request", "-m", "comment", "--comment", "echocount")
    last = (counter("syncount"), counter("echocount"), 0)
    with open("/out/rate.csv", "w") as f:
        f.write("epoch,tcp_syn,icmp_echo,http_requests\n")
        while True:
            await asyncio.sleep(1)
            now = (counter("syncount"), counter("echocount"), http_requests)
            f.write(f"{int(time.time())},{now[0]-last[0]},{now[1]-last[1]},{now[2]-last[2]}\n")
            f.flush()
            last = now


async def serve():
    hosts = live_hosts()
    prefix = NET.prefixlen
    for addr in hosts:
        sh("ip", "addr", "add", f"{addr}/{prefix}", "dev", "eth0")
    tls = None
    if os.path.exists("/tls/cert.pem"):
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain("/tls/cert.pem", "/tls/key.pem")
    servers = 0
    for addr, profile in hosts.items():
        for port, kind in PROFILES[profile].items():
            ctx = tls if kind == "admin-tls" else None
            if kind == "admin-tls" and tls is None:
                continue
            await asyncio.start_server(lambda r, w, k=kind, a=addr: handle(r, w, k, a), addr, port, ssl=ctx, backlog=64)
            servers += 1
    truth = {a: {"profile": p, "ports": sorted(port for port, k in PROFILES[p].items() if k != "admin-tls" or tls)}
             for a, p in hosts.items()}
    with open("/out/truth.json", "w") as f:
        json.dump({"network": str(NET), "addresses": NET.num_addresses, "live": len(hosts), "hosts": truth}, f)
    print(f"bignet: {len(hosts)} live hosts, {servers} listeners on {NET}", flush=True)
    open("/out/ready", "w").close()
    await rate_log()


def toggle(percent):
    hosts = sorted(live_hosts())
    prefix = NET.prefixlen
    down = [a for a in hosts if h(a, "d") % 100 < percent]
    for a in down:
        sh("ip", "addr", "del", f"{a}/{prefix}", "dev", "eth0")
    json.dump(down, open(STATE, "w"))
    print(f"down: {len(down)} hosts")


def restore():
    prefix = NET.prefixlen
    down = json.load(open(STATE)) if os.path.exists(STATE) else []
    for a in down:
        sh("ip", "addr", "add", f"{a}/{prefix}", "dev", "eth0")
    json.dump([], open(STATE, "w"))
    print(f"up: {len(down)} hosts")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "serve":
        asyncio.run(serve())
    elif cmd == "down":
        toggle(int(sys.argv[2]))
    elif cmd == "up":
        restore()
