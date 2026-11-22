#!/usr/bin/env python3
"""Misbehaving HTTP targets for the reliability harness: one behaviour per address.

    hostile.py serve      add 172.29.0.10-26 and .40 to eth0 and serve every behaviour in TARGETS
    hostile.py vanish     a normal page on :80; when /tmp/armed exists, answer the first HTTP request
                          that is not the product's own probe (i.e. nmap -sV) and then exit, so the host
                          is gone before the HTTP probe reaches it
    hostile.py toggle     :8080 always open, :80 open unless /tmp/close80 exists; the host stays up (port-flap)
    hostile.py expected   print TARGETS as JSON (used by check.py)

Every response is deterministic (no Date header, fixed bytes), so two scans must not differ.
Every request is logged as one JSON line to /out/requests.log.
"""
import asyncio
import json
import os
import subprocess
import sys
import time

NET = "172.29.0"
OFFSITE = f"{NET}.40"  # redirect destination that is NOT in the targets file
HOLD = 900             # upper bound for "forever" behaviours, seconds
TARGETS = {            # last octet -> (port, behaviour)
    10: (80, "bigbody"),        # 10 MiB body
    11: (80, "loop"),           # endless redirect chain to itself
    12: (80, "offsite"),        # redirect to another host (must be recorded, not followed)
    13: (80, "slowloris"),      # response headers trickled one byte per second
    14: (80, "silent"),         # accepts, reads, never answers
    15: (80, "slowbody"),       # 1 kB/s body forever
    16: (443, "badtls"),        # garbage in place of a ServerHello on 443
    17: (80, "garbage"),        # binary garbage on port 80
    18: (80, "xss"),            # <script> in the title
    19: (80, "longtitle"),      # 5 kB title
    20: (80, "latin2"),         # ISO-8859-2 title
    21: (80, "brokenutf"),      # invalid UTF-8 bytes in the title
    22: (80, "manyheaders"),    # 500 different response headers
    23: (80, "crlfnul"),        # header values with CR, LF and NUL
    24: (80, "chunked"),        # chunked encoding that never terminates
    25: (80, "http10"),         # HTTP/1.0 without Content-Length
    26: (80, "bigcookie"),      # Set-Cookie with a 4 kB name
}
GARBAGE = bytes((i * 131 + 7) % 256 for i in range(4096))
LOG = "/out/requests.log"


def log(**kw):
    kw["t"] = round(time.time(), 3)
    try:
        with open(LOG, "a") as f:
            f.write(json.dumps(kw) + "\n")
    except OSError:
        pass


def page(title, body=b"ok"):
    return b"<html><head><title>" + title + b"</title></head><body>" + body + b"</body></html>"


def response(html, extra=(), ctype=b"text/html; charset=utf-8", proto=b"HTTP/1.1", length=True, status=b"200 OK"):
    lines = [proto + b" " + status, b"Server: hostile", b"Content-Type: " + ctype, b"Connection: close", *extra]
    if length:
        lines.append(b"Content-Length: %d" % len(html))
    return b"\r\n".join(lines) + b"\r\n\r\n", html


async def read_request(reader):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
    except Exception:
        return None, "", ""
    first = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
    ua = ""
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"user-agent:"):
            ua = line.split(b":", 1)[1].strip().decode("latin1", "replace")
    return head, first, ua


async def drip(writer, chunks, interval):
    end = time.time() + HOLD
    for c in chunks:
        if time.time() > end:
            break
        writer.write(c)
        await writer.drain()
        await asyncio.sleep(interval)


def forever(chunk):
    while True:
        yield chunk


async def handle(reader, writer, kind, addr):
    try:
        if kind == "garbage":
            log(addr=addr, kind=kind, event="connect")
            writer.write(GARBAGE)
            await writer.drain()
            return
        if kind == "badtls":
            hello = await asyncio.wait_for(reader.read(4096), 30)
            log(addr=addr, kind=kind, event="connect", bytes=len(hello))
            writer.write(b"\x16\x03\x03\x00\x40" + GARBAGE[:64])
            await writer.drain()
            return
        head, first, ua = await read_request(reader)
        log(addr=addr, kind=kind, request=first, ua=ua)
        if head is None:
            return
        is_head = first.startswith("HEAD")
        path = first.split(" ")[1] if first.count(" ") >= 2 else "/"
        if kind == "silent":
            await asyncio.sleep(HOLD)
            return
        if kind == "slowloris":
            data = b"HTTP/1.1 200 OK\r\nServer: hostile\r\n" + b"".join(b"X-Slow-%d: drip\r\n" % i for i in range(1000))
            await drip(writer, (data[i:i + 1] for i in range(len(data))), 1)
            return
        if kind == "slowbody":
            h, _ = response(b"", length=False)
            writer.write(h + page(b"slow body", b""))
            await drip(writer, forever(b"s" * 1024), 1)
            return
        if kind == "chunked":
            h, _ = response(b"", extra=[b"Transfer-Encoding: chunked"], length=False)
            first_chunk = page(b"chunked forever", b"")
            writer.write(h + b"%x\r\n" % len(first_chunk) + first_chunk + b"\r\n")
            await drip(writer, forever(b"10\r\n" + b"c" * 16 + b"\r\n"), 2)
            return
        if kind == "loop":
            n = int(path.rsplit("=", 1)[1]) + 1 if "=" in path and path.rsplit("=", 1)[1].isdigit() else 1
            h, b = response(b"", extra=[b"Location: http://%s/loop?n=%d" % (addr.encode(), n)], status=b"302 Found")
        elif kind == "offsite":
            h, b = response(b"", extra=[b"Location: http://%s/offsite" % OFFSITE.encode()], status=b"302 Found")
        elif kind == "normal":
            h, b = response(page(b"offsite page - must not be fetched"))
        elif kind == "bigbody":
            h, b = response(page(b"ten mebibytes", b"A" * (10 << 20)))
        elif kind == "xss":
            h, b = response(page(b"<script>alert(1)</script>"))
        elif kind == "longtitle":
            h, b = response(page(b"T" * 5000))
        elif kind == "latin2":
            h, b = response(page("Zażółć gęślą jaźń".encode("iso-8859-2")), ctype=b"text/html; charset=iso-8859-2")
        elif kind == "brokenutf":
            h, b = response(page(b"broken \xff\xfe \xc3\x28 \xed\xa0\x80 end"))
        elif kind == "manyheaders":
            h, b = response(page(b"many headers"), extra=[b"X-Hostile-%03d: value-%03d" % (i, i) for i in range(500)])
        elif kind == "crlfnul":
            h, b = response(page(b"crlf nul"), extra=[b"X-Nul: a\x00b", b"X-Cr: a\rb", b"X-Lf: a\nX-Injected: yes"])
        elif kind == "http10":
            h, b = response(page(b"http 1.0 no length"), proto=b"HTTP/1.0", length=False)
        elif kind == "bigcookie":
            h, b = response(page(b"big cookie"), extra=[b"Set-Cookie: " + b"c" * 4096 + b"=v; Path=/"])
        else:
            h, b = response(page(b"unknown"))
        writer.write(h if is_head else h + b)
        await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def serve():
    for octet in list(TARGETS) + [40]:
        subprocess.run(["ip", "addr", "add", f"{NET}.{octet}/24", "dev", "eth0"], check=False)
    for octet, (port, kind) in TARGETS.items():
        addr = f"{NET}.{octet}"
        await asyncio.start_server(lambda r, w, k=kind, a=addr: handle(r, w, k, a), addr, port, backlog=64)
    await asyncio.start_server(lambda r, w: handle(r, w, "normal", OFFSITE), OFFSITE, 80)
    open("/tmp/ready", "w").close()
    print(f"hostile: {len(TARGETS)} behaviours", flush=True)
    await asyncio.Event().wait()


async def vanish_handle(reader, writer):
    head, first, ua = await read_request(reader)
    armed = os.path.exists("/tmp/armed")
    log(addr="vanish", request=first, ua=ua, armed=armed)
    if head is None:
        writer.close()
        return
    h, b = response(page(b"Vanishing host"), extra=[b"X-Powered-By: PHP/7.4.3"])
    writer.write(h if first.startswith("HEAD") else h + b)
    await writer.drain()
    writer.close()
    if armed and not ua.startswith("asi-discovery"):
        os.remove("/tmp/armed")
        log(addr="vanish", event="exit")
        os._exit(0)


async def vanish():
    await asyncio.start_server(vanish_handle, "0.0.0.0", 80)
    print("vanish: up", flush=True)
    await asyncio.Event().wait()


async def toggle():
    """Port 8080 always open; port 80 open unless /tmp/close80 exists (checked twice a second). The host stays up."""
    async def handler(reader, writer):
        head, first, ua = await read_request(reader)
        if head is not None:
            hd, body = response(page(b"Toggle host"))
            writer.write(hd if first.startswith("HEAD") else hd + body)
            await writer.drain()
        writer.close()
    await asyncio.start_server(handler, "0.0.0.0", 8080)
    srv = None
    print("toggle: up", flush=True)
    while True:
        want = not os.path.exists("/tmp/close80")
        if want and srv is None:
            srv = await asyncio.start_server(handler, "0.0.0.0", 80)
        elif not want and srv is not None:
            srv.close()
            await srv.wait_closed()
            srv = None
        await asyncio.sleep(0.5)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "serve":
        asyncio.run(serve())
    elif cmd == "vanish":
        asyncio.run(vanish())
    elif cmd == "toggle":
        asyncio.run(toggle())
    elif cmd == "expected":
        print(json.dumps({f"{NET}.{o}": {"port": p, "kind": k} for o, (p, k) in TARGETS.items()}))
