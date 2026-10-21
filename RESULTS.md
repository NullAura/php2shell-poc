# Verification result

Date: 2026-10-21

Target:

```text
PHP 8.4.26 NTS mod_php
Apache 2.4.68 prefork, one worker
linux/amd64 official php:8.4.26-apache libphp.so
display_errors=On, memory_limit=8M
```

Command:

```bash
python3 validation/php2shell-official/poc.py \
  http://127.0.0.1:8088/index.php
```

Proof:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The proof file is `out/p1`.
The script succeeded on three independently recreated target containers.

## Chain

1. Leak the 2 MiB Zend MM chunk base through the forged stale `PS(id)` length
   and the `Set-Cookie` out-of-bounds read.
2. Grow the same read to 512 KiB and place 150 one-element arrays in the
   window. The resulting real HashTables expose `pDestructor`; 235 copies of
   the same code pointer were observed.
3. Request A OOMs while the session reference is live, leaving
   `PS(http_session_vars)` dangling for the next pre-RINIT request.
4. Request B reclaims that reference with a live 31-byte field value. The
   calibrated A/B shapes put the forged `IS_REFERENCE` exactly at the stale
   pointer.
5. Destruction reaches the fake HashTable's `pDestructor`, set to
   `zif_system`. The command is `id>/out/p1`.

The terminal call intentionally crashes the worker after writing the proof;
the crash is not used as success evidence.
