# Distro profile table - LiteSpeed lsphp82 8.2.34 (official -dbg symbols)

All build-ids verified against the matching stripped binaries from
rpms.litespeedtech.com. Deltas computed as zval_ptr_dtor - zend_call_function.

| Distro | zend_call_function | zval_ptr_dtor | delta_call |
|--------|--------------------|---------------|------------|
| bookworm | 0x511ae0 | 0x51e410 | 0xc930 |
| noble    | 0x533ba0 | 0x540a90 | 0xcef0 |
| jammy    | 0x51fb90 | 0x52cbf0 | 0xd060 |

## How to fingerprint the live target's distro sub-build
The target (<REDACTED>) reports PHP/8.2.34 + LiteSpeed LSAPI. The exact
sub-build (bookworm vs noble vs jammy) shifts the delta by ~0x130-0x220, so
pinning it matters. Read-only fingerprints that do NOT require RCE:
1. Server behavior / response headers only weakly distinguish distro; CF masks
   OS details.
2. Timing of the leak-oracle stage may differ per build (build size changes
   session-tree alloc granularity), but that is noisy.
3. Best: run the LEAK stage and read one runtime zval_ptr_dtor; then match
   dtor&0xFFF against the three candidates to select the exact delta.

## Offline assets (saved in this directory)
- lsphp82-8.2.34-1-bookworm.zval.debug
- lsphp82-8.2.34-1-noble.zval.debug
- lsphp82-8.2.34-1-jammy.zval.debug

Usage:
  python3 php_up_framework.py --syms --binary lsphp82-8.2.34-1-<distro>.zval.debug

The delta blocker is closed for all three LiteSpeed 8.2.34 sub-builds.