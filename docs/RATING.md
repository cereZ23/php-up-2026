# Evaluation & Rating - PHP session.upload_progress UAF (presumed CVE-2026-109618/619)

## Basis
Public facts as of 2026-10-20 (pre-embargo):
- Two RCE flaws in PHP core (session.upload_progress path), leaked ahead of the
  coordinated disclosure; patches scheduled 2026-10-21 14:00 UTC.
- Vendor (php.net) advance notice rates BOTH **CVSS v4.0 = 9.2**.
- watchTowr confirms CVE-2026-109618 reproduced; no in-the-wild exploit seen.
- Only PHP 8 receives official fixes; PHP 5/6/7 EOL => no fix.
- Leaked-report figure "10.0" is unofficial; vendor 9.2 authoritative.

## Rating
- Severity (vendor): CVSS v4.0 9.2/10.0 (Critical).
- Per CVSS v3.1 the same primitive scores ~9.8
  (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) because the UAF reaches zend_call_function
  -> system() with a network-only, unauthenticated, low-complexity trigger.
- Fix-availability: PHP 8.x patched 2026-10-21; EOL branches permanently exposed.
- Risk posture: HIGH - RCE, network-reachable, no auth, default-ini reachable
  (upload_progress.enabled=1 default; reachable via any multipart POST endpoint
  in any app, not just WordPress).
- Wild exploitation: none confirmed pre-patch (window closing fast).

## Confidence in the analysis
- Source-line verification: 100% of op-writeup references confirmed against
  real php-8.4 tree (VALIDATION.md).
- Mechanism: structurally consistent UAF (stale bucket zval* + double-ownership
  refcount-1 arrays + re-decode/track_init free).
- Empirical: ASAN build + trigger harness in progress.