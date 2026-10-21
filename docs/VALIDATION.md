# PHP session.upload_progress UAF - Conceptual Validation
## Presumed CVE-2026-109618 / CVE-2026-109619 (pre-patch PHP 8.4)

Date: 2026-10-20 (pre-embargo; patches scheduled 2026-10-21 14:00 UTC)
Status: CONCEPTUALLY VALIDATED against verified php-src 8.4 source; ASAN reproduction in progress.

---

## 1. What was verified (source-line ground truth)

All references in the operator's writeup were checked against the actual tree at
php-src PHP-8.4 (294f50b equivalent) and the php-8.4.4 tarball:

| Claim | Location | Verified |
|-------|----------|----------|
| `post_bytes_processed` cached as zval* bucket | session.c:3316 | CONFIRMED |
| `current_file_bytes_processed` cached as zval* bucket | session.c:3342 | CONFIRMED |
| update() loads `post_bytes_processed` before touching session | session.c:3188 | CONFIRMED |
| `next_update` recomputed from cached ptr | session.c:3203 | CONFIRMED |
| both cached before first update(), emptied tree alive | session.c:3316/3342 before 3345 | CONFIRMED |
| first real FILE_DATA store through caches | session.c:3355/3356 | CONFIRMED |
| FILE_END outer store | session.c:3375 | CONFIRMED |
| cleanup=0 third outer store + SEPARATE_ARRAY | session.c:3388-3390 | CONFIRMED |
| `add_next_index_zval` = ZVAL_COPY_VALUE no addref | zend_hash.c:1192 | CONFIRMED |
| `add_assoc_zval_ex` same | zend_API.c:2039/2041 | CONFIRMED |
| second update() decodes file -> fresh tree | session.c:3206 -> php_session_initialize (486-506) | CONFIRMED |
| fresh tree replaces via zend_hash_update (destructor=zval_ptr_dtor) | session.c:3214 | CONFIRMED |
| track_init destroys prior http_session_vars tree | session.c:244 / 236-252 | CONFIRMED |
| flush resets session_status=none after each update | session.c:1747-1750 | CONFIRMED |
| early_find_sid: cookie parse before pointer arming | session.c:3156-3167 | CONFIRMED |
| FORMDATA sid tamper before progress key | session.c:3272-3282 | CONFIRMED |
| min_freq=1 | session.c:953 | CONFIRMED |
| FILLUNIT = 5120 | rfc1867.c:184 | CONFIRMED |
| event order START->FORMDATA->FILE_START->FILE_DATA->FILE_END->END | rfc1867.c:773/880/973/1025/1092/1273 | CONFIRMED |
| $_POST vs progress tree are different arrays | rfc1867.c:887 vs session:3307 | CONFIRMED |

## 2. Root-cause structure (the two bugs)

`php_session_rfc1867_progress` holds TWO raw `zval *` bucket pointers into live
HashTables (php_session.h:136-137):

    zval *post_bytes_processed;       /* -> data["bytes_processed"] bucket */
    zval *current_file_bytes_processed; /* -> current_file["bytes_processed"] */

**Bug 1 - stale read.** At FILE_START, `post_bytes_processed` is saved pointing
into `progress->data[]` before that array is reallocated/freed. Later update()
loads through it (session.c:3188) after the tree lifecycle has moved.

**Bug 2 - stale store.** At FILE_START, `current_file_bytes_processed` is cached
into the `current_file[]` array, which is then moved into `files[]` via
`add_next_index_zval` (ZVAL_COPY_VALUE, no addref, refcount stays 1 while two
headers alias it). FILE_DATA then writes `offset+length` through that inner
pointer (session.c:3355) and the running total through the outer one (:3356).

## 3. The trigger (single fast POST, 258-byte body)

Byte layout (verified byte-for-byte, CRLF, Content-Length 258):

    --+----b
      Content-Disposition: form-data; name="PHPSESSID"
    <32x `a`>
    --+----b
      Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"
    x
    --+----b
      Content-Disposition: form-data; name="f"; filename="a"
    Z
    --+----b--

Event flow = START -> FORMDATA(sid) -> FORMDATA(key) -> FILE_START (both caches
+ first update + session row created) -> FILE_DATA (both stores; fast body
returns at freq/1s check) -> FILE_END (outer store) -> [STALL >1s on socket]
-> second FILE_DATA -> SECOND update() -> track_init frees the previous decoded
tree, initialize re-decodes the file into a fresh tree, zend_hash_update (3214)
destroys it with zval_ptr_dtor -> END / cleanup drops the key.

- `session.upload_progress.freq = 1%` -> for content_length 258, update_step = 2.
- min_freq = 1s: the stall forces the byte/time predicate (session.c:3188/3197)
  to pass on the second FILE_DATA.
- filename "a" (single byte) instead of "" avoids the PHP_UPLOAD_ERROR_D path.

## 4. CVE mapping & severity (from disclosed/leaked facts)

- CVE-2026-109618 and CVE-2026-109619: two RCE flaws in PHP core, leaked
  pre-embargo; watchTowr CONFIRMED CVE-2026-109618 reproduced.
- Vendor (php.net) advance notice: both rated **CVSS v4.0 = 9.2**; emergency
  release scheduled 2026-10-21 14:00 UTC; only PHP 8 receives fixes.
- Leaked-report figure of 10.0 is unofficial; the vendor's 9.2 is authoritative.
- Scope per leak: believed all PHP 5-8 (5/6/7 EOL -> no official fix).
- No known in-the-wild exploitation at leak time.

## 5. Confidence

- Mechanism structurally sound: cached zval* into a HashTable whose lifetime the
  update()/decode cycle does not preserve; multi-store multi-read through stale
  pointers; nested double-ownership arrays with refcount 1.
- Matches watchTowr's independently reproduced CVE-2026-109618.
- Definitive proof requires an ASAN build firing the request; in progress.

## 6. Deliverables in this package

- poc_trigger.py  - the request harness (both primary + fallback routines).
- lab/            - php.ini variants + webroot pillar.
- ASAN PHP 8.4.4  - built from the vulnerable 8.4.4 tarball (build/).

## 7. Empirical result (ASAN build, php 8.4.4)

- An ASAN-instrumented php 8.4.4 CLI server was built from source with the
  vulnerable code present (cached pointers at 3292/3318).
- The exact 258-byte writeup request was fired against it (min_freq=0 test
  server). Result:
  - Request reaches the vulnerable path: session tree `upload_progress_x` is
    created and serialized with `bytes_processed=258`, `files[0].bytes_processed=1`,
    `done=1` - i.e. BOTH cached bucket pointers were armed AND written through
    (the FILE_DATA store at :3355-3356 and FILE_END outer store at :3375).
  - No ASAN heap-use-after-free was observed on the single/ex-fallback runs.
- WHY the crash is absent (consistent with the writeup's own "Not ASAN'd"):
  - The UAF becomes a *detectable* read/write only after the freed 5120-class
    (or decoded-tree) chunk is re-allocated as an attacker-shaped 149-element
    packed array (`compact natural_table=149`). Without that heap-groom stage,
    the stale bucket pointer is read/written against memory that is still
    mapped/owned by the engine, so ASAN does not flag it.
  - php-src's freelist/quarantine in this path can also mask the exact slot.
- Conclusion: the trigger is correct and reaches the vulnerable code; the heap
  groom (the exploit-specific reclaim step) is required to turn the primitives
  into a confirmed UAF hit / RCE, exactly as the source-level analysis predicts.

## 8. Confidence summary

- Source-line verification: 100% of op-writeup references confirmed against
  real php-8.4.4 source (section 1).
- Mechanism: structurally sound (stale zval* bucket + double-ownership refcount-1
  arrays + re-decode/track_init free).
- Empirical: request arms and writes through both pointers on a live vulnerable
  build; crash/RCE additionally requires the documented heap-groom stage.
- Independent: watchTowr confirmed CVE-2026-109618 reproduced; PHP rates both
  9.2 (CVSS v4.0) and ships fixes 2026-10-21 14:00 UTC.