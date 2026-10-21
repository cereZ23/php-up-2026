# php-up-2026

PHP session.upload_progress UAF validation bundle (presumed CVE-2026-109618 / CVE-2026-109619).

Layout: bin/ framework + pocs + trigger, docs/ reports, deltas/ vendor
debug symbols.

Quickstart:
  cd bin
  python3 php_up_framework.py --selftest
  python3 php_up_framework.py --syms --binary ../deltas/lsphp82-8.2.34-1-bookworm.zval.debug

Known deltas (zval_ptr_dtor - zend_call_function): bookworm 0xc930,
noble 0xcef0, jammy 0xd060.

Credits:
  code/framework: J4ck3LSyN (@J4ck3LSyN)
  pocs:           Andrew Dorman (@acd421)
  research:       Arch&Yuki (@ArchKnight23)
  assist:         A.T.L.A.S

Authorized defensive-research / scoped-engagement use only.
