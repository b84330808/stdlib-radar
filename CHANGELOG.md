# Changelog

## 0.1.0 (2026-10-27)

First release.

- 83 entries for Python 3.13, 3.14 and 3.15 (75 detected, 8 listed as not detectable statically),
  each citing its What's New section and checked against it by `scripts/verify_docs.py`.
- Scans a venv's site-packages grouped by distribution (RECORD), plus your own source trees.
- Guards: `try`/`except`, `contextlib.suppress`, `sys.version_info`/`six.PY2` checks evaluated for
  the target version, `hasattr()`/`find_spec()` feature checks, `TYPE_CHECKING`, installed or
  declared backports (`standard-*`, `legacy-cgi`, `audioop-lts`).
- Severity: fails at import, fails on call, or behaviour change. Text, Markdown and JSON output;
  exit code 1 for CI.
- Opt-in `--encoding` check for PEP 686 (UTF-8 mode by default in 3.15).
- Validated on a venv with 33 popular packages (162 distributions); the 9 false positives
  found there are fixed and covered by tests.
