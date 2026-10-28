# Changelog

## 0.2.0 (2026-10-28)

New:

- `--format leads`: unguarded findings grouped by distribution, each with the project URL from its
  metadata (the source repository when one is listed, trimmed to the repository root), as
  Markdown. Meant as a starting list for upstream fixes. JSON output now has a `url` per group.

Fewer false positives, each found on a scan of about 360 real distributions and covered by a
regression test:

- Branches that only run on Jython or IronPython (`if sys.platform.startswith("java"):`,
  `os.name == "java"`, `platform.python_implementation() == "Jython"`, ...) count as guarded:
  `platform.java_ver()` in the `appdirs` copies vendored by numba and seaborn.
- `load_module()` and `is_reserved()` on an object of unknown type are only reported when the
  receiver looks like a loader or a path (a name such as `loader`, `spec.loader`, `path`; a call
  into `importlib`/`zipimport`/`pathlib` in the chain; a local assigned from one; `self` in a
  loader class). mypyc's `builder.load_module(...)` and winappdbg's `mbi.is_reserved()` are no
  longer reported.
- `super().load_module()` and `self.load_module()` are not reported when a class in the same file
  that the class derives from defines `load_module()` (ansible's collection loader).
- argparse: in `grp = grp.add_mutually_exclusive_group()` the receiver is the old group, not the
  new one, and a name rebound to something else is forgotten (you-get).
- A hit inside `except AttributeError:` whose `try` body probes a module attribute is a fallback
  for older Pythons and counts as guarded (dnspython: `asyncio.get_running_loop()` first,
  `asyncio.get_event_loop()` in the fallback).
- `getpass.getuser()` in `try`/`except KeyError` is not reported when an unguarded
  `getpass.getuser()` call in an enclosing block already ran (ansible's user facts, where the
  `KeyError` is for `pwd.getpwnam()`).

Fixed:

- The Markdown header no longer lowercases "Python" in the environment description.

Checked on a venv with 46 popular packages (222 distributions): the 12 false positives of 0.1.0
there are gone, no finding was added, and three more true positives turned up (fabric, pyzmq,
pip; see the README).

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
