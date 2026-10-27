# stdlib-radar

Which of your installed dependencies, and which of your own files, use standard library
APIs that were removed or changed in Python 3.13, 3.14 and 3.15?

`stdlib-radar` reads the source of every distribution in a venv (and your own code), finds
uses of those APIs with an AST scan, and tells you per distribution whether the code will
fail **at import**, fail **when called**, or **behave differently**, with `file:line`, the
fix, and a link to the What's New section that documents the change.

It does not import or run anything it scans.

```
pipx install git+https://github.com/b84330808/stdlib-radar
```

## Example

A Python 3.12 venv with 33 popular packages (requests, numpy, pandas, scipy, matplotlib,
Django, Flask, FastAPI, aiohttp, tornado, Twisted, celery, scikit-learn, sympy, transformers,
wandb, PyInstaller, Sphinx, ...) and their dependencies: 162 distributions, 14,474 files.
Abridged output of `stdlib-radar --venv .venv` (run with Python 3.15.1):

```
stdlib-radar 0.1.0: changes after Python 3.12 up to 3.15; 14474 files in 162 distributions (Python 3.12.13, .venv)

== tornado 6.6: 1 call, 3 behavior
  pkgutil.get_loader() and pkgutil.find_loader() removed [3.14, py314-pkgutil-loaders]
    CALL   tornado/autoreload.py:339  pkgutil.get_loader
    fix:  importlib.util.find_spec(name) and spec.loader
    docs: https://docs.python.org/3.14/whatsnew/3.14.html#pkgutil
  asyncio.get_event_loop() raises RuntimeError when there is no current loop instead of creating one [3.14, py314-asyncio-get-event-loop]
    BEHAV  tornado/platform/asyncio.py:286  asyncio.get_event_loop() (medium confidence)
    BEHAV  tornado/process.py:316  asyncio.get_event_loop() (medium confidence)
    BEHAV  tornado/process.py:325  asyncio.get_event_loop() (medium confidence)
    fix:  asyncio.run(main()), asyncio.Runner, or asyncio.get_running_loop() inside coroutines
    docs: https://docs.python.org/3.14/whatsnew/3.14.html#id10

== sympy 1.14.0: 1 call
  deprecated ast node classes removed [3.14, py314-ast-classes]
    CALL   sympy/testing/runtests.py:1187  ast.Str
    fix:  use ast.Constant and check type(node.value)
    docs: https://docs.python.org/3.14/whatsnew/3.14.html#id9

== Twisted 26.4.0: 1 call
  load_module() removed from importlib.abc.Loader and its subclasses (SourceFileLoader, zipimporter, ...) [3.15, py315-load-module-call]
    CALL   twisted/trial/runner.py:764  (...).load_module (medium confidence)
    fix:  spec = importlib.util.spec_from_loader(name, loader); module = importlib.util.module_from_spec(spec); loader.exec_module(module)
    docs: https://docs.python.org/3.15/whatsnew/3.15.html#importlib

== wandb 0.31.0: 1 behavior
  getpass.getuser() now raises OSError on failure, not KeyError or ImportError; this except clause no longer catches it [3.13, py313-getpass-getuser]
    BEHAV  wandb/cli/cli.py:67  getpass.getuser() in try/except KeyError
    fix:  catch OSError (keep KeyError/ImportError for older versions)
    docs: https://docs.python.org/3.13/whatsnew/3.13.html#changes-in-the-python-api

[... Pygments, aiohttp, setuptools, SQLAlchemy, transformers ...]

0 import-time, 4 call-time and 11 behaviour findings in 9 groups; 22 guarded (hidden, see --show-guarded)
```

Every finding of that run was checked by hand:

- The 4 call-time findings are real: tornado's `python -m tornado.autoreload -m module` calls
  the removed `pkgutil.get_loader()`; Twisted trial's `loadFile()` calls
  `SourceFileLoader(...).load_module()`; a Pygments maintenance script under
  `if __name__ == "__main__"` uses `FancyURLopener`; sympy's test runner does
  `from ast import ... Str` inside `_enhance_asserts` (its caller swallows the `ImportError`, so
  on 3.14 assert rewriting is silently skipped rather than crashing). All four are still on the
  upstream default branches.
- wandb's `cli.py` runs `getpass.getuser()` at import time and catches only `KeyError`. Since
  3.13 a missing passwd entry (a container with an arbitrary UID) raises `OSError`, so
  importing the CLI fails there.
- The `asyncio.get_event_loop()` findings depend on the caller. transformers'
  `testing_utils.execute_subprocess_async()` calls it from synchronous code and then
  `run_until_complete()`, which raises `RuntimeError` on 3.14 (reproduced). The aiohttp and
  SQLAlchemy calls are in code normally reached from a running loop, where
  `get_event_loop()` still returns that loop.
- The 22 guarded hits are all correctly guarded: `try`/`except ImportError` around
  `crypt`/`spwd` (passlib, Twisted), version checks (pytest, Jinja2, sympy's ANTLR parsers,
  anyio), `hasattr` branches (cloudpickle), `except RuntimeError` (tornado, aiohttp,
  prompt_toolkit).

The first run on this venv also produced 9 false positives. Their causes are fixed and covered
by regression tests: an import inside `except ImportError:` used as a fallback (nltk),
`obj.co_lnotab = ...` assignments on stand-in code objects (Twisted, billiard), a local variable
annotation (anyio), `visit_Num` on a non-`ast` visitor (sympy's LFortran visitor),
`load_module(dotted_name=...)` with a foreign signature (jedi), `hasattr()` branch chains
(cloudpickle) and a `hasattr()` check in the class (wandb), a finder that only has
`find_module()` (dead since 3.12, not a 3.15 change), and a `functools.partial` class attribute
used only as a decorator (matplotlib).

## Usage

```
stdlib-radar                      # ./ (your code) and ./.venv, ./venv or $VIRTUAL_ENV
stdlib-radar --venv path/to/venv  # only the installed distributions
stdlib-radar --python /usr/bin/python3.12   # the site-packages of that interpreter
stdlib-radar src tests            # only these source trees
```

| Option | |
|---|---|
| `--target 3.15` | the version you upgrade to (default: newest in the table) |
| `--since 3.12` | the version you run today; only later changes are reported |
| `--encoding` | also report text I/O without `encoding=` (UTF-8 mode is the default in 3.15, PEP 686). Off by default because it is noisy. |
| `--removed-only` | skip behaviour changes |
| `--min-confidence high` | hide heuristic findings (method-name matches); the default `medium` hides only `low` ones, `low` shows everything |
| `--dist NAME` | only report these distributions |
| `--include-tests` / `--exclude-tests` | test files are skipped in site-packages and scanned in source trees by default |
| `--show-guarded` | also list hits behind a guard (see below) |
| `--format text\|markdown\|json`, `--json` | output format |
| `--fail-on import\|call\|behavior\|never` | exit 1 when an unguarded finding is this severe (default `call`) |
| `--list-rules` | print the rule table |

In CI:

```yaml
- run: pipx run --spec git+https://github.com/b84330808/stdlib-radar stdlib-radar --target 3.14
```

## What it finds

83 entries ([docs/RULES.md](docs/RULES.md)): the PEP 594 "dead batteries" and `lib2to3`, removed
functions and classes (`ast.Num`, `asyncio` child watchers, `pkgutil.get_loader`,
`importlib.abc.Traversable`, `sqlite3.version`, `platform.java_ver`, `sre_*`, ...), removed
parameters (`urlopen(cafile=)`, `sqlite3.connect(db, 5.0)`, `NamedTuple("P", x=int)`, ...), and
behaviour changes that can be seen in the source:

- `asyncio.get_event_loop()` with no running loop raises `RuntimeError` (3.14)
- `strptime(s, "%m-%d")`: `%d` without a year raises `ValueError` (3.15)
- custom loaders that only define `load_module()` are no longer called (3.15)
- `visit_Num`/`visit_Str` methods of `ast.NodeVisitor` subclasses are never called (3.14)
- `functools.partial` as a class attribute now binds `self` (3.14)
- `@classmethod` over `@property` (3.13), `with Path(...)` (3.13), nested argparse groups (3.14),
  `add_argument("-f", "-foo")` dest (3.15), `getpass.getuser()` raising `OSError` (3.13),
  `importlib.metadata.metadata()` raising `MetadataNotFound` (3.15, low confidence: shown with
  `--min-confidence low`), ...

Every entry cites the What's New section it comes from. `scripts/verify_docs.py` checks each
citation against docs.python.org (weekly in CI), and `tests/test_runtime.py` checks each
removal on the real interpreter: present before `removed_in`, gone from it on (CI runs 3.9 to 3.15
on Linux and Windows).

Eight entries are listed but not detected because the source alone cannot show them, for
example pickling `itertools` iterators or `EntryPoint[0]`.

### Severity

| | |
|---|---|
| `IMPORT` | at module level: importing the module fails on the target version |
| `CALL` | inside a function, or under `if __name__ == "__main__"`: fails when that code runs |
| `BEHAV` | runs, but does something different (or raises only in some situations) |

Findings found by method name alone (for example `.is_reserved()` or `.load_module()` on an
object of unknown type, with a call that fits the stdlib signature) are marked
`medium confidence`.

### Guards

A hit is reported as guarded, and hidden unless `--show-guarded`, when it sits

- in a `try` block whose `except` catches the error the removal raises (`ImportError`,
  `AttributeError`, `TypeError`, ..., or a base class), or under `contextlib.suppress(...)`
- in a branch that does not run on the target: `sys.version_info`, `sys.hexversion`,
  `six.PY2`, `PY2`, and module-level flags such as `PY313 = sys.version_info >= (3, 13)` are
  evaluated for the target version; version checks it cannot evaluate also count as a guard
- behind `hasattr(mod, "name")`, `find_spec("name")` or `if TYPE_CHECKING:`, in an
  `if hasattr(...)`/`elif`/`else` feature-detection chain, or in a class that checks
  `hasattr(obj, "method")` before using the method
- in an `except ImportError:` block (fallback code)
- in an annotation, which 3.14+ evaluates only when something introspects it (annotations of
  local variables, and all annotations under `from __future__ import annotations`, are never
  evaluated and are not reported)
- in a distribution that depends on a backport (`standard-imghdr`, `legacy-cgi`,
  `audioop-lts`, ...), or in an environment where a module of that name is installed
- `import chunk` next to a local `chunk.py`

## How it works

- Files are mapped to distributions with each distribution's `RECORD`; editable installs are
  followed through their `.pth` files. Files without a `RECORD` are grouped by top-level name.
- Imports are resolved per file (`import xml.etree.ElementTree as ET`, `from ast import Num`,
  `importlib.import_module("cgi")`), and attribute chains are matched against the table.
- Files are parsed with the running interpreter's `ast`, so run it on the newest Python you
  have. Files that do not parse (Python 2 code in old packages) are counted and listed with `-v`.

## Prior art

- `pylint`'s `deprecated-module` and `deprecated-method` checks and type checkers with typeshed
  (`mypy --python-version 3.15`) cover your own code, not your dependencies grouped by
  distribution, and do not tell import-time from call-time failures.
- `vermin` reports the minimum Python version code needs, not what newer versions removed.
- `ruff`'s pyupgrade rules modernise syntax; they do not track stdlib removals.

## License

MIT
