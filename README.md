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

<!-- OUTPUT -->

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
| `--min-confidence medium` | hide heuristic findings (method-name matches) |
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
  `importlib.metadata.metadata()` raising `MetadataNotFound` (3.15), ...

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
object of unknown type) are marked `medium confidence`.

### Guards

A hit is reported as guarded, and hidden unless `--show-guarded`, when it sits

- in a `try` block whose `except` catches the error the removal raises (`ImportError`,
  `AttributeError`, `TypeError`, ..., or a base class), or under `contextlib.suppress(...)`
- in a branch that does not run on the target: `sys.version_info`, `sys.hexversion`,
  `six.PY2`, `PY2`, and module-level flags such as `PY313 = sys.version_info >= (3, 13)` are
  evaluated for the target version; version checks it cannot evaluate also count as a guard
- behind `hasattr(mod, "name")`, `find_spec("name")` or `if TYPE_CHECKING:`
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
