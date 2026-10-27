"""Command line interface."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache
from pathlib import Path

from . import __version__
from .report import Group, Report, failing, render_json, render_markdown, render_text
from .rules import CONFIDENCES, known_versions, load_entries, parse_version, select_entries
from .scanner import FileContext, ParseError, analyze_source
from .sources import (
    find_default_venv,
    is_test_path,
    load_environment,
    norm_name,
    site_dirs_for_prefix,
    site_dirs_for_python,
    source_unit,
    venv_python_version,
)

EPILOG = """\
examples:
  stdlib-radar                      your code in . and the venv in ./.venv or $VIRTUAL_ENV
  stdlib-radar --venv .venv         only the installed distributions
  stdlib-radar src --since 3.13     only changes made in 3.14 and 3.15
  stdlib-radar --encoding           also flag text I/O without encoding= (PEP 686, 3.15)
  stdlib-radar --format markdown > report.md

exit status: 0 nothing at or above --fail-on, 1 findings, 2 usage error.
"""


def build_parser() -> argparse.ArgumentParser:
    latest = known_versions()[-1]
    p = argparse.ArgumentParser(
        prog="stdlib-radar",
        description="Find uses of standard library APIs removed or changed in Python 3.13-3.15, "
        "in your code and in your installed dependencies.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("paths", nargs="*", type=Path, help="source files or directories to scan (default: .)")
    env = p.add_mutually_exclusive_group()
    env.add_argument("--venv", type=Path, metavar="DIR", help="scan the site-packages of this venv or prefix")
    env.add_argument("--python", metavar="EXE", help="scan the site-packages of this interpreter")
    env.add_argument("--no-env", action="store_true", help="do not look for a venv; scan only PATHS")
    p.add_argument("--target", default=latest, metavar="X.Y", help=f"Python version you upgrade to (default {latest})")
    p.add_argument("--since", default="3.12", metavar="X.Y",
                   help="Python version you run today; only later changes are reported (default 3.12)")
    p.add_argument("--encoding", action="store_true",
                   help="also report text I/O without encoding= (UTF-8 default in 3.15, PEP 686; noisy)")
    p.add_argument("--removed-only", action="store_true", help="skip behaviour changes, report removals only")
    p.add_argument("--min-confidence", choices=CONFIDENCES, default="low",
                   help="hide heuristic findings below this confidence (default low: show all)")
    p.add_argument("--dist", action="append", default=[], metavar="NAME",
                   help="only report these distributions (repeatable)")
    tests = p.add_mutually_exclusive_group()
    tests.add_argument("--include-tests", dest="tests", action="store_true", default=None,
                       help="scan test files of installed distributions too")
    tests.add_argument("--exclude-tests", dest="tests", action="store_false",
                       help="skip test files in source trees too")
    p.add_argument("--show-guarded", action="store_true",
                   help="also list hits behind try/except, version checks, hasattr() or installed backports")
    p.add_argument("--format", choices=("text", "markdown", "json"), default="text")
    p.add_argument("--json", action="store_const", const="json", dest="format", help="same as --format json")
    p.add_argument("--fail-on", choices=("import", "call", "behavior", "never"), default="call",
                   help="exit 1 if an unguarded finding is this severe (default call: import- or call-time)")
    p.add_argument("--jobs", "-j", type=int, default=0, metavar="N", help="worker processes (default: CPU count)")
    p.add_argument("--verbose", "-v", action="store_true", help="list files that could not be parsed")
    p.add_argument("--list-rules", action="store_true", help="print the rule table and exit")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


# ---------------------------------------------------------------- workers

_ENTRIES = ()
_TARGET = (3, 15)
_PROVIDED: dict = {}


def _init_worker(entries, target, provided) -> None:
    global _ENTRIES, _TARGET, _PROVIDED
    _ENTRIES, _TARGET, _PROVIDED = entries, target, provided


@lru_cache(maxsize=4096)
def _siblings(directory: str) -> frozenset:
    names = set()
    try:
        for entry in os.scandir(directory):
            if entry.name.endswith(".py"):
                names.add(entry.name[:-3])
            elif entry.is_dir() and os.path.exists(os.path.join(entry.path, "__init__.py")):
                names.add(entry.name)
    except OSError:
        pass
    return frozenset(names)


def _scan_one(task):
    index, path, requirements = task
    ctx = FileContext(
        target=_TARGET,
        provided_modules=_PROVIDED,
        requirements=requirements,
        siblings=_siblings(os.path.dirname(path)),
    )
    try:
        with open(path, "rb") as fh:
            data = fh.read()
        return index, analyze_source(data, _ENTRIES, ctx, filename=path), None
    except ParseError as exc:
        return index, [], str(exc)
    except OSError as exc:
        return index, [], f"cannot read: {exc}"


def _run_tasks(tasks, entries, target, provided, jobs):
    if jobs <= 1 or len(tasks) < 200:
        _init_worker(entries, target, provided)
        return [_scan_one(t) for t in tasks]
    with ProcessPoolExecutor(max_workers=jobs, initializer=_init_worker,
                             initargs=(entries, target, provided)) as pool:
        return list(pool.map(_scan_one, tasks, chunksize=32))


# ------------------------------------------------------------------- main

def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def print_rules(out) -> None:
    for e in load_entries():
        detect = "not detected" if e.kind == "undetected" else e.kind
        out.write(f"{e.removed_in}  {e.id:<40} {e.category:<8} {detect:<12} {e.api}\n")
        out.write(f"      {e.doc}\n")


def main(argv=None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except AttributeError:  # pragma: no cover - replaced streams
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list_rules:
        print_rules(sys.stdout)
        return 0
    try:
        target, since = parse_version(args.target), parse_version(args.since)
    except ValueError as exc:
        parser.error(str(exc))
    if since >= target:
        parser.error("--since must be older than --target")

    categories = {"removed"} if args.removed_only else {"removed", "changed"}
    if args.encoding:
        categories.add("encoding")
    entries = select_entries(target, since, frozenset(categories))
    min_conf = CONFIDENCES.index(args.min_confidence)

    # What to scan.
    env = None
    environment = ""
    if args.python:
        try:
            dirs, version = site_dirs_for_python(args.python)
        except (OSError, subprocess.CalledProcessError, ValueError) as exc:
            parser.error(f"cannot query {args.python}: {exc}")
        env, environment = load_environment(dirs, version), f"Python {version}, {args.python}"
    else:
        prefix = args.venv
        if prefix is None and not args.no_env and not args.paths:
            prefix = find_default_venv(Path.cwd())
        if prefix is not None:
            dirs = site_dirs_for_prefix(prefix)
            if not dirs:
                parser.error(f"no site-packages found under {prefix}")
            version = venv_python_version(prefix)
            env = load_environment(dirs, version)
            environment = (f"Python {version}, " if version else "") + str(prefix)
    paths = args.paths or ([] if (args.venv or args.python or args.dist) else [Path(".")])
    for p in paths:
        if not p.exists():
            parser.error(f"no such file or directory: {p}")

    units = []
    if env is not None:
        wanted = {norm_name(d) for d in args.dist}
        for u in env.units:
            if wanted and norm_name(u.name) not in wanted:
                continue
            include_tests = bool(args.tests)
            u.files = [f for f in u.files if include_tests or not is_test_path(_rel(f, u.root))]
            units.append(u)
    for p in paths:
        u = source_unit(p)
        if args.tests is False:
            u.files = [f for f in u.files if not is_test_path(_rel(f, u.root))]
        units.append(u)

    tasks = []
    for ui, u in enumerate(units):
        for fi, f in enumerate(u.files):
            tasks.append(((ui, fi), str(f), u.requirements))
    jobs = args.jobs or os.cpu_count() or 1
    results = _run_tasks(tasks, entries, target, env.provided_modules if env else {}, jobs)

    groups = [Group(name=u.name, kind=u.kind, version=u.version, root=str(u.root)) for u in units]
    unparsable = []
    for (ui, fi), findings, error in results:
        path = units[ui].files[fi]
        rel = _rel(path, units[ui].root)
        if error:
            unparsable.append((str(path), error))
        for f in findings:
            if CONFIDENCES.index(f.confidence) < min_conf:
                continue
            f.path = rel
            groups[ui].findings.append(f)
    for g in groups:
        g.findings.sort(key=lambda f: (f.path, f.line, f.col, f.rule))
    unparsable.sort()

    report = Report(
        target=f"{target[0]}.{target[1]}",
        since=f"{since[0]}.{since[1]}",
        groups=groups,
        files=len(tasks),
        unparsable=unparsable,
        environment=environment,
        distributions=sum(1 for u in units if u.kind == "distribution"),
        sources=sum(1 for u in units if u.kind == "source"),
        options={"verbose": args.verbose},
    )
    render = {"text": render_text, "markdown": render_markdown, "json": render_json}[args.format]
    sys.stdout.write(render(report, show_guarded=args.show_guarded))
    return 1 if failing(report, args.fail_on) else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
