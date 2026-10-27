"""Check the data table against the interpreter running the tests.

On a Python older than an entry's removed_in the API must still exist (or the old
behaviour must still happen); on removed_in or newer it must be gone. CI runs this
on 3.9 to 3.15, so each entry is checked on both sides of its change.
"""

import argparse
import datetime
import importlib
import sys
import warnings

import pytest

from stdlib_radar.rules import load_entries, parse_version

RUNNING = sys.version_info[:2]

# Names that only exist on some platforms even before their removal.
PLATFORM_ONLY = {"msilib", "nis", "spwd", "ossaudiodev", "crypt", "_crypt", "tkinter.tix", "webbrowser.MacOSX",
                 "pty.master_open", "pty.slave_open"}
# Names that did not exist on every version this package supports.
ADDED_IN = {"opcode.ENABLE_SPECIALIZATION": (3, 12), "opcode.is_pseudo": (3, 12),
            "opcode.MIN_PSEUDO_OPCODE": (3, 12), "opcode.MAX_PSEUDO_OPCODE": (3, 12)}

# Method entries: where the method lived in the stdlib.
METHOD_HOMES = {
    "py313-turtle-settiltangle": ["turtle.RawTurtle.settiltangle"],
    "py313-testprogram-usageexit": ["unittest.TestProgram.usageExit"],
    "py314-asyncio-policy-child-watcher": ["asyncio.AbstractEventLoopPolicy.get_child_watcher",
                                           "asyncio.AbstractEventLoopPolicy.set_child_watcher"],
    "py315-load-module-call": ["importlib.abc.Loader.load_module", "zipimport.zipimporter.load_module"],
    "py315-purepath-is-reserved": ["pathlib.PurePath.is_reserved"],
    "py315-wave-markers": ["wave.Wave_read.getmarkers", "wave.Wave_read.getmark", "wave.Wave_write.setmark"],
    "py315-co-lnotab": ["types.CodeType.co_lnotab"],
}


def resolve(dotted):
    """Import the longest importable module prefix of dotted and getattr the rest."""
    parts = dotted.split(".")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # the APIs warn before they go
        for i in range(len(parts), 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:i]))
            except ImportError:
                continue
            for attr in parts[i:]:
                obj = getattr(obj, attr)
            return obj
    raise ImportError(dotted)


def exists(dotted):
    try:
        resolve(dotted)
        return True
    except (ImportError, AttributeError):
        return False


def _entries(kind):
    return [pytest.param(e, id=e.id) for e in load_entries() if e.kind == kind]


@pytest.mark.parametrize("entry", _entries("module") + _entries("attribute"))
def test_names_exist_until_removed(entry):
    for name in entry.targets:
        if RUNNING >= entry.version:
            assert not exists(name), f"{name} still exists on {RUNNING}"
        elif name in PLATFORM_ONLY or RUNNING < ADDED_IN.get(name, (3, 0)):
            continue
        elif sys.platform == "win32" and ("ChildWatcher" in name or "unix_events" in name):
            continue  # the watcher classes were Unix-only
        else:
            assert exists(name), f"{name} missing on {RUNNING}"


@pytest.mark.parametrize("entry", [e for e in _entries("method") if e.values[0].id in METHOD_HOMES])
def test_methods_exist_until_removed(entry):
    homes = METHOD_HOMES[entry.id]
    for name in homes:
        if name.startswith("turtle."):
            pytest.importorskip("tkinter")
        if RUNNING >= entry.version:
            assert not exists(name), f"{name} still exists on {RUNNING}"
        else:
            assert exists(name), f"{name} missing on {RUNNING}"


def _raises(exc, fn):
    """True if fn raises exc; False if it returns or raises something else."""
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            fn()
        except exc:
            return True
        except Exception:
            return False
    return False


def _path_with():
    import pathlib
    with pathlib.Path("."):
        pass


def _nested_group():
    p = argparse.ArgumentParser()
    p.add_argument_group("a").add_argument_group("b")


def _bool_optional_metavar():
    argparse.ArgumentParser().add_argument("--x", action=argparse.BooleanOptionalAction, metavar="X")


def _single_dash_dest():
    p = argparse.ArgumentParser()
    return p.add_argument("-f", "-foo").dest


# rule id -> (exception or None, callable). With an exception: raised from removed_in on,
# not raised before. Callables that return a value are compared with (old, new) instead.
BEHAVIOUR = {
    "py313-urlopen-cafile": (TypeError, lambda: __import__("urllib.request").request.urlopen(
        "file:///nonexistent-stdlib-radar", cafile="x")),
    "py313-typeddict-kwargs": (TypeError, lambda: __import__("typing").TypedDict("TD", x=int)),
    "py313-path-context-manager": (TypeError, _path_with),
    "py314-email-localtime-isdst": (TypeError, lambda: __import__("email.utils").utils.localtime(None, isdst=-1)),
    "py314-path-kwargs": (TypeError, lambda: __import__("pathlib").Path("a", foo=1)),
    "py314-path-relative-to-args": (TypeError, lambda: __import__("pathlib").PurePath("a/b").relative_to("a", "b")),
    "py314-argparse-nested-groups": (ValueError, _nested_group),
    "py314-argparse-booleanoptionalaction": (TypeError, _bool_optional_metavar),
    "py315-resources-files-package": (TypeError, lambda: __import__("importlib.resources").resources.files(
        package="json")),
    "py315-sysconfig-check-home": (TypeError, lambda: __import__("sysconfig").is_python_build(check_home=False)),
    "py315-namedtuple-kwargs": (TypeError, lambda: __import__("typing").NamedTuple("P", x=int)),
    "py315-typeddict-no-fields": (TypeError, lambda: __import__("typing").TypedDict("TD")),
    "py315-sqlite3-connect-positional": (TypeError, lambda: __import__("sqlite3").connect(":memory:", 5.0)),
    "py315-strptime-day-without-year": (ValueError, lambda: datetime.datetime.strptime("02-03", "%m-%d")),
    "py315-argparse-single-dash-dest": (("f", "foo"), _single_dash_dest),
}


@pytest.mark.parametrize("rule", sorted(BEHAVIOUR))
def test_behaviour(rule):
    entry = next(e for e in load_entries() if e.id == rule)
    expected, fn = BEHAVIOUR[rule]
    new = RUNNING >= entry.version
    if isinstance(expected, tuple) and not isinstance(expected[0], type):
        assert fn() == expected[1 if new else 0]
        return
    assert _raises(expected, fn) == new, f"{rule}: expected {'an' if new else 'no'} {expected.__name__}"


def test_getdefaultlocale_was_not_removed():
    # Planned for removal in 3.15 but undeprecated instead (What's New in 3.15, locale).
    import locale
    assert hasattr(locale, "getdefaultlocale")


def test_every_entry_cites_its_own_whats_new():
    for e in load_entries():
        assert e.doc.startswith(f"https://docs.python.org/{e.removed_in}/whatsnew/{e.removed_in}.html#"), e.id
        parse_version(e.removed_in)
