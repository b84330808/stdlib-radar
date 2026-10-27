import textwrap

import pytest

from stdlib_radar.rules import select_entries
from stdlib_radar.scanner import FileContext, ParseError, analyze_source

ALL = frozenset({"removed", "changed", "encoding"})


def scan(code, target=(3, 15), since=(3, 12), categories=ALL, **ctx):
    entries = select_entries(target, since, categories)
    return analyze_source(textwrap.dedent(code), entries, FileContext(target=target, **ctx))


def rules(code, **kw):
    return [(f.rule, f.line) for f in scan(code, **kw) if not f.guard]


def one(code, **kw):
    found = scan(code, **kw)
    assert len(found) == 1, found
    return found[0]


# --- removed modules -------------------------------------------------------

@pytest.mark.parametrize("code", [
    "import cgi",
    "import cgi as c",
    "from cgi import parse_header",
    "import xml, cgi",
    "from typing.io import TextIO",
    "from typing import io",
    "import tkinter.tix",
    "from tkinter import tix",
    "import lib2to3.pgen2.token",
    "import importlib\nimportlib.import_module('telnetlib')",
    "__import__('imghdr')",
])
def test_removed_module_detected(code):
    assert scan(code), code


def test_import_time_vs_call_time():
    f = scan("""
        import crypt
        def f():
            import imghdr
        if __name__ == "__main__":
            import pipes
    """)
    assert [(x.api, x.severity) for x in f] == [("crypt", "import"), ("imghdr", "call"), ("pipes", "call")]


def test_attribute_path_to_removed_submodule():
    f = one("import typing\nx: int = 1\ny = typing.io.TextIO")
    assert f.rule == "py313-typing-io-re" and f.line == 3


def test_usage_after_import_reported_once():
    found = scan("import cgi\ncgi.escape('x')\ncgi.parse_header('y')")
    assert [(f.api, f.line) for f in found] == [("cgi", 1)]


def test_relative_and_third_party_imports_ignored():
    assert not scan("from . import cgi\nfrom .compat import imghdr\nimport mypkg.chunk\nfrom mypkg import uu")


# --- guards ---------------------------------------------------------------

@pytest.mark.parametrize("code,guard", [
    ("try:\n    import imghdr\nexcept ImportError:\n    imghdr = None", "try/except ImportError"),
    ("try:\n    import imghdr\nexcept (ModuleNotFoundError, OSError):\n    pass", "try/except ModuleNotFoundError/OSError"),
    ("try:\n    import imghdr\nexcept Exception:\n    pass", "try/except Exception"),
    ("try:\n    import imghdr\nexcept:\n    pass", "try/except BaseException"),
    ("import contextlib\nwith contextlib.suppress(ImportError):\n    import imghdr", "suppress(ImportError)"),
    ("import sys\nif sys.version_info < (3, 13):\n    import imghdr", "version check (not run on 3.15)"),
    ("import sys\nif sys.version_info >= (3, 13):\n    pass\nelse:\n    import imghdr", "version check (not run on 3.15)"),
    ("import sys\nif sys.version_info[:2] <= (3, 12):\n    import imghdr", "version check (not run on 3.15)"),
    ("import sys\nif sys.version_info.minor < 13:\n    import imghdr", "version check (not run on 3.15)"),
    ("import sys\nif sys.hexversion < 0x030D0000:\n    import imghdr", "version check (not run on 3.15)"),
    ("from sys import version_info as vi\nif vi < (3, 13):\n    import imghdr", "version check (not run on 3.15)"),
    ("import sys\nOLD = sys.version_info < (3, 13)\nif OLD:\n    import imghdr", "version check (not run on 3.15)"),
    ("import six\nif six.PY2:\n    import imghdr", "version check (not run on 3.15)"),
    ("if PY2:\n    import imghdr", "version check (not run on 3.15)"),
    ("from .compat import PY313\nif not PY313:\n    import imghdr", "version check"),
    ("from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import imghdr", "TYPE_CHECKING"),
    ("import importlib.util\nif importlib.util.find_spec('imghdr'):\n    import imghdr", "feature check"),
])
def test_guards(code, guard):
    f = one(code)
    assert f.guard == guard


def test_version_check_that_runs_on_target_is_not_a_guard():
    f = one("import sys\nif sys.version_info >= (3, 13):\n    import imghdr")
    assert f.guard is None


def test_target_changes_version_guard():
    code = "import sys\nif sys.version_info < (3, 14):\n    import ast\n    ast.Num"
    assert one(code, target=(3, 15)).guard
    assert not scan(code, target=(3, 13))  # ast.Num still exists on 3.13


def test_hasattr_guard():
    f = one("import ast\nif hasattr(ast, 'Num'):\n    x = ast.Num")
    assert f.guard == "feature check"


def test_boolop_guard():
    f = one("import sys, ast\nok = sys.version_info < (3, 8) and isinstance(n, ast.Num)")
    assert f.guard.startswith("version check")


def test_try_except_attributeerror_guards_attribute():
    f = one("import ast\ntry:\n    N = ast.Num\nexcept AttributeError:\n    N = None")
    assert f.guard == "try/except AttributeError"


def test_wrong_exception_does_not_guard():
    f = one("try:\n    import imghdr\nexcept ValueError:\n    pass")
    assert f.guard is None


def test_backport_installed_guard():
    f = one("import imghdr", provided_modules={"imghdr": "standard-imghdr"})
    assert f.guard == "'imghdr' is installed by standard-imghdr"


def test_backport_declared_guard():
    f = one("import cgi", requirements=frozenset({"legacy-cgi"}))
    assert f.guard == "depends on backport legacy-cgi"


def test_sibling_module_guard():
    f = one("import chunk", siblings=frozenset({"chunk"}))
    assert "local module" in f.guard


# --- attributes -----------------------------------------------------------

@pytest.mark.parametrize("code,rule", [
    ("import ast\nast.Num", "py314-ast-classes"),
    ("import ast as a\nisinstance(n, a.Str)", "py314-ast-classes"),
    ("from ast import NameConstant", "py314-ast-classes"),
    ("import asyncio\nasyncio.get_child_watcher()", "py314-asyncio-child-watchers"),
    ("import asyncio\nasyncio.set_child_watcher(None)", "py314-asyncio-child-watchers"),
    ("from importlib.abc import Traversable", "py314-importlib-abc-resources"),
    ("import importlib.abc\nimportlib.abc.ResourceReader", "py314-importlib-abc-resources"),
    ("import pkgutil\npkgutil.get_loader('x')", "py314-pkgutil-loaders"),
    ("import sqlite3\nsqlite3.version", "py314-sqlite3-version"),
    ("import urllib.request\nurllib.request.URLopener()", "py314-urllib-urlopener"),
    ("from urllib.request import FancyURLopener", "py314-urllib-urlopener"),
    ("import locale\nlocale.resetlocale()", "py313-locale-resetlocale"),
    ("import re\nre.template('x')", "py313-re-template"),
    ("import unittest\nunittest.makeSuite(T)", "py313-unittest-functions"),
    ("import configparser\nconfigparser.LegacyInterpolation()", "py313-configparser-legacyinterpolation"),
    ("import glob\nglob.glob1('.', '*')", "py315-glob-glob0-glob1"),
    ("from http.server import CGIHTTPRequestHandler", "py315-cgihttprequesthandler"),
    ("import platform\nplatform.java_ver()", "py315-platform-java-ver"),
    ("import ctypes\nctypes.SetPointerType(a, b)", "py315-ctypes-setpointertype"),
    ("import typing\n@typing.no_type_check_decorator\ndef d(f): pass", "py315-no-type-check-decorator"),
    ("import sre_constants", "py315-sre-modules"),
])
def test_attribute_rules(code, rule):
    assert rule in [f.rule for f in scan(code)]


def test_attribute_not_flagged_without_import():
    assert not scan("ast = object()\nast.Num\nsqlite3.version")


def test_similar_names_not_flagged():
    assert not scan("import sqlite3\nsqlite3.sqlite_version\nimport ast\nast.Constant\nimport re\nre.TEMPLATE_X")


def test_since_filters_rules():
    code = "import ast\nast.Num\nimport cgi"
    assert {f.rule for f in scan(code, since=(3, 13))} == {"py314-ast-classes"}
    assert {f.rule for f in scan(code, target=(3, 13))} == {"py313-cgi"}


# --- methods (heuristic) ----------------------------------------------------

def test_load_module_call():
    f = one("import importlib.machinery\nimportlib.machinery.SourceFileLoader('m', 'p').load_module()")
    assert f.rule == "py315-load-module-call" and f.confidence == "medium" and f.severity == "import"


def test_load_module_other_module_not_flagged():
    assert not scan("import imp\nimp.load_module('x', f, p, d)")


def test_load_module_own_method_not_flagged():
    code = """
        class L:
            def load_module(self, name):
                pass
            def get(self):
                return self.load_module('x')
    """
    assert "py315-load-module-call" not in [f.rule for f in scan(code)]


def test_is_reserved_only_when_called():
    assert not scan("addr.is_reserved")
    assert one("def f(p):\n    return p.is_reserved()").severity == "call"


def test_relative_to_extra_args():
    assert one("p.relative_to('a', 'b')").rule == "py314-path-relative-to-args"
    assert not scan("p.relative_to('a')\np.relative_to(*parts)")


def test_co_lnotab():
    assert one("def f(c):\n    return c.co_lnotab").rule == "py315-co-lnotab"


# --- removed parameters -----------------------------------------------------

@pytest.mark.parametrize("code,rule", [
    ("import urllib.request\nurllib.request.urlopen(u, cafile='x')", "py313-urlopen-cafile"),
    ("from urllib.request import urlopen\nurlopen(u, capath='x')", "py313-urlopen-cafile"),
    ("import email.utils\nemail.utils.localtime(dt, True)", "py314-email-localtime-isdst"),
    ("from email.utils import localtime\nlocaltime(isdst=1)", "py314-email-localtime-isdst"),
    ("from pathlib import Path\nPath('a', foo=1)", "py314-path-kwargs"),
    ("import importlib.resources as r\nr.files(package='x')", "py315-resources-files-package"),
    ("import sysconfig\nsysconfig.is_python_build(True)", "py315-sysconfig-check-home"),
    ("import threading\nthreading.RLock(1)", "py315-rlock-args"),
    ("from typing import NamedTuple\nP = NamedTuple('P', x=int)", "py315-namedtuple-kwargs"),
    ("from typing import TypedDict\nTD = TypedDict('TD', x=int)", "py313-typeddict-kwargs"),
    ("import sqlite3\nsqlite3.connect('db', 5.0)", "py315-sqlite3-connect-positional"),
])
def test_call_rules(code, rule):
    assert rule in [f.rule for f in scan(code)]


@pytest.mark.parametrize("code", [
    "import urllib.request\nurllib.request.urlopen(u, context=c)",
    "from pathlib import Path\nPath('a', 'b')",
    "import importlib.resources as r\nr.files('x')",
    "import threading\nthreading.RLock()",
    "from typing import TypedDict\nTD = TypedDict('TD', {'x': int}, total=False)",
    "import typing_extensions\ntyping_extensions.TypedDict('TD', x=int)",
    "import sqlite3\nsqlite3.connect('db', timeout=5.0)",
    "import sqlite3\nsqlite3.connect(*args)",
    "import sqlite3\nsqlite3.connect('db', **kw)",
])
def test_call_rules_negative(code):
    assert not scan(code)


# --- custom checks ------------------------------------------------------------

def test_strptime_without_year():
    f = one("from datetime import datetime\ndatetime.strptime(s, '%m-%d')")
    assert f.rule == "py315-strptime-day-without-year" and f.confidence == "high"
    assert one("import time\ntime.strptime(s, '%d %b')").confidence == "high"
    assert one("dt.strptime(s, format='%d/%m')").confidence == "medium"
    assert not scan("from datetime import datetime\ndatetime.strptime(s, '%d/%m/%Y')")
    assert not scan("from datetime import datetime\ndatetime.strptime(s, '%H:%M')")
    assert not scan("from datetime import datetime\ndatetime.strptime(s, '%%d')")
    assert not scan("import pandas\npandas.Timestamp.strptime(s, '%d')")


def test_get_event_loop():
    code = """
        import asyncio
        loop = asyncio.get_event_loop()
        def sync():
            return asyncio.get_event_loop()
        async def coro():
            return asyncio.get_event_loop()
    """
    found = scan(code)
    assert [(f.line, f.severity, f.confidence) for f in found] == [(3, "import", "high"), (5, "behavior", "medium")]


def test_get_event_loop_guarded_by_runtimeerror():
    code = "import asyncio\ndef f():\n    try:\n        return asyncio.get_event_loop()\n    except RuntimeError:\n        pass"
    assert one(code).guard == "try/except RuntimeError"


def test_getpass_getuser():
    bad = "import getpass\ntry:\n    u = getpass.getuser()\nexcept KeyError:\n    u = None"
    good = "import getpass\ntry:\n    u = getpass.getuser()\nexcept (KeyError, OSError):\n    u = None"
    assert one(bad).rule == "py313-getpass-getuser"
    assert not scan(good)
    assert not scan("import getpass\nu = getpass.getuser()")


def test_classmethod_property():
    f = one("class A:\n    @classmethod\n    @property\n    def x(cls): return 1")
    assert f.rule == "py313-classmethod-chain" and f.line == 2
    assert not scan("class A:\n    @property\n    def x(self): return 1")


def test_path_context_manager():
    assert one("import pathlib\nwith pathlib.Path('x') as p:\n    pass").rule == "py313-path-context-manager"
    assert not scan("import pathlib\nwith pathlib.Path('x').open('rb') as f:\n    pass")


def test_path_glob_doublestar():
    assert one("from pathlib import Path\nPath('.').glob('a/**')").rule == "py313-path-glob-doublestar"
    assert not scan("from pathlib import Path\nPath('.').glob('**/*.py')")
    assert not scan("fs.glob('bucket/**')\nimport glob\nglob.glob('**')")


def test_argparse_checks():
    found = rules("""
        import argparse
        p = argparse.ArgumentParser()
        p.add_argument('--x', action=argparse.BooleanOptionalAction, metavar='X')
        g = p.add_argument_group('g')
        g.add_argument_group('nested')
        m = p.add_mutually_exclusive_group()
        m.add_argument_group('nested')
        m.add_mutually_exclusive_group()
        g.add_mutually_exclusive_group()
        p.add_argument('-f', '-foo')
        p.add_argument('-foo', '-f')
        p.add_argument('-f', '--foo')
    """)
    assert found == [
        ("py314-argparse-booleanoptionalaction", 4),
        ("py314-argparse-nested-groups", 6),
        ("py314-argparse-nested-groups", 8),
        ("py314-argparse-nested-groups", 9),
        ("py315-argparse-single-dash-dest", 11),
    ]


def test_ast_visit_methods():
    code = """
        import ast
        class V(ast.NodeVisitor):
            def visit_Num(self, node): pass
        class W(ast.NodeVisitor):
            def visit_Str(self, node): pass
            def visit_Constant(self, node): pass
    """
    f = one(code)
    assert f.rule == "py314-ast-visit-methods" and f.line == 4 and f.confidence == "high"


def test_loader_without_exec_module():
    code = """
        import importlib.abc
        class Old(importlib.abc.Loader):
            def load_module(self, fullname): pass
        class New(importlib.abc.Loader):
            def load_module(self, fullname): pass
            def exec_module(self, module): pass
        class Sub(New):
            def load_module(self, fullname): pass
        class NotALoader:
            def load_module(self, x): pass
    """
    assert rules(code) == [("py315-load-module-loader", 4)]


def test_partial_class_attribute():
    code = """
        import functools
        class A:
            f = functools.partial(print, 1)
            g = staticmethod(functools.partial(print, 2))
        A().f()
    """
    assert rules(code) == [("py314-functools-partial-method", 4)]


def test_partial_used_only_in_class_body():
    # matplotlib.dviread: the partial is used as a decorator while the class body runs
    code = """
        from functools import partial
        def _dispatch(table, op): return lambda f: f
        class Dvi:
            _dtable = []
            _dispatch = partial(_dispatch, _dtable)
            @_dispatch(1)
            def _set_char(self): pass
    """
    assert not scan(code)


# --- false positives found on real packages (see README, validation) ------------

def test_fallback_in_except_importerror():
    # nltk: from html import escape / except ImportError: from cgi import escape
    f = one("try:\n    from html import escape\nexcept ImportError:\n    from cgi import escape")
    assert f.guard == "fallback in except ImportError"


def test_attribute_assignment_is_not_a_use():
    # twisted/billiard build stand-in code objects: self.co_lnotab = b""
    assert not scan("class FakeCode:\n    def __init__(self):\n        self.co_lnotab = b''")


def test_hasattr_branch_chain():
    # cloudpickle: if hasattr(obj, "co_exceptiontable"): ... else: obj.co_lnotab
    code = """
        def reduce(obj):
            if hasattr(obj, "co_exceptiontable"):
                return obj.co_linetable
            elif hasattr(obj, "co_nmeta"):
                return 1
            else:
                return obj.co_lnotab
    """
    assert one(code).guard == "feature check (hasattr branch)"


def test_hasattr_in_class_guards_method():
    # wandb import_hooks: _load_module is only installed when the loader has load_module
    code = """
        class Chained:
            def __init__(self, loader):
                self.loader = loader
                if hasattr(loader, "load_module"):
                    self.load_module = self._load_module
            def _load_module(self, fullname):
                return self.loader.load_module(fullname)
    """
    assert one(code).guard == "hasattr(..., 'load_module') check in class Chained"


def test_method_with_foreign_signature_not_flagged():
    # jedi: compiled_subprocess.load_module(dotted_name=..., **kwargs)
    assert not scan("def f(s, n, **kw):\n    return s.load_module(dotted_name=n, **kw)")
    assert not scan("def f(p):\n    return p.is_reserved(strict=True)")


def test_annotations():
    # anyio: a local variable annotation is never evaluated
    assert not scan("import asyncio\ndef f():\n    w: asyncio.AbstractChildWatcher | None = None")
    assert not scan("from __future__ import annotations\nimport ast\ndef f(n: ast.Num): pass")
    code = "import ast\ndef f(n: ast.Num): pass"
    assert one(code).guard == "annotation, evaluated only when introspected (3.14+)"


def test_visit_num_needs_an_ast_visitor():
    # sympy fortran_parser: LFortran's asr.ASTVisitor is not ast.NodeVisitor
    assert not scan("import ast\nfrom lfortran import asr\nclass V(asr.ASTVisitor):\n    def visit_Num(self, n): pass")
    code = """
        import ast
        class Base(ast.NodeTransformer):
            pass
        class V(Base):
            def visit_Str(self, n): pass
    """
    assert rules(code) == [("py314-ast-visit-methods", 6)]


def test_finder_with_only_find_module_not_flagged():
    # wandb.util.ImportMetaHook: find_module() is not called since 3.12, so 3.15 changes nothing
    code = """
        class Hook:
            def find_module(self, fullname, path=None): return self
            def load_module(self, fullname): pass
    """
    assert not scan(code)


def test_typeddict_without_fields():
    assert one("from typing import TypedDict\nTD = TypedDict('TD')").rule == "py315-typeddict-no-fields"
    assert one("import typing\nTD = typing.TypedDict('TD', None)").rule == "py315-typeddict-no-fields"
    assert not scan("from typing import TypedDict\nTD = TypedDict('TD', {})")


def test_gc_collect_1():
    assert one("import gc\ngc.collect(1)").rule == "py314-gc-collect-1"
    assert not scan("import gc\ngc.collect()\ngc.collect(2)")


def test_metadata_not_found():
    f = one("from importlib.metadata import metadata\nmetadata('x')")
    assert f.rule == "py315-metadata-not-found" and f.confidence == "low"


# --- encoding (PEP 686) --------------------------------------------------------

@pytest.mark.parametrize("code", [
    "open('f')",
    "open('f', 'w')",
    "open('f', mode='r+')",
    "import io\nio.open('f')",
    "from pathlib import Path\nPath('x').read_text()",
    "p.write_text(data)",
    "import subprocess\nsubprocess.run(cmd, text=True)",
    "import subprocess\nsubprocess.check_output(cmd, universal_newlines=True)",
    "import io\nio.TextIOWrapper(buf)",
    "import tempfile\ntempfile.NamedTemporaryFile('w')",
    "from pathlib import Path\nPath('x').open('w')",
])
def test_encoding_positive(code):
    assert [f.rule for f in scan(code)] == ["py315-utf8-default"], code


@pytest.mark.parametrize("code", [
    "open('f', 'rb')",
    "open('f', encoding='utf-8')",
    "open('f', 'r', -1, 'utf-8')",
    "open('f', mode)",
    "open('f', **kw)",
    "p.read_text('utf-8')",
    "p.read_text(encoding='utf-8')",
    "import subprocess\nsubprocess.run(cmd, text=True, encoding='utf-8')",
    "import subprocess\nsubprocess.run(cmd)",
    "import tempfile\ntempfile.NamedTemporaryFile()",
    "import gzip\nopen = gzip.open\nopen('f')",
    "import importlib.resources\nimportlib.resources.read_text('pkg', 'res')",
])
def test_encoding_negative(code):
    assert not scan(code), code


def test_encoding_is_opt_in():
    assert not scan("open('f')", categories=frozenset({"removed", "changed"}))


# --- robustness ----------------------------------------------------------------

def test_python2_file_is_parse_error():
    with pytest.raises(ParseError):
        scan("import imghdr\nprint 'hello'")


def test_file_without_triggers_skips_parse():
    assert scan("print 'py2 but irrelevant'") == []


def test_coding_cookie_bytes():
    entries = select_entries((3, 15), (3, 12), ALL)
    src = "# -*- coding: latin-1 -*-\nimport cgi\nx = '\xe9'\n".encode("latin-1")
    found = analyze_source(src, entries, FileContext(target=(3, 15)))
    assert [f.api for f in found] == ["cgi"]
