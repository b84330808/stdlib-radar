"""AST analysis of one Python file against the selected rules."""

from __future__ import annotations

import ast
import re
import sys
import warnings
from dataclasses import asdict, dataclass
from importlib.util import decode_source

from .rules import Entry

# Exception hierarchy, as far as guards need it: name -> parent.
_EXC_PARENT = {
    "ModuleNotFoundError": "ImportError",
    "ImportError": "Exception",
    "AttributeError": "Exception",
    "TypeError": "Exception",
    "ValueError": "Exception",
    "RuntimeError": "Exception",
    "MetadataNotFound": "FileNotFoundError",
    "FileNotFoundError": "OSError",
    "OSError": "Exception",
    "ProgrammingError": "Exception",
    "Exception": "BaseException",
}
_EXC_ALIASES = {"IOError": "OSError", "EnvironmentError": "OSError", "error": "OSError"}

_VERSIONISH_NAME = re.compile(r"(?i)(^|_)(py(thon)?_?(2|3|v(er(sion)?)?|gte?|lt|ge)|version_info|hexversion)")
_TYPE_CHECKING = {"TYPE_CHECKING", "typing.TYPE_CHECKING", "typing_extensions.TYPE_CHECKING"}
_PATHLIB_CLASSES = ("pathlib.Path", "pathlib.PurePath", "pathlib.PosixPath", "pathlib.WindowsPath",
                    "pathlib.PurePosixPath", "pathlib.PureWindowsPath")
_AST_VISITS = ("visit_Num", "visit_Str", "visit_Bytes", "visit_NameConstant", "visit_Ellipsis")
_FUNCS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)
_TRY = (ast.Try,) + ((ast.TryStar,) if sys.version_info >= (3, 11) else ())


@dataclass
class Finding:
    rule: str
    removed_in: str
    category: str
    severity: str  # import | call | behavior
    confidence: str  # high | medium | low
    line: int
    col: int
    api: str
    message: str
    fix: str
    doc: str
    guard: str | None = None
    path: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FileContext:
    """What the caller knows about the environment the file lives in."""

    target: tuple[int, int]
    # Top-level module names importable from the scanned environment -> providing distribution.
    provided_modules: dict | None = None
    # Normalised requirement names declared by the distribution that owns the file.
    requirements: frozenset = frozenset()
    # Module names of .py files / packages next to the file (``import chunk`` may mean ./chunk.py).
    siblings: frozenset = frozenset()


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _call_name(node: ast.AST) -> str | None:
    """Plain textual dotted name of an expression (no import resolution)."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _str_const(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


class Analyzer:
    def __init__(self, tree: ast.Module, entries: tuple[Entry, ...], ctx: FileContext) -> None:
        self.tree = tree
        self.ctx = ctx
        self.findings: dict[tuple, Finding] = {}
        self.stack: list[tuple[ast.AST, str, ast.AST]] = []  # (parent, field, child)
        self.by_kind: dict[str, list[Entry]] = {}
        for e in entries:
            self.by_kind.setdefault(e.kind, []).append(e)
        self.checks = {e.check: e for e in self.by_kind.get("check", ())}
        self.attr_targets = {t: e for e in self.by_kind.get("attribute", ()) for t in e.targets}
        self.call_targets: dict[str, list[Entry]] = {}
        for e in self.by_kind.get("call", ()):
            for t in e.targets:
                self.call_targets.setdefault(t, []).append(e)
        self.method_targets: dict[str, list[Entry]] = {}
        for e in self.by_kind.get("method", ()):
            for t in e.targets:
                self.method_targets.setdefault(t, []).append(e)
        self.module_entries = self.by_kind.get("module", ())
        self.bindings: dict[str, set[str]] = {}
        self.assigned_names: set[str] = set()
        self.version_names: dict[str, ast.expr] = {}
        self.class_methods: dict[str, set[str]] = {}
        self.class_bases: dict[str, list[ast.expr]] = {}
        self.group_vars: dict[int, dict[str, str]] = {}
        self._prepass()

    # ------------------------------------------------------------------ setup

    def _prepass(self) -> None:
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        self.bindings.setdefault(a.asname, set()).add(a.name)
                    else:
                        root = a.name.split(".")[0]
                        self.bindings.setdefault(root, set()).add(root)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                for a in node.names:
                    if a.name != "*":
                        self.bindings.setdefault(a.asname or a.name, set()).add(f"{node.module}.{a.name}")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                self.assigned_names.add(node.name)
                if isinstance(node, ast.ClassDef):
                    methods = set()
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            methods.add(item.name)
                        elif isinstance(item, ast.Assign):
                            methods.update(t.id for t in item.targets if isinstance(t, ast.Name))
                    self.class_methods.setdefault(node.name, set()).update(methods)
                    self.class_bases[node.name] = node.bases
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
                self.assigned_names.add(node.id)
        for stmt in self.tree.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                if self._versionish(stmt.value):
                    self.version_names[stmt.targets[0].id] = stmt.value

    # ------------------------------------------------------------- resolution

    def resolve(self, node: ast.AST) -> set[str]:
        """Fully qualified names an expression may refer to, through imports."""
        if isinstance(node, ast.Name):
            if node.id in self.bindings:
                return self.bindings[node.id]
            if node.id not in self.assigned_names and node.id in ("open", "__import__"):
                return {f"builtins.{node.id}"}
            return set()
        if isinstance(node, ast.Attribute):
            return {f"{b}.{node.attr}" for b in self.resolve(node.value)}
        return set()

    def resolves_to(self, node: ast.AST, names) -> str | None:
        for q in self.resolve(node):
            if q in names:
                return q
        return None

    # ---------------------------------------------------------------- context

    def in_function(self) -> ast.AST | None:
        """Innermost function whose body contains the current node, if any."""
        for parent, field, _child in reversed(self.stack):
            if isinstance(parent, _FUNCS) and field == "body":
                return parent
        return None

    def in_annotation(self) -> bool:
        return any(field in ("annotation", "returns") for _p, field, _c in self.stack)

    def enclosing_class(self) -> ast.ClassDef | None:
        for parent, _field, _child in reversed(self.stack):
            if isinstance(parent, ast.ClassDef):
                return parent
        return None

    def in_main_block(self) -> bool:
        for parent, field, _child in self.stack:
            if isinstance(parent, ast.If) and field == "body" and isinstance(parent.test, ast.Compare):
                sides = [parent.test.left, *parent.test.comparators]
                if any(isinstance(s, ast.Name) and s.id == "__name__" for s in sides) and any(
                        _str_const(s) == "__main__" for s in sides):
                    return True
        return False

    def severity_for(self, entry: Entry) -> str:
        if entry.effect != "error":
            return "behavior"
        if self.in_function() is not None or self.in_annotation() or self.in_main_block():
            return "call"
        return "import"

    # ----------------------------------------------------------------- guards

    @staticmethod
    def _handler_names(handler: ast.ExceptHandler) -> list[str]:
        if handler.type is None:
            return ["BaseException"]
        types = handler.type.elts if isinstance(handler.type, ast.Tuple) else [handler.type]
        names = []
        for t in types:
            name = _call_name(t)
            if name:
                last = name.split(".")[-1]
                names.append(_EXC_ALIASES.get(last, last))
        return names

    @staticmethod
    def _catches(caught: list[str], raised: str) -> bool:
        chain, exc = set(), raised
        while exc:
            chain.add(exc)
            exc = _EXC_PARENT.get(exc)
        chain.add("BaseException")
        return any(c in chain for c in caught)

    def _versionish(self, expr: ast.AST) -> bool:
        for n in ast.walk(expr):
            name = None
            if isinstance(n, ast.Name):
                name = n.id
                if self.resolves_to(n, ("sys.version_info", "sys.version", "sys.hexversion")):
                    return True
            elif isinstance(n, ast.Attribute):
                name = n.attr
                if self.resolves_to(n, ("sys.version_info", "sys.version", "sys.hexversion")):
                    return True
            elif isinstance(n, ast.Call):
                if any(q.startswith("platform.python_version") for q in self.resolve(n.func)):
                    return True
            if name and (_VERSIONISH_NAME.search(name) or name in self.version_names):
                return True
        return False

    def _version_value(self, e: ast.AST, depth: int = 0):
        major, minor = self.ctx.target
        info = (major, minor, 0, "final", 0)
        if depth > 5:
            return None
        if isinstance(e, ast.Constant) and isinstance(e.value, (int, str)) and not isinstance(e.value, bool):
            return e.value
        if isinstance(e, ast.Tuple):
            vals = [self._version_value(x, depth + 1) for x in e.elts]
            return None if any(v is None for v in vals) else tuple(vals)
        if isinstance(e, ast.Name) and e.id in self.version_names:
            return self._version_value(self.version_names[e.id], depth + 1)
        q = self.resolve(e)
        if "sys.version_info" in q:
            return info
        if "sys.hexversion" in q:
            return (major << 24) | (minor << 16) | 0xF0
        if isinstance(e, ast.Attribute) and e.attr in ("major", "minor", "micro"):
            base = self._version_value(e.value, depth + 1)
            if isinstance(base, tuple) and len(base) >= 3:
                return base[("major", "minor", "micro").index(e.attr)]
        if isinstance(e, ast.Subscript):
            base = self._version_value(e.value, depth + 1)
            if not isinstance(base, tuple):
                return None
            sl = e.slice
            if sys.version_info < (3, 9) and isinstance(sl, ast.Index):  # pragma: no cover
                sl = sl.value
            if isinstance(sl, ast.Constant) and isinstance(sl.value, int):
                try:
                    return base[sl.value]
                except IndexError:
                    return None
            if isinstance(sl, ast.Slice) and sl.step is None:
                lo = self._version_value(sl.lower, depth + 1) if sl.lower else 0
                hi = self._version_value(sl.upper, depth + 1) if sl.upper else None
                if isinstance(lo, int) and (hi is None or isinstance(hi, int)):
                    return base[lo:hi]
        return None

    def eval_version(self, e: ast.AST, depth: int = 0) -> bool | None:
        """Truth value of a version test on the target Python, or None if unknown."""
        if depth > 5:
            return None
        if isinstance(e, ast.BoolOp):
            vals = [self.eval_version(v, depth + 1) for v in e.values]
            if isinstance(e.op, ast.And):
                if any(v is False for v in vals):
                    return False
                return True if all(v is True for v in vals) else None
            if any(v is True for v in vals):
                return True
            return False if all(v is False for v in vals) else None
        if isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.Not):
            r = self.eval_version(e.operand, depth + 1)
            return None if r is None else not r
        if isinstance(e, ast.Constant) and isinstance(e.value, bool):
            return e.value
        if isinstance(e, ast.Name):
            if e.id in ("PY2", "PY27", "IS_PY2") and e.id not in self.version_names:
                return False
            if e.id in ("PY3", "PY3K", "IS_PY3") and e.id not in self.version_names:
                return True
            if e.id in self.version_names:
                return self.eval_version(self.version_names[e.id], depth + 1)
        q = self.resolve(e)
        if "six.PY2" in q:
            return False
        if "six.PY3" in q:
            return True
        if isinstance(e, ast.Compare) and len(e.ops) == 1:
            left = self._version_value(e.left)
            right = self._version_value(e.comparators[0])
            if left is None or right is None:
                return None
            if isinstance(left, tuple) and isinstance(right, tuple):
                n = min(len(left), len(right))
                left, right = left[:n], right[:n]
            op = e.ops[0]
            try:
                if isinstance(op, ast.Lt):
                    return left < right
                if isinstance(op, ast.LtE):
                    return left <= right
                if isinstance(op, ast.Gt):
                    return left > right
                if isinstance(op, ast.GtE):
                    return left >= right
                if isinstance(op, ast.Eq):
                    return left == right
                if isinstance(op, ast.NotEq):
                    return left != right
            except TypeError:
                return None
        return None

    def _mentions(self, expr: ast.AST, words: set[str]) -> bool:
        for n in ast.walk(expr):
            s = _str_const(n)
            if s and (s in words or s.split(".")[-1] in words):
                return True
        return False

    def guard_for(self, raises: str, api: str) -> str | None:
        words = {api, api.split(".")[-1]}
        for parent, field, child in reversed(self.stack):
            if isinstance(parent, _TRY) and field == "body":
                for h in parent.handlers:
                    names = self._handler_names(h)
                    if raises and self._catches(names, raises):
                        return f"try/except {'/'.join(names)}"
            elif isinstance(parent, (ast.With, ast.AsyncWith)) and field == "body":
                for item in parent.items:
                    ce = item.context_expr
                    if isinstance(ce, ast.Call) and (_call_name(ce.func) or "").split(".")[-1] == "suppress":
                        names = [(_call_name(a) or "").split(".")[-1] for a in ce.args]
                        if raises and self._catches(names, raises):
                            return f"suppress({'/'.join(names)})"
            elif isinstance(parent, (ast.If, ast.IfExp, ast.While)) and field in ("body", "orelse"):
                guard = self._branch_guard(parent.test, field == "body", words)
                if guard:
                    return guard
            elif isinstance(parent, ast.BoolOp) and field == "values":
                idx = next((i for i, v in enumerate(parent.values) if v is child), 0)
                for prev in parent.values[:idx]:
                    r = self.eval_version(prev)
                    is_and = isinstance(parent.op, ast.And)
                    if r is not None and r != is_and:
                        return f"version check (not run on {self.ctx.target[0]}.{self.ctx.target[1]})"
                    if r is None and (self._versionish(prev) or self._mentions(prev, words)):
                        return "version/feature check"
        return None

    def _branch_guard(self, test: ast.AST, in_body: bool, words: set[str]) -> str | None:
        r = self.eval_version(test)
        if r is not None:
            if r != in_body:
                return f"version check (not run on {self.ctx.target[0]}.{self.ctx.target[1]})"
            return None
        if in_body and (self.resolves_to(test, _TYPE_CHECKING) or _call_name(test) in _TYPE_CHECKING):
            return "TYPE_CHECKING"
        if self._versionish(test):
            return "version check"
        if self._mentions(test, words):
            return "feature check"
        return None

    # --------------------------------------------------------------- findings

    def report(self, entry: Entry, node: ast.AST, api: str, *, raises: str | None = None,
               severity: str | None = None, confidence: str | None = None, message: str | None = None,
               guard: str | None = None) -> None:
        raises = entry.raises if raises is None else raises
        key = (entry.id, node.lineno, node.col_offset, api)
        if key in self.findings:
            return
        self.findings[key] = Finding(
            rule=entry.id,
            removed_in=entry.removed_in,
            category=entry.category,
            severity=severity or self.severity_for(entry),
            confidence=confidence or entry.confidence,
            line=node.lineno,
            col=node.col_offset + 1,
            api=api,
            message=message or entry.message,
            fix=entry.fix,
            doc=entry.doc,
            guard=guard or self.guard_for(raises, api),
        )

    def module_guard(self, entry: Entry, module: str) -> str | None:
        top = module.split(".")[0]
        provided = (self.ctx.provided_modules or {}).get(top)
        if provided:
            return f"'{top}' is installed by {provided}"
        declared = sorted(b for b in entry.backports if _norm(b) in self.ctx.requirements)
        if declared:
            return f"depends on backport {', '.join(declared)}"
        if top in self.ctx.siblings and module == top:
            return f"may be the local module {top}.py next to this file"
        return None

    def removed_module(self, name: str) -> Entry | None:
        for e in self.module_entries:
            for t in e.targets:
                if name == t or name.startswith(t + "."):
                    return e
        return None

    # -------------------------------------------------------------- traversal

    def run(self) -> list[Finding]:
        self.walk(self.tree)
        return sorted(self.findings.values(), key=lambda f: (f.line, f.col, f.rule))

    def walk(self, node: ast.AST) -> None:
        self.visit(node)
        for field, value in ast.iter_fields(node):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        self.stack.append((node, field, item))
                        self.walk(item)
                        self.stack.pop()
            elif isinstance(value, ast.AST):
                self.stack.append((node, field, value))
                self.walk(value)
                self.stack.pop()

    def visit(self, node: ast.AST) -> None:
        if isinstance(node, ast.Import):
            self.visit_import(node)
        elif isinstance(node, ast.ImportFrom):
            self.visit_import_from(node)
        elif isinstance(node, ast.Attribute):
            self.visit_attribute(node)
        elif isinstance(node, ast.Call):
            self.visit_call(node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self.visit_function(node)
        elif isinstance(node, ast.ClassDef):
            self.visit_class(node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            self.visit_with(node)
        elif isinstance(node, ast.Assign):
            self.visit_assign(node)

    # imports

    def visit_import(self, node: ast.Import) -> None:
        for a in node.names:
            e = self.removed_module(a.name)
            if e:
                self.report(e, node, a.name, guard=self.module_guard(e, a.name))

    def visit_import_from(self, node: ast.ImportFrom) -> None:
        if node.level or not node.module:
            return
        e = self.removed_module(node.module)
        if e:
            self.report(e, node, node.module, guard=self.module_guard(e, node.module))
            return
        for a in node.names:
            full = f"{node.module}.{a.name}"
            e = self.removed_module(full)
            if e:
                self.report(e, node, full, guard=self.module_guard(e, full))
            elif full in self.attr_targets:
                self.report(self.attr_targets[full], node, full, raises="ImportError")

    # attribute access

    def visit_attribute(self, node: ast.Attribute) -> None:
        names = self.resolve(node)
        for q in names:
            if q in self.attr_targets:
                self.report(self.attr_targets[q], node, q)
                return
            e = self.removed_module(q)
            if e:
                # "typing.io" reached from "import typing". When the receiver is itself the removed
                # module (cgi.escape after "import cgi"), the import statement was already reported.
                if not any(self.removed_module(b) for b in self.resolve(node.value)):
                    self.report(e, node, q, raises="AttributeError")
                return
        if node.attr in self.method_targets:
            parent = self.stack[-1] if self.stack else None
            is_called = bool(parent and isinstance(parent[0], ast.Call) and parent[1] == "func")
            for e in self.method_targets[node.attr]:
                self.method_hit(e, node, names, is_called, parent[0] if is_called else None)

    def method_hit(self, e: Entry, node: ast.Attribute, names: set[str], is_called: bool, call) -> None:
        if e.called and not is_called:
            return
        if e.min_args:
            if call is None or any(isinstance(a, ast.Starred) for a in call.args) or len(call.args) < e.min_args:
                return
        receiver = self.resolve(node.value)
        if receiver:
            if not any(r == o or r.startswith(o + ".") for r in receiver for o in e.owners):
                return
        if isinstance(node.value, ast.Name) and node.value.id in ("self", "cls"):
            cls = self.enclosing_class()
            if cls is not None and node.attr in self.class_methods.get(cls.name, ()):
                return
        self.report(e, node, f"{_call_name(node.value) or '(...)'}.{node.attr}")

    # calls

    def visit_call(self, node: ast.Call) -> None:
        funcs = self.resolve(node.func)
        for q in funcs:
            for e in self.call_targets.get(q, ()):
                self.call_hit(e, node, q)
            if q in ("importlib.import_module", "builtins.__import__"):
                mod = _str_const(node.args[0]) if node.args else None
                e = self.removed_module(mod) if mod else None
                if e:
                    self.report(e, node, mod, guard=self.module_guard(e, mod))
        c = self.checks
        if "strptime_day_without_year" in c:
            self.check_strptime(c["strptime_day_without_year"], node, funcs)
        if "asyncio_get_event_loop" in c and funcs & {"asyncio.get_event_loop", "asyncio.events.get_event_loop"}:
            self.check_get_event_loop(c["asyncio_get_event_loop"], node)
        if "getpass_getuser" in c and "getpass.getuser" in funcs:
            self.check_getuser(c["getpass_getuser"], node)
        if "gc_collect_generation1" in c and "gc.collect" in funcs:
            gen = node.args[0] if node.args else next((k.value for k in node.keywords if k.arg == "generation"), None)
            if isinstance(gen, ast.Constant) and gen.value == 1:
                self.report(c["gc_collect_generation1"], node, "gc.collect(1)")
        if "typeddict_without_fields" in c and "typing.TypedDict" in funcs:
            self.check_typeddict(c["typeddict_without_fields"], node)
        if "metadata_not_found" in c and "importlib.metadata.metadata" in funcs:
            self.report(c["metadata_not_found"], node, "importlib.metadata.metadata()")
        if isinstance(node.func, ast.Attribute):
            attr = node.func.attr
            if attr == "add_argument":
                if "argparse_booleanoptionalaction" in c:
                    self.check_boolean_optional(c["argparse_booleanoptionalaction"], node)
                if "argparse_single_dash_dest" in c:
                    self.check_single_dash(c["argparse_single_dash_dest"], node)
            elif attr in ("add_argument_group", "add_mutually_exclusive_group") and "argparse_nested_groups" in c:
                self.check_nested_group(c["argparse_nested_groups"], node)
            elif attr in ("glob", "rglob") and "path_glob_doublestar" in c:
                pattern = _str_const(node.args[0]) if node.args else None
                if pattern and pattern.rstrip().endswith("**") and self._pathlike(node.func.value):
                    self.report(c["path_glob_doublestar"], node, f"Path.{attr}({pattern!r})")
        if funcs & {"argparse.BooleanOptionalAction"} and "argparse_booleanoptionalaction" in c:
            bad = [k.arg for k in node.keywords if k.arg in ("type", "choices", "metavar")]
            if bad:
                self.report(c["argparse_booleanoptionalaction"], node, f"BooleanOptionalAction({', '.join(bad)}=)")
        if "implicit_encoding" in c:
            self.check_encoding(c["implicit_encoding"], node, funcs)

    def call_hit(self, e: Entry, node: ast.Call, q: str) -> None:
        if any(k.arg is None for k in node.keywords):
            return  # **kwargs: unknown
        bad = [k.arg for k in node.keywords if k.arg in e.keywords]
        if e.any_keyword:
            bad += [k.arg for k in node.keywords if k.arg not in e.keywords_except and k.arg not in bad]
        if e.max_positional is not None and not any(isinstance(a, ast.Starred) for a in node.args):
            if len(node.args) > e.max_positional:
                bad.append(f"{len(node.args)} positional")
        if bad:
            self.report(e, node, f"{q}({', '.join(bad)})")

    # checks on definitions

    def visit_function(self, node) -> None:
        c = self.checks.get("classmethod_chain")
        if c:
            names = [(_call_name(d) or "").split(".")[-1] for d in node.decorator_list]
            if "classmethod" in names:
                inner = names[names.index("classmethod") + 1:]
                for wrapped in ("property", "cached_property", "abstractproperty"):
                    if wrapped in inner:
                        self.report(c, node.decorator_list[names.index("classmethod")],
                                    f"@classmethod @{wrapped} {node.name}")
                        break

    def _class_has(self, cls_name: str, method: str, seen=None) -> bool:
        seen = seen or set()
        if cls_name in seen:
            return False
        seen.add(cls_name)
        if method in self.class_methods.get(cls_name, ()):
            return True
        return any(isinstance(b, ast.Name) and self._class_has(b.id, method, seen)
                   for b in self.class_bases.get(cls_name, ()))

    def visit_class(self, node: ast.ClassDef) -> None:
        methods = {i.name: i for i in node.body if isinstance(i, (ast.FunctionDef, ast.AsyncFunctionDef))}
        base_names = [b for base in node.bases for b in (self.resolve(base) or {_call_name(base) or ""})]
        c = self.checks.get("ast_visit_methods")
        if c and any(m in methods for m in _AST_VISITS) and not self._class_has(node.name, "visit_Constant"):
            direct = any(b in ("ast.NodeVisitor", "ast.NodeTransformer") for b in base_names)
            looks = direct or any(b.endswith(("Visitor", "Transformer")) for b in base_names)
            if looks:
                for m in _AST_VISITS:
                    if m in methods:
                        self.report(c, methods[m], f"{node.name}.{m}", confidence="high" if direct else "medium")
        c = self.checks.get("loader_without_exec_module")
        if c and "load_module" in methods and not self._class_has(node.name, "exec_module"):
            loaderish = any(re.search(r"Loader|Importer|Finder", b.split(".")[-1]) for b in base_names)
            loaderish = loaderish or bool({"find_spec", "find_module", "create_module"} & set(methods))
            if loaderish:
                self.report(c, methods["load_module"], f"{node.name}.load_module", severity="call")
        c = self.checks.get("partial_class_attribute")
        if c:
            for item in node.body:
                value = item.value if isinstance(item, (ast.Assign, ast.AnnAssign)) else None
                if isinstance(value, ast.Call) and self.resolves_to(value.func, ("functools.partial",)):
                    self.report(c, item, f"{node.name}: class attribute = functools.partial(...)")

    def visit_with(self, node) -> None:
        c = self.checks.get("path_context_manager")
        if not c:
            return
        for item in node.items:
            ce = item.context_expr
            if isinstance(ce, ast.Call) and self.resolves_to(ce.func, _PATHLIB_CLASSES):
                self.report(c, ce, f"with {_call_name(ce.func)}(...)")

    def visit_assign(self, node: ast.Assign) -> None:
        if "argparse_nested_groups" not in self.checks:
            return
        value = node.value
        if (len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and value.func.attr in ("add_argument_group", "add_mutually_exclusive_group")):
            scope = id(self.in_function() or self.tree)
            kind = "group" if value.func.attr == "add_argument_group" else "mutex"
            self.group_vars.setdefault(scope, {})[node.targets[0].id] = kind

    # checks on calls

    def _pathlike(self, expr: ast.AST) -> bool:
        """The receiver is visibly a pathlib object: Path(...)..., pathlib.Path.cwd()..., etc."""
        while True:
            if isinstance(expr, ast.Call):
                if self.resolves_to(expr.func, _PATHLIB_CLASSES):
                    return True
                expr = expr.func
            elif isinstance(expr, ast.Attribute):
                if self.resolves_to(expr, _PATHLIB_CLASSES):
                    return True
                expr = expr.value
            else:
                return bool(self.resolves_to(expr, _PATHLIB_CLASSES))

    def check_strptime(self, e: Entry, node: ast.Call, funcs: set[str]) -> None:
        resolved = funcs & {"datetime.datetime.strptime", "datetime.date.strptime", "time.strptime"}
        if not resolved and not (isinstance(node.func, ast.Attribute) and node.func.attr == "strptime"):
            return
        if not resolved and self.resolve(node.func):
            return  # some other module's strptime
        fmt = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "format"), None)
        fmt = _str_const(fmt)
        if fmt is None:
            return
        directives = re.findall(r"%(.)", fmt.replace("%%", ""))
        if "d" in directives and not {"Y", "y"} & set(directives):
            self.report(e, node, f"strptime(..., {fmt!r})", confidence="high" if resolved else "medium")

    def check_get_event_loop(self, e: Entry, node: ast.Call) -> None:
        func = self.in_function()
        if isinstance(func, ast.AsyncFunctionDef):
            return  # a coroutine always has a running loop
        if func is None and not self.in_main_block():
            self.report(e, node, "asyncio.get_event_loop()", severity="import", confidence="high",
                        message="asyncio.get_event_loop() at import time raises RuntimeError on 3.14+ (no current loop)")
        else:
            self.report(e, node, "asyncio.get_event_loop()")

    def check_getuser(self, e: Entry, node: ast.Call) -> None:
        for parent, field, _child in reversed(self.stack):
            if isinstance(parent, _TRY) and field == "body":
                names = [n for h in parent.handlers for n in self._handler_names(h)]
                old = [n for n in names if n in ("KeyError", "ImportError")]
                if old and not self._catches(names, "OSError"):
                    self.report(e, node, f"getpass.getuser() in try/except {'/'.join(old)}")
                return

    def check_typeddict(self, e: Entry, node: ast.Call) -> None:
        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
            return
        extra_kw = [k for k in node.keywords if k.arg not in ("total", "closed", "extra_items")]
        if len(node.args) == 1 and not extra_kw:
            self.report(e, node, "TypedDict(name)")
        elif len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and node.args[1].value is None:
            self.report(e, node, "TypedDict(name, None)")

    def check_boolean_optional(self, e: Entry, node: ast.Call) -> None:
        action = next((k.value for k in node.keywords if k.arg == "action"), None)
        if action is not None and self.resolves_to(action, ("argparse.BooleanOptionalAction",)):
            bad = [k.arg for k in node.keywords if k.arg in ("type", "choices", "metavar")]
            if bad:
                self.report(e, node, f"add_argument(action=BooleanOptionalAction, {', '.join(bad)}=)")

    def check_single_dash(self, e: Entry, node: ast.Call) -> None:
        if any(k.arg == "dest" or k.arg is None for k in node.keywords):
            return
        opts = [_str_const(a) for a in node.args]
        if not opts or any(o is None or not o.startswith("-") for o in opts):
            return
        if any(o.startswith("--") for o in opts):
            return
        first_short = next((i for i, o in enumerate(opts) if len(o) == 2), None)
        first_long = next((i for i, o in enumerate(opts) if len(o) > 2), None)
        if first_short is not None and first_long is not None and first_short < first_long:
            self.report(e, node, f"add_argument({', '.join(repr(o) for o in opts)})")

    def check_nested_group(self, e: Entry, node: ast.Call) -> None:
        recv = node.func.value
        kind = None
        if isinstance(recv, ast.Name):
            kind = self.group_vars.get(id(self.in_function() or self.tree), {}).get(recv.id)
        elif isinstance(recv, ast.Call) and isinstance(recv.func, ast.Attribute):
            kind = {"add_argument_group": "group", "add_mutually_exclusive_group": "mutex"}.get(recv.func.attr)
        if kind == "mutex" or (kind == "group" and node.func.attr == "add_argument_group"):
            outer = "argument_group" if kind == "group" else "mutually_exclusive_group"
            self.report(e, node, f"{outer}.{node.func.attr}()")

    def check_encoding(self, e: Entry, node: ast.Call, funcs: set[str]) -> None:
        kws = {k.arg for k in node.keywords}
        if None in kws or "encoding" in kws:
            return
        if any(isinstance(a, ast.Starred) for a in node.args):
            return

        def mode_is_text(mode_node, default_text: bool) -> bool:
            if mode_node is None:
                return default_text
            mode = _str_const(mode_node)
            return mode is not None and "b" not in mode

        def mode_arg(pos: int):
            if len(node.args) > pos:
                return node.args[pos]
            return next((k.value for k in node.keywords if k.arg == "mode"), None)

        if funcs & {"builtins.open", "io.open", "os.fdopen"}:
            if len(node.args) < 4 and mode_is_text(mode_arg(1), True):
                self.report(e, node, f"{_call_name(node.func)}() without encoding")
        elif "codecs.open" in funcs:
            if len(node.args) < 3 and mode_is_text(mode_arg(1), True):
                self.report(e, node, "codecs.open() without encoding")
        elif funcs & {"io.TextIOWrapper"}:
            if len(node.args) < 2:
                self.report(e, node, "io.TextIOWrapper() without encoding")
        elif funcs & {"tempfile.NamedTemporaryFile", "tempfile.TemporaryFile", "tempfile.SpooledTemporaryFile"}:
            if len(node.args) < 3 and mode_is_text(mode_arg(0), False):
                self.report(e, node, f"{_call_name(node.func)}(text mode) without encoding")
        elif any(f.startswith("subprocess.") for f in funcs):
            if {f.split(".")[-1] for f in funcs} & {"run", "call", "check_call", "check_output", "Popen"}:
                text = [k.arg for k in node.keywords if k.arg in ("text", "universal_newlines")
                        and isinstance(k.value, ast.Constant) and k.value.value is True]
                if text:
                    self.report(e, node, f"{_call_name(node.func)}({text[0]}=True) without encoding")
        elif isinstance(node.func, ast.Attribute) and not self.resolve(node.func):
            attr = node.func.attr
            if attr == "read_text" and not node.args:
                self.report(e, node, ".read_text() without encoding")
            elif attr == "write_text" and len(node.args) == 1:
                self.report(e, node, ".write_text() without encoding")
            elif attr == "open" and self._pathlike(node.func.value):
                if len(node.args) < 3 and mode_is_text(mode_arg(0), True):
                    self.report(e, node, "Path.open() without encoding")


_TRIGGERS_CACHE: dict[int, re.Pattern] = {}


def _trigger_pattern(entries: tuple[Entry, ...]) -> re.Pattern:
    """Cheap pre-filter: a file that mentions none of these words cannot produce a finding."""
    key = hash(tuple(e.id for e in entries))
    pat = _TRIGGERS_CACHE.get(key)
    if pat is None:
        words = set()
        for e in entries:
            if e.kind in ("module", "attribute", "call"):
                words.update(t.split(".")[0] for t in e.targets)
                words.update(t.split(".")[-1] for t in e.targets)
            elif e.kind == "method":
                words.update(e.targets)
            elif e.kind == "check":
                words.update({
                    "classmethod_chain": ["classmethod"],
                    "path_context_manager": ["pathlib"],
                    "getpass_getuser": ["getuser"],
                    "path_glob_doublestar": ["glob"],
                    "argparse_booleanoptionalaction": ["BooleanOptionalAction"],
                    "argparse_nested_groups": ["add_argument_group", "add_mutually_exclusive_group"],
                    "ast_visit_methods": list(_AST_VISITS),
                    "asyncio_get_event_loop": ["get_event_loop"],
                    "partial_class_attribute": ["partial"],
                    "gc_collect_generation1": ["collect"],
                    "strptime_day_without_year": ["strptime"],
                    "loader_without_exec_module": ["load_module"],
                    "typeddict_without_fields": ["TypedDict"],
                    "argparse_single_dash_dest": ["add_argument"],
                    "metadata_not_found": ["metadata"],
                    "implicit_encoding": ["open", "fdopen", "read_text", "write_text", "TextIOWrapper",
                                          "subprocess", "tempfile"],
                }.get(e.check, [e.check]))
        pat = re.compile(r"\b(?:" + "|".join(sorted(map(re.escape, words), key=len, reverse=True)) + r")\b")
        _TRIGGERS_CACHE[key] = pat
    return pat


class ParseError(Exception):
    pass


def analyze_source(source: str | bytes, entries: tuple[Entry, ...], ctx: FileContext,
                   filename: str = "<unknown>") -> list[Finding]:
    """Return findings for one file. Raises ParseError if the file cannot be parsed."""
    if isinstance(source, bytes):
        try:
            source = decode_source(source)
        except (SyntaxError, UnicodeDecodeError, LookupError) as exc:
            raise ParseError(f"cannot decode: {exc}") from None
    if not _trigger_pattern(entries).search(source):
        return []
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(source, filename=filename)
        return Analyzer(tree, entries, ctx).run()
    except (SyntaxError, ValueError) as exc:
        raise ParseError(f"syntax error: {exc}") from None
    except RecursionError:
        raise ParseError("too deeply nested") from None
