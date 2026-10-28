"""Text, Markdown and JSON output."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import __version__
from .scanner import Finding

SEVERITY_RANK = {"import": 0, "call": 1, "behavior": 2}
SEVERITY_LABEL = {"import": "IMPORT", "call": "CALL", "behavior": "BEHAV"}


@dataclass
class Group:
    name: str
    kind: str  # distribution | source | unowned
    version: str = ""
    root: str = ""
    findings: list = field(default_factory=list)
    url: str = ""

    def visible(self, show_guarded: bool) -> list:
        return [f for f in self.findings if show_guarded or not f.guard]

    def counts(self) -> dict:
        c = {"import": 0, "call": 0, "behavior": 0, "guarded": 0}
        for f in self.findings:
            c["guarded" if f.guard else f.severity] += 1
        return c

    @property
    def title(self) -> str:
        if self.kind == "source":
            return f"{self.name} (source)"
        if self.kind == "unowned":
            return f"{self.name} (in site-packages, no RECORD)"
        return f"{self.name} {self.version}".strip()


@dataclass
class Report:
    target: str
    since: str
    groups: list
    files: int
    unparsable: list  # (path, reason)
    environment: str = ""  # "Python 3.11.9 at .venv"
    distributions: int = 0
    sources: int = 0
    options: dict = field(default_factory=dict)

    def totals(self) -> dict:
        t = {"import": 0, "call": 0, "behavior": 0, "guarded": 0}
        for g in self.groups:
            for k, v in g.counts().items():
                t[k] += v
        return t


def _sorted_groups(report: Report, show_guarded: bool) -> list:
    def key(g: Group):
        vis = g.visible(show_guarded)
        worst = min((SEVERITY_RANK[f.severity] + (3 if f.guard else 0) for f in vis), default=9)
        return (g.kind == "source", worst, -len(vis), g.name.lower())

    return sorted((g for g in report.groups if g.visible(show_guarded)), key=key)


def _by_rule(findings: list) -> list:
    rules: dict[str, list] = {}
    for f in findings:
        rules.setdefault(f.rule, []).append(f)

    def key(item):
        fs = item[1]
        return (min(SEVERITY_RANK[f.severity] + (3 if f.guard else 0) for f in fs), fs[0].removed_in, item[0])

    return sorted(rules.items(), key=key)


def _header(report: Report) -> str:
    what = []
    if report.distributions:
        what.append(f"{report.distributions} distributions")
    if report.sources:
        what.append(f"{report.sources} source tree{'s' if report.sources > 1 else ''}")
    line = (f"stdlib-radar {__version__}: changes after Python {report.since} up to {report.target}; "
            f"{report.files} files in {' and '.join(what) or 'nothing'}")
    if report.environment:
        line += f" ({report.environment})"
    return line


def _sentence(report: Report) -> str:
    """The header without the tool name, as a sentence ("Changes after Python 3.12 ...")."""
    text = _header(report).split(": ", 1)[1]
    return text[:1].upper() + text[1:] + "."


def _summary(report: Report, show_guarded: bool) -> str:
    t = report.totals()
    hit_groups = sum(1 for g in report.groups if g.visible(False))
    s = (f"{t['import']} import-time, {t['call']} call-time and {t['behavior']} behaviour findings "
         f"in {hit_groups} group{'s' if hit_groups != 1 else ''}")
    if t["guarded"]:
        s += f"; {t['guarded']} guarded" + ("" if show_guarded else " (hidden, see --show-guarded)")
    return s


def render_text(report: Report, show_guarded: bool = False) -> str:
    out = [_header(report), ""]
    for g in _sorted_groups(report, show_guarded):
        vis = g.visible(show_guarded)
        c = g.counts()
        parts = [f"{c[k]} {k}" for k in ("import", "call", "behavior") if c[k]]
        out.append(f"== {g.title}: {', '.join(parts) or 'guarded only'}")
        for _rule, fs in _by_rule(vis):
            f0 = fs[0]
            out.append(f"  {f0.message} [{f0.removed_in}, {f0.rule}]")
            for f in fs:
                sev = SEVERITY_LABEL[f.severity]
                conf = "" if f.confidence == "high" else f" ({f.confidence} confidence)"
                guard = f"  [guarded: {f.guard}]" if f.guard else ""
                out.append(f"    {sev:<6} {f.path}:{f.line}  {f.api}{conf}{guard}")
            out.append(f"    fix:  {f0.fix}")
            out.append(f"    docs: {f0.doc}")
        out.append("")
    if report.unparsable:
        out.append(f"{len(report.unparsable)} files could not be parsed (Python 2 or newer syntax); "
                   "run with --verbose to list them.")
        if report.options.get("verbose"):
            out.extend(f"  {p}: {why}" for p, why in report.unparsable)
    out.append(_summary(report, show_guarded))
    return "\n".join(out) + "\n"


def _md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Report, show_guarded: bool = False) -> str:
    out = ["# stdlib-radar report", "", _sentence(report), ""]
    groups = _sorted_groups(report, show_guarded)
    if groups:
        out += ["| Group | Import-time | Call-time | Behaviour | Guarded |", "|---|---:|---:|---:|---:|"]
        for g in groups:
            c = g.counts()
            out.append(f"| {_md(g.title)} | {c['import']} | {c['call']} | {c['behavior']} | {c['guarded']} |")
        out.append("")
    for g in groups:
        out += [f"## {_md(g.title)}", "", "| Severity | Location | API | Change | Fix |", "|---|---|---|---|---|"]
        for _rule, fs in _by_rule(g.visible(show_guarded)):
            for f in fs:
                sev = f.severity + ("" if f.confidence == "high" else f" ({f.confidence})")
                if f.guard:
                    sev += f", guarded: {f.guard}"
                out.append(f"| {_md(sev)} | `{_md(f.path)}:{f.line}` | `{_md(f.api)}` | "
                           f"[{_md(f.message)}]({f.doc}) ({f.removed_in}) | {_md(f.fix)} |")
        out.append("")
    if report.unparsable:
        out += [f"{len(report.unparsable)} files could not be parsed.", ""]
    out.append(_summary(report, show_guarded) + ".")
    return "\n".join(out) + "\n"


def render_json(report: Report, show_guarded: bool = False) -> str:
    data = {
        "tool": "stdlib-radar",
        "version": __version__,
        "target": report.target,
        "since": report.since,
        "environment": report.environment,
        "files": report.files,
        "unparsable": [{"path": p, "reason": r} for p, r in report.unparsable],
        "totals": report.totals(),
        "groups": [
            {
                "name": g.name,
                "kind": g.kind,
                "version": g.version,
                "root": g.root,
                "url": g.url,
                "counts": g.counts(),
                "findings": [f.to_dict() for f in g.visible(show_guarded)],
            }
            for g in _sorted_groups(report, show_guarded)
        ],
    }
    return json.dumps(data, indent=2) + "\n"


def render_leads(report: Report, show_guarded: bool = False) -> str:
    """Unguarded findings grouped by distribution with each project's URL, for upstream reports.

    Guarded hits are never listed here, whatever --show-guarded says.
    """
    groups = _sorted_groups(report, False)
    out = ["# stdlib-radar leads", "", _sentence(report),
           "Unguarded findings only. Check each one against the project's default branch before reporting it.", ""]
    total = 0
    for g in groups:
        vis = g.visible(False)
        total += len(vis)
        if g.kind == "distribution":
            where = g.url or "no project URL in its metadata"
        else:
            where = "source tree" if g.kind == "source" else "no RECORD, owner unknown"
        out += [f"## {g.title}", "", f"<{where}>" if g.url else f"({where})", ""]
        for _rule, fs in _by_rule(vis):
            f0 = fs[0]
            out.append(f"- {f0.message} ({f0.removed_in}, {f0.rule})")
            for f in fs:
                conf = "" if f.confidence == "high" else f", {f.confidence} confidence"
                out.append(f"  - {SEVERITY_LABEL[f.severity]} `{f.path}:{f.line}` `{f.api}`{conf}")
            out.append(f"  - fix: {f0.fix}")
            out.append(f"  - docs: {f0.doc}")
        out.append("")
    n = len(groups)
    out.append(f"{total} finding{'s' if total != 1 else ''} in {n} group{'s' if n != 1 else ''}.")
    return "\n".join(out) + "\n"


def failing(report: Report, fail_on: str) -> list[Finding]:
    if fail_on == "never":
        return []
    limit = SEVERITY_RANK[fail_on]
    return [f for g in report.groups for f in g.findings if not f.guard and SEVERITY_RANK[f.severity] <= limit]
