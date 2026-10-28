"""Find what to scan: site-packages of an environment (grouped by distribution) and source trees."""

from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

# Directories skipped when walking a source tree (site-packages is walked in full).
SKIP_DIRS = {
    ".git", ".hg", ".svn", ".tox", ".nox", ".venv", "venv", "__pycache__", "node_modules", "site-packages",
    "dist-packages", ".eggs", ".mypy_cache", ".pytest_cache", ".ruff_cache", "build", ".idea", ".vscode",
}
TEST_DIRS = {"tests", "test"}


@dataclass
class Unit:
    """A group of files reported together: one installed distribution or one source tree."""

    name: str
    kind: str  # distribution | source | unowned
    root: Path
    version: str = ""
    files: list = field(default_factory=list)
    requirements: frozenset = frozenset()
    url: str = ""  # project URL from the distribution's metadata (source repository if listed)


@dataclass
class Environment:
    site_dirs: list
    python: str = ""  # X.Y.Z of the environment, when known
    units: list = field(default_factory=list)
    provided_modules: dict = field(default_factory=dict)  # top-level module -> distribution name


def norm_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def is_test_path(rel: str) -> bool:
    parts = rel.replace("\\", "/").split("/")
    name = parts[-1]
    return (
        any(p in TEST_DIRS for p in parts[:-1])
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )


def venv_python_version(prefix: Path) -> str:
    cfg = prefix / "pyvenv.cfg"
    if cfg.is_file():
        for line in cfg.read_text(encoding="utf-8", errors="replace").splitlines():
            key, _, value = line.partition("=")
            if key.strip() in ("version", "version_info"):
                return value.strip()
    return ""


def site_dirs_for_prefix(prefix: Path) -> list:
    """site-packages directories of a venv / conda env / installation prefix."""
    if any(prefix.glob("*.dist-info")):
        return [prefix]  # already a site-packages directory
    found = []
    for cand in [prefix / "Lib" / "site-packages", *sorted(prefix.glob("lib*/python3*/site-packages"))]:
        if cand.is_dir() and cand not in found:
            found.append(cand)
    return found


def site_dirs_for_python(python: str) -> tuple[list, str]:
    code = (
        "import json, sys, sysconfig; print(json.dumps({'paths': [sysconfig.get_path('purelib'), "
        "sysconfig.get_path('platlib')], 'version': '%d.%d.%d' % sys.version_info[:3]}))"
    )
    out = subprocess.run([python, "-I", "-c", code], capture_output=True, text=True, check=True, encoding="utf-8")
    info = json.loads(out.stdout)
    dirs = []
    for p in info["paths"]:
        path = Path(p)
        if path.is_dir() and path not in dirs:
            dirs.append(path)
    return dirs, info["version"]


_FORGES = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org", "git.sr.ht", "foss.heptapod.net")
_SOURCE_LABELS = {"source", "sourcecode", "repository", "repo", "code", "github", "gitlab", "git", "homepage",
                  "home", "sources", "vcs"}


def project_url(meta) -> str:
    """Best guess at the project's source repository from core metadata, else its home page.

    Forge links (GitHub, GitLab, ...) are trimmed to the repository root, so an "Issues" or
    "Changelog" link still gives the repository.
    """
    candidates = []
    for item in meta.get_all("Project-URL") or ():
        label, _, url = item.partition(",")
        candidates.append((re.sub(r"[^a-z]", "", label.lower()), url.strip()))
    home = meta.get("Home-page")
    if home and home.strip().upper() != "UNKNOWN":
        candidates.append(("homepage", home.strip()))
    best, best_rank = "", 99
    for label, url in candidates:
        if not url.startswith(("http://", "https://")):
            continue
        m = re.match(r"https?://(?:www\.)?([^/]+)/([^/#?]+)/([^/#?]+)", url)
        forge = m and m.group(1).lower() in _FORGES
        if forge:
            url = f"https://{m.group(1).lower()}/{m.group(2)}/{m.group(3).removesuffix('.git')}"
        rank = (0 if label in _SOURCE_LABELS else 1) if forge else (2 if label in _SOURCE_LABELS else 3)
        if rank < best_rank:
            best, best_rank = url, rank
    return best


def _requirement_names(dist) -> frozenset:
    names = set()
    for req in dist.requires or ():
        m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
        if m:
            names.add(norm_name(m.group(1)))
    return frozenset(names)


def _iter_py(root: Path, source_tree: bool = True):
    for dirpath, dirnames, filenames in os.walk(root):
        if source_tree:
            dirnames[:] = [
                d for d in dirnames
                if d not in SKIP_DIRS and not d.endswith((".egg-info", ".dist-info"))
                and not (Path(dirpath) / d / "pyvenv.cfg").exists()
            ]
        else:
            dirnames[:] = [d for d in dirnames if d != "__pycache__" and not d.endswith(".dist-info")]
        for f in filenames:
            if f.endswith(".py"):
                yield Path(dirpath) / f


def _top_level_name(entry: str) -> str | None:
    """'pkg/__init__.py' -> 'pkg', 'mod.py' -> 'mod', 'ext.cp311-win_amd64.pyd' -> 'ext'."""
    parts = entry.replace("\\", "/").split("/")
    first = parts[0]
    if first.endswith((".dist-info", ".egg-info", ".data")) or first in ("..", "__pycache__", ""):
        return None
    if len(parts) > 1:
        return first if first.isidentifier() else None
    for suffix in (".py", ".pyd", ".so"):
        if first.endswith(suffix):
            stem = first[: -len(suffix)].split(".")[0]
            return stem if stem.isidentifier() else None
    return None


def load_environment(site_dirs: list, python: str = "") -> Environment:
    env = Environment(site_dirs=site_dirs, python=python)
    owner: dict[str, Unit] = {}
    for sp in site_dirs:
        for dist in metadata.distributions(path=[str(sp)]):
            name = dist.metadata["Name"] or "?"
            unit = Unit(name=name, kind="distribution", root=Path(sp), version=dist.version or "",
                        requirements=_requirement_names(dist), url=project_url(dist.metadata))
            env.units.append(unit)
            for f in dist.files or ():
                path = Path(str(dist.locate_file(f)))
                top = _top_level_name(str(f))
                if top:
                    env.provided_modules.setdefault(top, name)
                if str(f).endswith(".py"):
                    owner[os.path.normcase(os.path.abspath(path))] = unit
                elif str(f).endswith(".pth") and path.is_file():
                    _add_pth_roots(unit, path, sp)
    for sp in site_dirs:
        unowned: dict[str, Unit] = {}
        for path in _iter_py(sp, source_tree=False):
            key = os.path.normcase(os.path.abspath(path))
            unit = owner.get(key)
            if unit is None:
                rel = path.relative_to(sp)
                top = rel.parts[0] if len(rel.parts) > 1 else rel.stem
                unit = unowned.get(top)
                if unit is None:
                    unit = unowned[top] = Unit(name=top, kind="unowned", root=Path(sp))
                    env.units.append(unit)
                    if top.isidentifier():
                        env.provided_modules.setdefault(top, f"{top} (no RECORD)")
            unit.files.append(path)
    env.units = [u for u in env.units if u.files]
    return env


def _add_pth_roots(unit: Unit, pth: Path, site_dir: Path) -> None:
    """Editable installs: a .pth line naming a directory puts that directory on sys.path."""
    for line in pth.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "import ", "import\t")):
            continue
        d = Path(line)
        if not d.is_absolute():
            d = site_dir / d
        if d.is_dir() and site_dir.resolve() not in (d.resolve(), *d.resolve().parents):
            unit.files.extend(_iter_py(d))


def source_unit(path: Path) -> Unit:
    path = Path(path)
    if path.is_file():
        return Unit(name=str(path), kind="source", root=path.parent, files=[path])
    return Unit(name=str(path), kind="source", root=path, files=sorted(_iter_py(path)))


def find_default_venv(cwd: Path) -> Path | None:
    venv = os.environ.get("VIRTUAL_ENV")
    if venv and Path(venv).is_dir():
        return Path(venv)
    for name in (".venv", "venv"):
        if (cwd / name / "pyvenv.cfg").is_file():
            return cwd / name
    return None

