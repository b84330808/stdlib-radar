import json
import textwrap

import pytest

from stdlib_radar.cli import main
from stdlib_radar.sources import is_test_path


def make_dist(site, name, version, files, requires=()):
    """Write a minimal installed distribution (METADATA + RECORD) into a fake site-packages."""
    info = site / f"{name}-{version}.dist-info"
    info.mkdir(parents=True)
    meta = [f"Metadata-Version: 2.1", f"Name: {name}", f"Version: {version}"]
    meta += [f"Requires-Dist: {r}" for r in requires]
    (info / "METADATA").write_text("\n".join(meta) + "\n", encoding="utf-8")
    record = []
    for rel, text in files.items():
        path = site / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(text), encoding="utf-8")
        record.append(f"{rel},,")
    record.append(f"{info.name}/RECORD,,")
    (info / "RECORD").write_text("\n".join(record) + "\n", encoding="utf-8")


@pytest.fixture
def site(tmp_path):
    site = tmp_path / "venv" / "Lib" / "site-packages"
    site.mkdir(parents=True)
    (tmp_path / "venv" / "pyvenv.cfg").write_text("home = x\nversion = 3.11.9\n", encoding="utf-8")
    make_dist(site, "oldlib", "1.0", {
        "oldlib/__init__.py": "import imghdr\n",
        "oldlib/util.py": "def f():\n    import ast\n    return ast.Num\n",
        "oldlib/tests/test_x.py": "import cgi\n",
    })
    make_dist(site, "careful", "2.0", {
        "careful/__init__.py": "try:\n    import cgi\nexcept ImportError:\n    cgi = None\n",
    })
    make_dist(site, "backported", "3.0", {"backported/__init__.py": "import telnetlib\n"},
              requires=["standard-telnetlib; python_version >= '3.13'"])
    make_dist(site, "standard-uu", "1.0", {"uu.py": "x = 1\n"})
    make_dist(site, "useuu", "1.0", {"useuu.py": "import uu\n"})
    (site / "loose").mkdir()
    (site / "loose" / "__init__.py").write_text("import nntplib\n", encoding="utf-8")
    return tmp_path / "venv"


def run(capsys, *args):
    code = main([str(a) for a in args])
    return code, capsys.readouterr().out


def test_json_groups_by_distribution(site, capsys):
    code, out = run(capsys, "--venv", site, "--json", "-j", "1")
    data = json.loads(out)
    assert code == 1
    groups = {g["name"]: g for g in data["groups"]}
    assert set(groups) == {"oldlib", "loose"}
    old = groups["oldlib"]
    assert old["version"] == "1.0"
    assert [(f["path"], f["line"], f["severity"], f["api"]) for f in old["findings"]] == [
        ("oldlib/__init__.py", 1, "import", "imghdr"),
        ("oldlib/util.py", 3, "call", "ast.Num"),
    ]
    assert groups["loose"]["kind"] == "unowned"
    assert data["environment"].startswith("Python 3.11.9")


def test_show_guarded(site, capsys):
    _code, out = run(capsys, "--venv", site, "--json", "--show-guarded", "-j", "1")
    guards = {g["name"]: [f["guard"] for f in g["findings"]] for g in json.loads(out)["groups"]}
    assert guards["careful"] == ["try/except ImportError"]
    assert guards["backported"] == ["depends on backport standard-telnetlib"]
    assert guards["useuu"] == ["'uu' is installed by standard-uu"]


def test_include_tests(site, capsys):
    _code, out = run(capsys, "--venv", site, "--json", "--include-tests", "-j", "1")
    paths = [f["path"] for g in json.loads(out)["groups"] for f in g["findings"]]
    assert "oldlib/tests/test_x.py" in paths


def test_dist_filter_and_fail_on(site, capsys):
    code, out = run(capsys, "--venv", site, "--dist", "oldlib", "--fail-on", "import", "--json", "-j", "1")
    assert [g["name"] for g in json.loads(out)["groups"]] == ["oldlib"]
    assert code == 1
    code, _ = run(capsys, "--venv", site, "--fail-on", "never")
    assert code == 0


def test_text_and_markdown(site, capsys):
    _code, out = run(capsys, "--venv", site, "-j", "1")
    assert "== oldlib 1.0: 1 import, 1 call" in out
    assert "IMPORT oldlib/__init__.py:1  imghdr" in out
    assert "fix:  filetype, puremagic" in out
    assert "guarded (hidden, see --show-guarded)" in out
    _code, out = run(capsys, "--venv", site, "--format", "markdown", "-j", "1")
    assert out.startswith("# stdlib-radar report")
    assert "| oldlib 1.0 | 1 | 1 | 0 | 0 |" in out
    assert "| import | `oldlib/__init__.py:1` | `imghdr` |" in out


def test_source_tree(tmp_path, capsys):
    (tmp_path / "app.py").write_text("import asyncio\nloop = asyncio.get_event_loop()\n", encoding="utf-8")
    (tmp_path / "ok.py").write_text("print('fine')\n", encoding="utf-8")
    (tmp_path / "py2.py").write_text("import cgi\nprint 'x'\n", encoding="utf-8")
    code, out = run(capsys, tmp_path, "--json")
    data = json.loads(out)
    assert code == 1
    assert data["files"] == 3
    assert [u["path"].endswith("py2.py") for u in data["unparsable"]] == [True]
    (group,) = data["groups"]
    assert group["kind"] == "source"
    assert [(f["path"], f["rule"], f["severity"]) for f in group["findings"]] == [
        ("app.py", "py314-asyncio-get-event-loop", "import")]


def test_clean_tree_exits_zero(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("import json\n", encoding="utf-8")
    code, out = run(capsys, tmp_path)
    assert code == 0
    assert "0 import-time, 0 call-time and 0 behaviour findings" in out


def test_behavior_does_not_fail_by_default(tmp_path, capsys):
    (tmp_path / "a.py").write_text("import gc\ngc.collect(1)\n", encoding="utf-8")
    assert run(capsys, tmp_path)[0] == 0
    assert run(capsys, tmp_path, "--fail-on", "behavior")[0] == 1


def test_usage_errors(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--since", "3.15", "--target", "3.14", str(tmp_path)])
    assert exc.value.code == 2
    with pytest.raises(SystemExit) as exc:
        main([str(tmp_path / "missing")])
    assert exc.value.code == 2


def test_list_rules(capsys):
    assert main(["--list-rules"]) == 0
    out = capsys.readouterr().out
    assert "py313-cgi" in out and "not detected" in out


def test_parallel_matches_serial(tmp_path, capsys):
    for i in range(250):
        (tmp_path / f"m{i}.py").write_text("import imghdr\n" if i % 50 == 0 else "x = 1\n", encoding="utf-8")
    serial = json.loads(run(capsys, tmp_path, "--json", "-j", "1")[1])
    parallel = json.loads(run(capsys, tmp_path, "--json", "-j", "2")[1])
    assert serial["groups"] == parallel["groups"]
    assert serial["totals"]["import"] == 5


@pytest.mark.parametrize("rel,expected", [
    ("pkg/tests/test_a.py", True),
    ("pkg/test/util.py", True),
    ("pkg/conftest.py", True),
    ("pkg/core_test.py", True),
    ("pkg/testing/util.py", False),
    ("pkg/attest.py", False),
])
def test_is_test_path(rel, expected):
    assert is_test_path(rel) is expected
