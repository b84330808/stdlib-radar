import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "verify_docs.py"
spec = importlib.util.spec_from_file_location("verify_docs", SCRIPT)
verify_docs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify_docs)

PAGE = """
<section id="removed"><h2>Removed</h2>
  <section id="id1"><h3>ast</h3><p>Remove <code>ast.Num</code>.</p></section>
  <section id="id2"><h3>glob</h3><p>Removed <code>glob.glob0()</code>.</p></section>
</section>
<section id="other"><h2>Other</h2>
  <span id="label"></span><ul><li>UTF-8 is the default encoding.</li></ul>
  <p>Later text in the same section.</p>
  <section id="sub"><p>Nested.</p></section>
</section>
<section id="after"><p>After.</p></section>
"""


def text(anchor):
    p = verify_docs.SectionText(anchor)
    p.feed(PAGE)
    return p.found, p.text()


def test_section_text_is_limited_to_the_section():
    found, t = text("id1")
    assert found and "ast.Num" in t and "glob0" not in t


def test_label_runs_to_end_of_enclosing_section():
    found, t = text("label")
    assert found and "default encoding" in t and "Later text" in t and "Nested" in t and "After" not in t


def test_missing_anchor():
    assert text("nope") == (False, "")
