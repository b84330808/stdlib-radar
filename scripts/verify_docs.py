"""Check every entry of changes.json against the What's New page it cites.

For each entry, fetch the page, find the cited anchor, take the text of that
section (or, for a label inside a section, from the label to the end of the
section) and check that ``doc_quote`` appears in it. Exit 1 on any mismatch.

    python scripts/verify_docs.py               # fetch from docs.python.org
    python scripts/verify_docs.py --html-dir D  # use saved pages D/3.13.html ...
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from html.parser import HTMLParser
from pathlib import Path

DATA = Path(__file__).resolve().parent.parent / "src" / "stdlib_radar" / "data" / "changes.json"


class SectionText(HTMLParser):
    """Collect the text from the element with ``id=anchor`` to the end of its section."""

    def __init__(self, anchor: str) -> None:
        super().__init__(convert_charrefs=True)
        self.anchor = anchor
        self.sections = 0
        self.stop_at: int | None = None
        self.capturing = False
        self.done = False
        self.found = False
        self.parts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if self.done:
            return
        if tag == "section":
            self.sections += 1
        if not self.capturing and dict(attrs).get("id") == self.anchor:
            self.found = True
            self.capturing = True
            # Either way capture ends when the innermost open section closes: for a
            # <section> that is the element itself, for a label its parent section.
            self.stop_at = self.sections - 1

    def handle_endtag(self, tag):
        if self.done:
            return
        if tag == "section":
            self.sections -= 1
            if self.capturing and self.sections == self.stop_at:
                self.capturing = False
                self.done = True

    def handle_data(self, data):
        if self.capturing:
            self.parts.append(data)

    def text(self) -> str:
        return re.sub(r"\s+", " ", "".join(self.parts))


def load_page(url: str, html_dir: Path | None, cache: dict[str, str]) -> str:
    page = url.split("#", 1)[0]
    if page not in cache:
        if html_dir is not None:
            version = re.search(r"/whatsnew/(3\.\d+)\.html", page).group(1)
            cache[page] = (html_dir / f"{version}.html").read_text(encoding="utf-8")
        else:
            req = urllib.request.Request(page, headers={"User-Agent": "stdlib-radar verify_docs"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                cache[page] = resp.read().decode("utf-8")
    return cache[page]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--html-dir", type=Path, help="directory with saved 3.13.html, 3.14.html, 3.15.html")
    args = ap.parse_args()

    entries = json.loads(DATA.read_text(encoding="utf-8"))["entries"]
    cache: dict[str, str] = {}
    failures = 0
    for e in entries:
        url = e["doc"]
        if not url.startswith(f"https://docs.python.org/{e['removed_in']}/whatsnew/{e['removed_in']}.html#"):
            print(f"FAIL {e['id']}: doc URL does not point at What's New in {e['removed_in']}: {url}")
            failures += 1
            continue
        anchor = url.split("#", 1)[1]
        parser = SectionText(anchor)
        parser.feed(load_page(url, args.html_dir, cache))
        if not parser.found:
            print(f"FAIL {e['id']}: anchor #{anchor} not found")
            failures += 1
        elif not re.search(r"(?<!\w)" + re.escape(e["doc_quote"]) + r"(?!\w)", parser.text()):
            print(f"FAIL {e['id']}: {e['doc_quote']!r} not in #{anchor}")
            failures += 1
        else:
            print(f"ok   {e['id']}: {e['doc_quote']!r} in #{anchor}")
    print(f"{len(entries) - failures}/{len(entries)} entries verified")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
