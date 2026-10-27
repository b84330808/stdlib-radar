"""The curated table of stdlib removals and behaviour changes (data/changes.json)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources

SEVERITIES = ("import", "call", "behavior")
CONFIDENCES = ("low", "medium", "high")
CATEGORIES = ("removed", "changed", "encoding")


def parse_version(text: str) -> tuple[int, int]:
    """'3.15' -> (3, 15). Raises ValueError for anything else."""
    parts = text.strip().split(".")
    if len(parts) < 2 or not all(p.isdigit() for p in parts[:2]):
        raise ValueError(f"not a Python version: {text!r}")
    return int(parts[0]), int(parts[1])


@dataclass(frozen=True)
class Entry:
    id: str
    removed_in: str
    category: str
    kind: str
    api: str
    effect: str
    raises: str
    confidence: str
    message: str
    fix: str
    doc: str
    doc_quote: str
    targets: tuple[str, ...] = ()
    check: str = ""
    owners: tuple[str, ...] = ()
    called: bool = False
    min_args: int = 0
    max_args: int | None = None
    allowed_keywords: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    keywords_except: tuple[str, ...] = ()
    any_keyword: bool = False
    max_positional: int | None = None
    backports: tuple[str, ...] = ()
    extra: dict = field(default_factory=dict, compare=False, hash=False)

    @property
    def version(self) -> tuple[int, int]:
        return parse_version(self.removed_in)


_TUPLE_FIELDS = ("targets", "owners", "keywords", "keywords_except", "backports", "allowed_keywords")


@lru_cache(maxsize=None)
def load_entries() -> tuple[Entry, ...]:
    raw = json.loads(resources.files("stdlib_radar").joinpath("data/changes.json").read_text(encoding="utf-8"))
    known = set(Entry.__dataclass_fields__)
    entries = []
    for item in raw["entries"]:
        kwargs = {k: (tuple(v) if k in _TUPLE_FIELDS else v) for k, v in item.items() if k in known}
        kwargs["extra"] = {k: v for k, v in item.items() if k not in known}
        entries.append(Entry(**kwargs))
    return tuple(entries)


def select_entries(
    target: tuple[int, int],
    since: tuple[int, int],
    categories: frozenset[str],
) -> tuple[Entry, ...]:
    """Entries with since < removed_in <= target in the chosen categories (detectable kinds only)."""
    return tuple(
        e
        for e in load_entries()
        if e.kind != "undetected" and e.category in categories and since < e.version <= target
    )


def known_versions() -> list[str]:
    return sorted({e.removed_in for e in load_entries()}, key=parse_version)
