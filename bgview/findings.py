"""Shared finding/severity vocabulary used by every other bgview module.

Deliberately dependency-free (stdlib only, no imports of sibling bgview
modules) so it can sit at the bottom of the import graph.
"""

from __future__ import annotations

import dataclasses
import enum
import os


class Severity(enum.IntEnum):
    """Finding severity. Ordered so `>=` threshold comparisons (V16) just work."""

    INFO = 10
    WARN = 20
    ERROR = 30

    @classmethod
    def parse(cls, s: str) -> "Severity":
        """Parse "info"|"warn"|"error" (case-insensitive) into a Severity."""
        try:
            return cls[s.strip().upper()]
        except KeyError:
            raise ValueError(
                f"unknown severity {s!r}; expected one of "
                f"{[m.name.lower() for m in cls]}"
            ) from None


@dataclasses.dataclass(frozen=True)
class Finding:
    """One detector hit. Always traceable to a real source location (V15)."""

    file: str          # absolute path of the source .xml
    line: int           # 1-based; V15 forbids line==0
    severity: Severity
    detector: str       # "D1".."D16"
    message: str
    node: str | None = None
    tag: str | None = None

    def __post_init__(self) -> None:
        # V15: "∀ finding carries file:line ... ⊥ finding w/o location" and
        # explicitly "line == 0 is forbidden". Enforced here, at construction,
        # so no detector can silently emit an unlocated finding.
        if self.line <= 0:
            raise ValueError(
                f"Finding.line must be a 1-based line number (V15 forbids "
                f"line==0); got {self.line!r} from detector={self.detector!r}"
            )
        if not self.file:
            raise ValueError("Finding.file must be a non-empty path (V15)")

    def key(self) -> tuple:
        """Identity for dedup/baseline comparison: (full path, detector, tag-or-node-or-message).

        §B.2: this used `os.path.basename(file)`, which silently collapsed findings
        from same-named files in different directories. That is not hypothetical --
        V21's pinned FP-budget set contains TWO files both named
        `BuildEditorAndTools.xml` (`Examples/` and `Examples/FPSBuildGraph/`), so a
        budget check reaching for `.key()` would have seen 1 finding where there are
        2 and passed while silently losing one. Normalised full path, not basename.
        """
        return (
            os.path.normcase(os.path.normpath(self.file)),
            self.detector,
            self.tag or self.node or self.message,
        )
