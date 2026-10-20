"""One summary over every gate a CI run judged: a sticky pull-request comment,
a job-summary table and a combined verdict.

Each gate maps its own result to a :class:`GateSummary` (a ``gate_summary``
function beside it); this module renders any list of them. Everything is a
pure function over in-memory values, so a caller that builds gate results
without a checkout renders the same comment the Action posts.

Every finding line in the comment ends in a hidden marker naming the gate and
the finding's line-free fingerprint, so a later run, or any other reader of
the comment, can tell which findings are gone (:func:`fingerprints_in`).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .markdown import ROW_LIMIT, cell, code, more_line, plural

PASS, WARN, FAIL = "pass", "warn", "fail"
#: The gate could not run (exit code 2); the combined verdict counts it as a fail.
ERROR = "error"
VERDICTS = (PASS, WARN, FAIL, ERROR)

#: Finding levels, as SARIF names them.
LEVELS = ("error", "warning", "note")

#: Opens the sticky comment; a run finds its earlier comment by it.
COMMENT_MARKER = "<!-- repowise-ci-summary -->"
_FINGERPRINT_TAG = "repowise-fingerprint:v1:"
_FINGERPRINT_RE = re.compile(r"<!-- " + re.escape(_FINGERPRINT_TAG) + r"([A-Za-z0-9_.:-]+) -->")
#: Kept out of a marker: anything that could end the HTML comment early.
_UNSAFE = re.compile(r"[^A-Za-z0-9_.:-]")

_TITLES = {
    "coverage": "Coverage",
    "doc-drift": "Doc drift",
    "security": "Security",
    "health": "Health",
    "risk": "Change risk",
}
_VERDICT_WORDS = {PASS: "Pass", WARN: "Warn", FAIL: "Fail", ERROR: "Could not evaluate"}


@dataclass(frozen=True)
class SummaryFinding:
    """One finding as the summary lists it."""

    level: str
    path: str
    line: int | None
    message: str
    #: Line-free, as the gate's SARIF ``partialFingerprints`` carries it.
    fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level,
            "file_path": self.path,
            "line_number": self.line,
            "message": self.message,
            "fingerprint": self.fingerprint,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> SummaryFinding:
        line = d.get("line_number")
        return cls(
            str(d["level"]),
            str(d["file_path"]),
            int(line) if line else None,
            str(d["message"]),
            str(d["fingerprint"]),
        )


@dataclass(frozen=True)
class GateSummary:
    """One gate's verdict, a one-line headline, and the findings worth listing."""

    gate: str
    verdict: str
    headline: str
    findings: tuple[SummaryFinding, ...] = ()

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError(f"unknown gate verdict {self.verdict!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate": self.gate,
            "verdict": self.verdict,
            "headline": self.headline,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> GateSummary:
        return cls(
            str(d["gate"]),
            str(d["verdict"]),
            str(d.get("headline") or ""),
            tuple(SummaryFinding.from_dict(f) for f in d.get("findings") or ()),
        )


def with_exit_code(summary: GateSummary | None, gate: str, exit_code: int) -> GateSummary:
    """*summary* reconciled with the gate's exit code, which decides fail and error.

    A gate that exits 1 failed even when its own result reads as a pass (a check
    layered on top, such as a grown baseline); exit 2, or no summary at all,
    means it could not be evaluated.
    """
    if exit_code not in (0, 1) or summary is None:
        headline = summary.headline if summary else "See the job log for why."
        findings = summary.findings if summary else ()
        return GateSummary(gate, ERROR, headline, findings)
    if exit_code == 1 and summary.verdict != FAIL:
        return GateSummary(gate, FAIL, summary.headline, summary.findings)
    if exit_code == 0 and summary.verdict in (FAIL, ERROR):
        return GateSummary(gate, WARN, summary.headline, summary.findings)
    return summary


def combined_verdict(gates: Iterable[GateSummary]) -> str:
    """``fail`` when any gate failed or could not run, else ``warn`` on any warning, else ``pass``."""
    verdicts = {g.verdict for g in gates}
    if verdicts & {FAIL, ERROR}:
        return FAIL
    return WARN if WARN in verdicts else PASS


def fingerprint_marker(gate: str, fingerprint: str) -> str:
    """The hidden ``<!-- repowise-fingerprint:v1:<gate>:<id> -->`` marker for one finding."""
    return f"<!-- {_FINGERPRINT_TAG}{marker_key(gate, fingerprint)} -->"


def marker_key(gate: str, fingerprint: str) -> str:
    """``<gate>:<id>``, the key :func:`fingerprints_in` returns, safe inside a marker."""
    return f"{_safe(gate)}:{_safe(fingerprint)}"


def _safe(text: str) -> str:
    return re.sub(r"-{2,}", "-", _UNSAFE.sub("_", text))


def fingerprints_in(body: str) -> frozenset[str]:
    """The ``<gate>:<id>`` keys an earlier comment's finding markers carry."""
    return frozenset(_FINGERPRINT_RE.findall(body or ""))


def render_comment(gates: Sequence[GateSummary], *, previous: str | None = None) -> str:
    """The sticky comment: the marker, the verdict table, then each gate's findings.

    Each gate lists its first :data:`~.markdown.ROW_LIMIT` findings, errors
    first. With *previous* (the comment this replaces), findings it listed
    that no gate reports any more are counted as resolved.
    """
    lines = [COMMENT_MARKER, *_table(gates)]
    for g in gates:
        if g.findings:
            lines += ["", f"#### {cell(_title(g.gate))}", *_finding_lines(g)]
    if previous is not None:
        current = {marker_key(g.gate, f.fingerprint) for g in gates for f in g.findings}
        resolved = len(fingerprints_in(previous) - current)
        if resolved:
            lines += ["", f"Resolved since the last run: {plural(resolved, 'finding')}."]
    return "\n".join(lines) + "\n"


def render_job_summary(gates: Sequence[GateSummary]) -> str:
    """The verdict table alone; each gate writes its own details to the job summary."""
    return "\n".join(_table(gates)) + "\n"


def _table(gates: Sequence[GateSummary]) -> list[str]:
    verdict = combined_verdict(gates)
    lines = [f"### Repowise gates: {_VERDICT_WORDS[verdict].lower()}", ""]
    if not gates:
        return [*lines, "No gate ran."]
    lines += ["| Gate | Result | Summary |", "| --- | --- | --- |"]
    lines += [
        f"| {cell(_title(g.gate))} | {_VERDICT_WORDS[g.verdict]} | {cell(g.headline)} |"
        for g in gates
    ]
    return lines


_LEVEL_ORDER = {level: i for i, level in enumerate(LEVELS)}


def _finding_lines(g: GateSummary) -> list[str]:
    ordered = sorted(
        g.findings, key=lambda f: (_LEVEL_ORDER.get(f.level, len(LEVELS)), f.path, f.line or 0)
    )
    out = [
        f"- {f.level} {code(f'{f.path}:{f.line}' if f.line else f.path)} {cell(f.message)} "
        f"{fingerprint_marker(g.gate, f.fingerprint)}"
        for f in ordered[:ROW_LIMIT]
    ]
    if rest := more_line(len(ordered) - ROW_LIMIT, "findings"):
        out.append(f"- {rest[0].upper()}{rest[1:]} See the job summary.")
    return out


def _title(gate: str) -> str:
    return _TITLES.get(gate, gate)
