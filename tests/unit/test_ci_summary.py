"""The combined CI summary: each gate's row, the verdict, the sticky comment."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from repowise.cli.ci import write_gate_summary
from repowise.cli.commands.ci_summary_cmd import ci_summary_command
from repowise.core.analysis import health_gate, security_gate
from repowise.core.analysis.doc_drift import render as doc_drift_render
from repowise.core.analysis.doc_drift.gate import evaluate_gate
from repowise.core.analysis.health.coverage import file_coverage
from repowise.core.analysis.patch_coverage import compute_patch_coverage
from repowise.core.analysis.patch_coverage import gate_summary as coverage_summary
from repowise.core.ci.markdown import ROW_LIMIT
from repowise.core.ci.summary import (
    COMMENT_MARKER,
    GateSummary,
    SummaryFinding,
    combined_verdict,
    fingerprint_marker,
    fingerprints_in,
    render_comment,
    render_job_summary,
    with_exit_code,
)


def _finding(fp: str = "abc", level: str = "error", line: int | None = 3) -> SummaryFinding:
    return SummaryFinding(level, "src/a.py", line, "Too complex", fp)


@pytest.mark.parametrize(
    ("verdicts", "expected"),
    [
        ((), "pass"),
        (("pass", "pass"), "pass"),
        (("pass", "warn"), "warn"),
        (("warn", "fail"), "fail"),
        (("pass", "error"), "fail"),
    ],
)
def test_combined_verdict(verdicts, expected) -> None:
    assert combined_verdict(GateSummary(f"g{i}", v, "") for i, v in enumerate(verdicts)) == expected


def test_the_exit_code_decides_fail_and_could_not_evaluate() -> None:
    passing = GateSummary("security", "pass", "No new finding.")
    assert with_exit_code(passing, "security", 0) is passing
    # A check layered on the gate (a grown baseline) fails it without a failing finding.
    assert with_exit_code(passing, "security", 1).verdict == "fail"
    assert with_exit_code(passing, "security", 2).verdict == "error"
    missing = with_exit_code(None, "health", 0)
    assert (missing.gate, missing.verdict) == ("health", "error")


def test_comment_lists_findings_with_a_fingerprint_marker_each() -> None:
    gates = [
        GateSummary("health", "fail", "Fails on 1 finding.", (_finding("f1"),)),
        GateSummary("security", "pass", "No new finding."),
    ]
    body = render_comment(gates)
    assert body.startswith(COMMENT_MARKER + "\n")
    assert "### Repowise gates: fail" in body
    assert "| Health | Fail | Fails on 1 finding. |" in body
    assert "| Security | Pass | No new finding. |" in body
    assert "#### Security" not in body
    line = next(x for x in body.splitlines() if "Too complex" in x)
    assert line.startswith("- error `src/a.py:3`")
    assert line.endswith(fingerprint_marker("health", "f1"))
    assert fingerprints_in(body) == {"health:f1"}


def test_comment_caps_each_gate_and_counts_the_rest() -> None:
    findings = tuple(_finding(f"f{i}", line=i + 1) for i in range(ROW_LIMIT + 3))
    body = render_comment([GateSummary("health", "fail", "x", findings)])
    assert len(fingerprints_in(body)) == ROW_LIMIT
    assert "And 3 more findings. See the job summary." in body


def test_comment_counts_findings_resolved_since_the_previous_one() -> None:
    before = render_comment(
        [GateSummary("health", "fail", "x", (_finding("kept"), _finding("gone")))]
    )
    after = render_comment(
        [GateSummary("health", "fail", "x", (_finding("kept"),))], previous=before
    )
    assert "Resolved since the last run: 1 finding." in after
    again = render_comment(
        [GateSummary("health", "fail", "x", (_finding("kept"),))], previous=after
    )
    assert "Resolved" not in again


def test_a_marker_never_closes_its_html_comment_early() -> None:
    marker = fingerprint_marker("doc-drift", "a-->b <x>")
    assert marker.count("-->") == 1 and marker.endswith(" -->")
    assert fingerprints_in(marker) == {"doc-drift:a-_b__x_"}


def test_job_summary_is_the_table_alone() -> None:
    text = render_job_summary([GateSummary("health", "warn", "Passed with 1 warning.", (_finding(),))])
    assert "| Health | Warn | Passed with 1 warning. |" in text
    assert "Too complex" not in text and COMMENT_MARKER not in text


def test_summary_round_trips_through_json() -> None:
    summary = GateSummary("health", "warn", "h", (_finding(line=None),))
    assert GateSummary.from_dict(json.loads(json.dumps(summary.to_dict()))) == summary


# -- each gate's row ----------------------------------------------------------


def test_health_row_lists_errors_and_warnings_but_not_notes() -> None:
    def gf(level: str, fp: str) -> health_gate.GateFinding:
        return health_gate.GateFinding("health", "nesting", level, "a.py", 4, "Deep", fp)

    result = health_gate.assemble(
        [gf("error", "e"), gf("warning", "w"), gf("note", "n")], fail_on="introduced"
    )
    row = health_gate.gate_summary(result)
    assert (row.gate, row.verdict) == ("health", "fail")
    assert [(f.level, f.fingerprint) for f in row.findings] == [("error", "e"), ("warning", "w")]


def _security_row(kind="eval_call", severity="high", snippet="eval(x)", line=1):
    return {
        "file_path": "a.py",
        "line_number": line,
        "kind": kind,
        "severity": severity,
        "snippet": snippet,
        "fingerprint": security_gate.fingerprint_of("a.py", kind, snippet),
        "commit": None,
    }


def test_security_row_warns_below_the_threshold_and_skips_the_baseline() -> None:
    low = _security_row("weak_hash", "low", "md5")
    high = _security_row()
    gate = security_gate.evaluate([low], fail_on="high")
    row = security_gate.gate_summary([low], gate)
    assert row.verdict == "warn" and [f.level for f in row.findings] == ["warning"]

    gate = security_gate.evaluate([high, low], fail_on="high")
    row = security_gate.gate_summary([high, low], gate)
    assert row.verdict == "fail" and row.headline == "1 new finding at high or above."
    assert row.findings[0].fingerprint == high["fingerprint"]

    accepted = security_gate.evaluate([high], baseline=frozenset({high["fingerprint"]}))
    assert security_gate.gate_summary([high], accepted).findings == ()


def test_doc_drift_row_lists_failing_findings_only() -> None:
    finding = {
        "file_path": "docs/a.md",
        "line_number": 7,
        "kind": "path",
        "target": "src/gone.py",
        "confidence": 0.95,
        "reason": "src/gone.py does not exist.",
        "origin": "markdown_link",
    }
    weak = {**finding, "target": "src/maybe.py", "confidence": 0.1}
    row = doc_drift_render.gate_summary(evaluate_gate([finding, weak]))
    assert row.verdict == "fail"
    assert [f.path for f in row.findings] == ["docs/a.md"]
    moved = doc_drift_render.gate_summary(evaluate_gate([{**finding, "line_number": 40}]))
    assert moved.findings[0].fingerprint == row.findings[0].fingerprint
    assert doc_drift_render.gate_summary(evaluate_gate([weak])).verdict == "pass"


def test_coverage_row_names_each_file_with_uncovered_changes_by_path() -> None:
    coverage = {"src/a.py": file_coverage("src/a.py", [1], [1, 2, 3])}
    pc = compute_patch_coverage({"src/a.py": {1, 2, 3}}, coverage, threshold=80)
    row = coverage_summary(pc)
    assert row.verdict == "fail"
    (f,) = row.findings
    assert (f.path, f.line) == ("src/a.py", None)
    assert "2 changed lines not covered" in f.message
    other = compute_patch_coverage({"src/a.py": {2}}, coverage)
    assert coverage_summary(other).findings[0].fingerprint == f.fingerprint
    assert coverage_summary(other).verdict == "pass"


# -- the CLI side -------------------------------------------------------------


def test_each_gate_leaves_its_row_only_when_the_action_asks(tmp_path) -> None:
    row = GateSummary("security", "pass", "No new finding.")
    assert not write_gate_summary(row, env={})
    env = {"REPOWISE_GATE_SUMMARY_DIR": str(tmp_path / "rows")}
    assert write_gate_summary(row, env=env)
    saved = json.loads((tmp_path / "rows" / "security.json").read_text(encoding="utf-8"))
    assert GateSummary.from_dict(saved) == row


def test_ci_summary_command_writes_the_comment_and_prints_the_verdict(tmp_path) -> None:
    rows = tmp_path / "rows"
    env = {"REPOWISE_GATE_SUMMARY_DIR": str(rows)}
    write_gate_summary(GateSummary("health", "warn", "w", (_finding(level="warning"),)), env=env)
    write_gate_summary(GateSummary("security", "pass", "ok"), env=env)
    step_summary = tmp_path / "step.md"
    comment = tmp_path / "comment.md"
    previous = tmp_path / "previous.md"
    previous.write_text(fingerprint_marker("security", "old"), encoding="utf-8")
    result = CliRunner().invoke(
        ci_summary_command,
        [
            str(rows),
            "--gate", "health=0",
            "--gate", "security=0",
            "--gate", "doc-drift=2",
            "--previous", str(previous),
            "--comment-file", str(comment),
        ],
        env={"GITHUB_STEP_SUMMARY": str(step_summary)},
    )  # fmt: skip
    assert result.exit_code == 0, result.output
    assert result.output.strip() == "fail"
    body = comment.read_text(encoding="utf-8")
    assert "| Doc drift | Could not evaluate |" in body
    assert "Resolved since the last run: 1 finding." in body
    assert "| Health | Warn | w |" in step_summary.read_text(encoding="utf-8")


def test_ci_summary_command_rejects_a_malformed_gate(tmp_path) -> None:
    result = CliRunner().invoke(ci_summary_command, [str(tmp_path), "--gate", "health"])
    assert result.exit_code == 2
    assert "NAME=EXIT_CODE" in result.output
