"""Aggregate repro/out/*.json into the build report, summary table and description.

  python3 -B repro/harness/report.py repro/out

Writes repro/out/repro-report.json, repro-summary.txt, repro-description.html
and repro-result.txt (SUCCESS, UNSTABLE or FAILURE) for the Jenkinsfile.
"""

from __future__ import annotations

import html
import json
import sys
from pathlib import Path

ORDER = [
    "SCOPE_ALL_PRODUCTS",
    "NO_DEADLINE",
    "REDIRECT_ANY_HOST",
    "NO_SIZE_CAP",
    "EMPTY_CSAF_WIPES_CACHE",
    "MODHIST_DRIFT",
    "SILENT_RESEED",
    "ABORT_AFTER_ACK_DUPLICATE",
    "NO_FAILURE_ALERT",
]


def table(rows: list[dict], widths: dict[str, int]) -> str:
    columns = ["ID", "VERDICT_PR", "VERDICT_CONTROL", "EVIDENCE"]
    lines = ["  ".join(column.ljust(widths[column]) for column in columns).rstrip()]
    for row in rows:
        lines.append("  ".join(str(row[column]).ljust(widths[column]) for column in columns).rstrip())
    return "\n".join(lines)


def main() -> None:
    out_dir = Path(sys.argv[1])
    bugs_filter = (sys.argv[2] if len(sys.argv) > 2 else "all").strip()
    wanted = set(ORDER) if bugs_filter in ("", "all") else {item.strip() for item in bugs_filter.split(",")}
    records = {}
    for path in out_dir.glob("*.json"):
        if path.name == "repro-report.json":
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        records[record["id"]] = record
    rows = []
    overall = "SUCCESS"
    reasons = []
    for check_id in ORDER:
        record = records.get(check_id)
        if record is None:
            if check_id in wanted:
                overall = "FAILURE"
                reasons.append(f"{check_id}: no result file, the stage failed or timed out")
                rows.append({"ID": check_id, "VERDICT_PR": "HARNESS_ERROR", "VERDICT_CONTROL": "-", "EVIDENCE": "no result file, the stage failed or timed out"})
            else:
                rows.append({"ID": check_id, "VERDICT_PR": "NOT_RUN", "VERDICT_CONTROL": "-", "EVIDENCE": "skipped by the BUGS parameter"})
            continue
        first = next((line for line in record["evidence_pr"] if not line.startswith(("mock-hit", "rewrite-active"))), "")
        verdict_control = record["verdict_control"]
        if record["control_mode"] == "run":
            verdict_control += " (flipped)" if record["control_flipped"] else " (NOT FLIPPED)"
        rows.append({"ID": check_id, "VERDICT_PR": record["verdict_pr"], "VERDICT_CONTROL": verdict_control, "EVIDENCE": first[:110]})
        if record["verdict_pr"] == "HARNESS_ERROR" or (record["control_mode"] == "run" and record["verdict_control"] == "HARNESS_ERROR"):
            overall = "FAILURE"
            reasons.append(f"{check_id}: harness error")
        elif record["control_mode"] == "run" and record["control_flipped"] is False:
            overall = "FAILURE"
            reasons.append(f"{check_id}: control did not flip")
        elif record["verdict_pr"] == "REPRODUCED" and overall != "FAILURE":
            overall = "UNSTABLE"
    widths = {column: max(len(column), *(len(str(row[column])) for row in rows)) for column in ("ID", "VERDICT_PR", "VERDICT_CONTROL", "EVIDENCE")}
    summary = table(rows, widths)
    counts = {
        "reproduced": sum(1 for r in records.values() if r["verdict_pr"] == "REPRODUCED"),
        "not_reproduced": sum(1 for r in records.values() if r["verdict_pr"] == "NOT_REPRODUCED"),
        "harness_error": sum(1 for r in records.values() if r["verdict_pr"] == "HARNESS_ERROR"),
        "controls_flipped": sum(1 for r in records.values() if r["control_flipped"] is True),
        "controls_not_flipped": sum(1 for r in records.values() if r["control_flipped"] is False),
    }
    header = f"PR 4532 reproducers: result={overall} {counts}" + (f" reasons={reasons}" if reasons else "")
    (out_dir / "repro-summary.txt").write_text(header + "\n" + summary + "\n", encoding="utf-8")
    (out_dir / "repro-result.txt").write_text(overall + "\n", encoding="utf-8")
    description_rows = [
        f"{html.escape(row['ID'])}: {html.escape(row['VERDICT_PR'])} / control {html.escape(row['VERDICT_CONTROL'])}" for row in rows
    ]
    (out_dir / "repro-description.html").write_text(
        f"PR 4532 reproducers: {html.escape(overall)}, {counts['reproduced']} reproduced, {counts['controls_flipped']} controls flipped<br>\n"
        + "<br>\n".join(description_rows)
        + "\n",
        encoding="utf-8",
    )
    report = {"result": overall, "counts": counts, "reasons": reasons, "checks": [records[c] for c in ORDER if c in records]}
    (out_dir / "repro-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(header)
    print(summary)
    for check_id in ORDER:
        record = records.get(check_id)
        if not record:
            continue
        print(f"--- {check_id} ({record['elapsed_s']}s)")
        for line in record["evidence_pr"]:
            print(f"  pr: {line}")
        for line in record["evidence_control"]:
            print(f"  control: {line}")


if __name__ == "__main__":
    main()
