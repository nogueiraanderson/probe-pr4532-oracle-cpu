"""Run one PR 4532 reproducer on the PR tree and, with --control, on a patched copy.

  python3 -B repro/harness/run_check.py <ID> --pr pr/ps/jenkins --out repro/out [--control]
          [--fixes repro/fixes] [--live] [--stub-a DIR --stub-b DIR --result-a R --result-b R
           --number-a N --number-b N --stub-job NAME]

Writes repro/out/<ID>.json and prints one verdict line per tree plus evidence.
Exit code is 0 unless the arguments are wrong: the report step decides the build result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from checks import CHECKS, HARNESS_ERROR, INSPECTION_ONLY, NOT_REPRODUCED, REPRODUCED, STATIC_ONLY, Context, Outcome  # noqa: E402
from pollrun import HarnessError  # noqa: E402


def run_detector(check_id: str, ctx: Context) -> Outcome:
    try:
        return CHECKS[check_id](ctx)
    except HarnessError as exc:
        return Outcome(HARNESS_ERROR, [f"harness: {exc}"])
    except Exception as exc:  # noqa: BLE001, any crash is a harness error, never a verdict
        return Outcome(HARNESS_ERROR, [f"harness crashed: {type(exc).__name__}: {exc}", traceback.format_exc()[-1500:]])


def _tree_digest(root: Path) -> dict[str, str]:
    digests = {}
    for path in sorted(root.rglob("*")):
        if path.is_file() and "__pycache__" not in path.parts:
            digests[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def apply_patch(pr_dir: Path, patch: Path, control_root: Path) -> tuple[Path, list[str]]:
    """Copy ps/jenkins from the PR tree into its own git repo and apply the fix patch there.

    The copy is made a repository of its own on purpose: inside a Jenkins
    workspace (a git worktree) `git apply` resolves patch paths against the
    enclosing repo root and silently ignores paths outside the current
    directory, exit 0. Fail closed: the patched files must really change.
    """
    if control_root.exists():
        shutil.rmtree(control_root)
    target = control_root / "ps" / "jenkins"
    shutil.copytree(pr_dir, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    before = _tree_digest(target)
    init = subprocess.run(["git", "init", "-q", "."], cwd=str(control_root), capture_output=True, text=True)
    if init.returncode != 0:
        raise HarnessError(f"git init of the control copy failed: {init.stderr.strip()[:200]}")
    check = subprocess.run(["git", "apply", "--check", str(patch.resolve())], cwd=str(control_root), capture_output=True, text=True)
    if check.returncode != 0:
        raise HarnessError(f"fix patch does not apply: {check.stderr.strip()[:400]}")
    applied = subprocess.run(["git", "apply", "--verbose", str(patch.resolve())], cwd=str(control_root), capture_output=True, text=True)
    if applied.returncode != 0:
        raise HarnessError(f"git apply failed: {applied.stderr.strip()[:400]}")
    after = _tree_digest(target)
    changed = sorted(name for name in before if before[name] != after.get(name)) + sorted(set(after) - set(before))
    if not changed:
        raise HarnessError("git apply reported success but no file in the control copy changed")
    expected = sorted(set(re.findall(r"^\+\+\+ b/ps/jenkins/(.+)$", patch.read_text(encoding="utf-8"), re.M)))
    if expected and sorted(changed) != expected:
        raise HarnessError(f"patch touched {changed}, expected {expected}")
    return target, [f"{name} changed, sha256 {before.get(name, 'new')[:12]} -> {after[name][:12]}" for name in changed]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("check_id", choices=sorted(CHECKS))
    parser.add_argument("--pr", required=True, help="PR tree ps/jenkins directory")
    parser.add_argument("--out", required=True)
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--fixes", default=str(Path(__file__).resolve().parent.parent / "fixes"))
    parser.add_argument("--live", action="store_true")
    for name in ("stub-a", "stub-b", "result-a", "result-b", "number-a", "number-b", "stub-job"):
        parser.add_argument(f"--{name}", default="")
    args = parser.parse_args()

    check_id = args.check_id
    pr_dir = Path(args.pr).resolve()
    out_root = Path(args.out).resolve() / check_id
    out_root.mkdir(parents=True, exist_ok=True)
    extra = {
        key.replace("-", "_"): getattr(args, key.replace("-", "_"))
        for key in ("stub-a", "stub-b", "result-a", "result-b", "number-a", "number-b", "stub-job")
    }
    started = time.monotonic()

    pr_outcome = run_detector(check_id, Context(pr_dir=pr_dir, out_dir=out_root / "pr", live=args.live, extra=extra))

    patch = Path(args.fixes) / f"{check_id}.patch"
    control_mode = "skipped"
    control_outcome: Outcome | None = None
    patch_stat: list[str] = []
    if check_id in INSPECTION_ONLY:
        control_mode = "inspection"
    elif args.control and pr_outcome.verdict == REPRODUCED:
        if not patch.is_file():
            control_mode = "missing-patch"
            control_outcome = Outcome(HARNESS_ERROR, [f"no fix patch at {patch}"])
        else:
            control_mode = "run"
            try:
                control_dir, patch_stat = apply_patch(pr_dir, patch, out_root / "control")
                control_outcome = run_detector(check_id, Context(pr_dir=control_dir, out_dir=out_root / "control-out", live=False, extra=extra))
            except HarnessError as exc:
                control_outcome = Outcome(HARNESS_ERROR, [f"harness: {exc}"])
    elif args.control:
        control_mode = "not-needed"

    control_flipped = None
    if control_mode == "run" and control_outcome is not None:
        control_flipped = control_outcome.verdict == NOT_REPRODUCED

    record = {
        "id": check_id,
        "static": check_id in STATIC_ONLY,
        "verdict_pr": pr_outcome.verdict,
        "evidence_pr": pr_outcome.evidence,
        "data_pr": pr_outcome.data,
        "control_mode": control_mode,
        "verdict_control": control_outcome.verdict if control_outcome else ("BY_INSPECTION" if control_mode == "inspection" else "-"),
        "evidence_control": control_outcome.evidence if control_outcome else [],
        "control_flipped": control_flipped,
        "patch": str(Path("repro/fixes") / f"{check_id}.patch") if patch.is_file() else None,
        "patch_stat": patch_stat,
        "elapsed_s": round(time.monotonic() - started, 1),
    }
    (Path(args.out).resolve() / f"{check_id}.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")

    print(f"{check_id} PR={record['verdict_pr']} CONTROL={record['verdict_control']} mode={control_mode} flipped={control_flipped}")
    for line in pr_outcome.evidence:
        print(f"  pr: {line}")
    if control_outcome:
        for line in control_outcome.evidence:
            print(f"  control: {line}")
        for line in patch_stat:
            print(f"  patch: {line}")


if __name__ == "__main__":
    main()
