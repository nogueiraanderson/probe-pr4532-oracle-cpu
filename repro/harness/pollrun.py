"""Drive one poll of the PR code against the mock and collect the evidence."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from mockoracle import MockOracle

HERE = Path(__file__).resolve().parent
RUNNER = HERE / "rewrite_runner.py"
POLL_FILES = ("cpu-state.json", "cpu-bug-cve.json", "cpu-notify.json", "cpu-run.json")


@dataclass
class PollResult:
    rc: int | None
    killed: bool
    elapsed: float
    workdir: Path
    opens: list[dict[str, Any]] = field(default_factory=list)
    http: list[dict[str, Any]] = field(default_factory=list)
    mock_hits: list[dict[str, Any]] = field(default_factory=list)
    maxrss_kb: int = 0
    rewrite_active: bool = False
    stdout_tail: str = ""
    stderr_tail: str = ""

    def file(self, name: str) -> Path:
        return self.workdir / name

    def json(self, name: str) -> Any:
        path = self.file(name)
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return None

    @property
    def state(self) -> Any:
        return self.json("cpu-state.json")

    @property
    def bugs(self) -> dict[str, list[str]]:
        data = self.json("cpu-bug-cve.json")
        return dict(data.get("bugs", {})) if isinstance(data, dict) else {}

    @property
    def manifest_items(self) -> list[dict[str, Any]]:
        data = self.json("cpu-notify.json")
        items = data.get("items") if isinstance(data, dict) else None
        return [item for item in (items or []) if isinstance(item, dict)]

    @property
    def report(self) -> dict[str, Any]:
        data = self.json("cpu-run.json")
        return data if isinstance(data, dict) else {}

    @property
    def notes(self) -> list[dict[str, Any]]:
        return [note for note in self.report.get("notes", []) if isinstance(note, dict)]

    def warning_notes(self) -> list[dict[str, Any]]:
        return [note for note in self.notes if note.get("level") in ("warning", "error")]

    def foreign_opens(self) -> list[dict[str, Any]]:
        """Original urls that are not https on www.oracle.com."""
        return [
            event
            for event in self.opens
            if event.get("scheme") != "https" or not str(event.get("host", "")).endswith("oracle.com")
        ]


def _tail(path: Path, lines: int = 12) -> str:
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(text[-lines:])


def run_poll(
    pr_dir: Path,
    workdir: Path,
    scenario_builder: Callable[[MockOracle], dict[str, Any]],
    *,
    hosts: tuple[str, ...] = ("127.0.0.1",),
    seed_state: dict[str, Any] | None = None,
    count: int = 10,
    notify: str = "none",
    ignore_state: bool = False,
    deadline_s: float = 300.0,
    rewrite: bool = True,
) -> PollResult:
    """Run cpu_cves.py once in a subprocess against a fresh mock, then collect everything."""
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)
    if seed_state is not None:
        (workdir / "cpu-state.json").write_text(json.dumps(seed_state, indent=2) + "\n", encoding="utf-8")
    mock = MockOracle(hosts).start()
    try:
        mock.scenario = scenario_builder(mock)
        log_path = workdir / "harness-http.jsonl"
        command = [
            sys.executable,
            "-B",
            str(RUNNER),
            "--pr",
            str(pr_dir),
            "--log",
            str(log_path),
            "--mock",
            mock.base(),
        ]
        if not rewrite:
            command.append("--no-rewrite")
        command += [
            "--",
            "--state",
            "cpu-state.json",
            "--bugs",
            "cpu-bug-cve.json",
            "--notify-manifest",
            "cpu-notify.json",
            "--report",
            "cpu-run.json",
            "--notify",
            notify,
            "--count",
            str(count),
        ]
        if ignore_state:
            command.append("--ignore-state")
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
        started = time.monotonic()
        killed = False
        with open(workdir / "poll.stdout", "w", encoding="utf-8") as out, open(
            workdir / "poll.stderr", "w", encoding="utf-8"
        ) as err:
            process = subprocess.Popen(command, cwd=str(workdir), stdout=out, stderr=err, env=env, start_new_session=True)
            try:
                rc: int | None = process.wait(timeout=deadline_s)
            except subprocess.TimeoutExpired:
                killed = True
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=30)
                rc = None
        elapsed = round(time.monotonic() - started, 2)
    finally:
        mock.stop()
    result = PollResult(rc=rc, killed=killed, elapsed=elapsed, workdir=workdir, mock_hits=mock.hits())
    if log_path.is_file():
        for line in log_path.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("ev") == "open":
                result.opens.append(event)
            elif event.get("ev") in ("http", "http_done"):
                result.http.append(event)
            elif event.get("ev") == "exit":
                result.maxrss_kb = int(event.get("maxrss_kb") or 0)
    result.rewrite_active = any(event.get("rewritten") for event in result.opens)
    result.stdout_tail = _tail(workdir / "poll.stdout")
    result.stderr_tail = _tail(workdir / "poll.stderr")
    return result


class HarnessError(Exception):
    """The harness could not prove its own stub ran. Never a NOT_REPRODUCED."""


def assert_mock_hit(result: PollResult, *, expect_rewrite: bool = True) -> list[str]:
    """Fail closed: the mock must have served the PR code through the rewrite."""
    evidence: list[str] = []
    if not result.mock_hits:
        raise HarnessError("mock received no request, the PR code never reached the fixture")
    first = result.mock_hits[0]
    evidence.append(f"mock-hit: {len(result.mock_hits)} requests, first {first['host']}:{first['port']}{first['path']} status={first['status']}")
    if expect_rewrite:
        if not result.rewrite_active:
            raise HarnessError("rewrite never fired, no https://www.oracle.com url was redirected to the mock")
        rewritten = [event for event in result.opens if event.get("rewritten")]
        evidence.append(f"rewrite-active: {len(rewritten)} oracle.com urls mapped to {rewritten[0]['target'].split('/', 3)[2]}")
    return evidence
