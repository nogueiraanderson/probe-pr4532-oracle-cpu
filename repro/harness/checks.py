"""Detectors for the nine PR 4532 findings. Each returns verdict plus evidence lines.

Verdicts: REPRODUCED, NOT_REPRODUCED, HARNESS_ERROR. A runtime check first
proves the mock was hit through the rewrite (assert_mock_hit), otherwise it
is HARNESS_ERROR. Static checks say so in their evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from mockoracle import ORACLE, MockOracle
from pollrun import HarnessError, PollResult, assert_mock_hit, run_poll

REPRODUCED = "REPRODUCED"
NOT_REPRODUCED = "NOT_REPRODUCED"
HARNESS_ERROR = "HARNESS_ERROR"

NEWEST = "cpujul2026"
OLDER = "cpuapr2026"
MYSQL = "Oracle MySQL Risk Matrix"
JAVA = "Oracle Java SE Risk Matrix"
MIB = 1024 * 1024


@dataclass
class Context:
    pr_dir: Path
    out_dir: Path
    live: bool = False
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def groovy(self) -> Path:
        return self.pr_dir / "check_oracle_cpu.groovy"


@dataclass
class Outcome:
    verdict: str
    evidence: list[str]
    data: dict[str, Any] = field(default_factory=dict)


def cve_sha(cves: list[str]) -> str:
    return hashlib.sha256("\n".join(cves).encode()).hexdigest()[:12]


def seed_state(rows: dict[str, tuple[list[str], dict[str, list[str]]]]) -> dict[str, Any]:
    advisories = {}
    for slug, (cves, bug_cves) in rows.items():
        advisories[slug] = {
            "sha": cve_sha(sorted(cves)),
            "cves": sorted(cves),
            "bug_cves": bug_cves,
            "title": f"CPU {slug}",
            "url": f"{ORACLE}/security-alerts/{slug}.html",
        }
    return {"threads": {}, "pending": [], "advisories": advisories}


def base_scenario(mock: MockOracle) -> dict[str, Any]:
    return {
        "slugs": [OLDER, NEWEST],
        "pages": {
            NEWEST: {
                "sections": [(MYSQL, ["CVE-2026-1001", "CVE-2026-1002"])],
                "history": {"cves": ["CVE-2020-9999"]},
            },
            OLDER: {"sections": [(MYSQL, ["CVE-2025-3001"])]},
        },
        "csaf": {
            NEWEST: {"vulns": [{"cve": "CVE-2026-1001", "bug": "111"}, {"cve": "CVE-2026-1002", "bug": "112"}]},
            OLDER: {"vulns": [{"cve": "CVE-2025-3001", "bug": "331"}]},
        },
    }


def tracked(result: PollResult, slug: str) -> list[str]:
    state = result.state
    if not isinstance(state, dict):
        return []
    row = (state.get("advisories") or {}).get(slug) or {}
    return list(row.get("cves") or [])


def bug_cves_of(result: PollResult, slug: str) -> Any:
    state = result.state
    if not isinstance(state, dict):
        return None
    row = (state.get("advisories") or {}).get(slug) or {}
    return row.get("bug_cves")


def manifest_texts(result: PollResult) -> list[str]:
    return [str(item.get("text") or "") for item in result.manifest_items]


def summary(result: PollResult) -> str:
    report = result.report
    return (
        f"rc={result.rc} killed={result.killed} elapsed={result.elapsed}s usable={report.get('usable')} "
        f"degraded={report.get('degraded')} warnings={len(result.warning_notes())} bugs={len(result.bugs)}"
    )


# ---------------------------------------------------------------- 1 SCOPE_ALL_PRODUCTS


def live_scope_evidence(ctx: Context) -> list[str]:
    """Real Oracle, newest advisory only: tracked CVE count versus the MySQL matrix."""
    result = run_poll(ctx.pr_dir, ctx.out_dir / "live", lambda mock: {}, count=1, deadline_s=600, rewrite=False)
    state = result.state if isinstance(result.state, dict) else {}
    advisories = state.get("advisories") or {}
    if not advisories:
        return [f"LIVE: poll produced no advisory ({summary(result)})"]
    slug, row = next(iter(advisories.items()))
    page_url = row.get("url") or f"{ORACLE}/security-alerts/{slug}.html"
    request = urllib.request.Request(page_url, headers={"User-Agent": "percona-pr4532-repro/1.0"})
    with urllib.request.urlopen(request, timeout=120) as response:
        html = response.read().decode("utf-8", "replace")
    section = mysql_section(html)
    mysql_cves = sorted({m.group(0).upper() for m in re.finditer(r"CVE-\d{4}-\d{4,}", section)})
    oracle_hosts = {event["host"] for event in result.opens}
    return [
        f"LIVE {slug}: tracked={len(row.get('cves') or [])} mysql_matrix={len(mysql_cves)} bug_map={len(result.bugs)} hosts={sorted(oracle_hosts)}"
    ]


def mysql_section(html: str) -> str:
    match = re.search(r"<h[1-6][^>]*>\s*Oracle MySQL Risk Matrix\s*</h[1-6]>", html, re.I)
    if not match:
        return ""
    rest = html[match.end() :]
    nxt = re.search(r"<h[1-6][^>]*>[^<]*(?:Risk Matrix|Modification History)[^<]*</h[1-6]>", rest, re.I)
    return rest[: nxt.start()] if nxt else rest


def check_scope_all_products(ctx: Context) -> Outcome:
    def scenario(mock: MockOracle) -> dict[str, Any]:
        scen = base_scenario(mock)
        scen["pages"][NEWEST]["sections"] = [(MYSQL, ["CVE-2026-1001"]), (JAVA, ["CVE-2026-2001"])]
        scen["csaf"][NEWEST] = {
            "vulns": [
                {"cve": "CVE-2026-1001", "bug": "111", "product": "MySQL Server"},
                {"cve": "CVE-2026-2001", "bug": "222", "product": "Java SE", "family": "Oracle Java SE"},
            ]
        }
        return scen

    result = run_poll(ctx.pr_dir, ctx.out_dir / "run", scenario)
    evidence = assert_mock_hit(result)
    cves = tracked(result, NEWEST)
    bugs = result.bugs
    java_tracked = "CVE-2026-2001" in cves
    java_bug = "222" in bugs
    java_notified = any("CVE-2026-2001" in text for text in manifest_texts(result))
    evidence.append(f"tracked {NEWEST}={cves} bug_map_ids={sorted(bugs)} manifest_items={len(result.manifest_items)}")
    evidence.append(f"java_cve_tracked={java_tracked} java_bug_in_map={java_bug} java_in_slack_text={java_notified} ({summary(result)})")
    if ctx.live:
        evidence.extend(live_scope_evidence(ctx))
    verdict = REPRODUCED if (java_tracked or java_bug or java_notified) else NOT_REPRODUCED
    return Outcome(verdict, evidence)


# ---------------------------------------------------------------- 2 NO_DEADLINE


def groovy_options_block(text: str) -> str:
    match = re.search(r"\n    options \{(.*?)\n    \}", text, re.S)
    return match.group(1) if match else ""


def check_no_deadline(ctx: Context) -> Outcome:
    options = groovy_options_block(ctx.groovy.read_text(encoding="utf-8"))
    static_missing = "timeout(" not in options
    evidence = [f"static: pipeline options block has timeout()={'no' if static_missing else 'yes'}"]

    def scenario(mock: MockOracle) -> dict[str, Any]:
        scen = base_scenario(mock)
        scen["index"] = {"drip": [1, 5.0]}
        return scen

    result = run_poll(ctx.pr_dir, ctx.out_dir / "run", scenario, deadline_s=90)
    evidence.extend(assert_mock_hit(result))
    index_hits = [hit for hit in result.mock_hits if hit["path"].startswith("/security-alerts")]
    dripped = sum(int(hit.get("bytes_sent") or 0) for hit in index_hits)
    evidence.append(
        f"runtime: index dripped 1 byte / 5 s, poll {'STILL RUNNING at 90 s, killed' if result.killed else f'finished rc={result.rc}'} after {result.elapsed}s, bytes dripped={dripped}"
    )
    verdict = REPRODUCED if (result.killed or static_missing) else NOT_REPRODUCED
    return Outcome(verdict, evidence)


# ---------------------------------------------------------------- 3 REDIRECT_ANY_HOST


def check_redirect_any_host(ctx: Context) -> Outcome:
    hosts = ("127.0.0.1", "127.0.0.2", "127.0.0.3")

    def scenario(mock: MockOracle) -> dict[str, Any]:
        scen = base_scenario(mock)
        scen["pages"][NEWEST]["csaf_href"] = f"{mock.base('127.0.0.2')}/evil/csaf.json"
        scen["pages"][OLDER]["redirect"] = f"{mock.base('127.0.0.3')}/security-alerts/{OLDER}.html"
        scen["pages"][OLDER]["redirect_from_host"] = "127.0.0.1"
        scen["evil"] = {"/evil/csaf.json": {"vulns": [{"cve": "CVE-2026-6666", "bug": "666"}]}}
        return scen

    result = run_poll(ctx.pr_dir, ctx.out_dir / "run", scenario, hosts=hosts)
    evidence = assert_mock_hit(result)
    foreign = result.foreign_opens()
    evil_bug = "666" in result.bugs
    older_cves = tracked(result, OLDER)
    foreign_used = bool(older_cves)
    evil_hits = len([hit for hit in result.mock_hits if hit["host"] == "127.0.0.2"])
    redirect_hits = len([hit for hit in result.mock_hits if hit["host"] == "127.0.0.3"])
    foreign_urls = [event["scheme"] + "://" + event["host"] + event["path"] for event in foreign][:4]
    evidence.append(
        f"foreign opens={len(foreign)} {foreign_urls} evil_host_hits={evil_hits} redirect_host_hits={redirect_hits}"
    )
    evidence.append(f"evil bug 666 in cpu-bug-cve.json={evil_bug}, {OLDER} CVEs via http://127.0.0.3 redirect={older_cves} ({summary(result)})")
    verdict = REPRODUCED if (evil_bug or (foreign and foreign_used)) else NOT_REPRODUCED
    return Outcome(verdict, evidence)


# ---------------------------------------------------------------- 4 NO_SIZE_CAP


def check_no_size_cap(ctx: Context) -> Outcome:
    pad_mb = 150

    def scenario(mock: MockOracle) -> dict[str, Any]:
        scen = base_scenario(mock)
        scen["pages"][NEWEST]["sections"] = [(MYSQL, ["CVE-2026-1001", "CVE-2026-7777"])]
        scen["csaf"][NEWEST] = {
            "vulns": [{"cve": "CVE-2026-1001", "bug": "111"}, {"cve": "CVE-2026-7777", "bug": "777"}],
            "pad_mb": pad_mb,
        }
        return scen

    result = run_poll(ctx.pr_dir, ctx.out_dir / "run", scenario, deadline_s=900)
    evidence = assert_mock_hit(result)
    csaf_reads = [event for event in result.http if event.get("ev") == "http_done" and event["url"].endswith("csaf.json")]
    max_read = max((int(event.get("bytes") or 0) for event in csaf_reads), default=0)
    served = max((int(hit.get("bytes_sent") or 0) for hit in result.mock_hits if hit["path"].endswith("csaf.json")), default=0)
    bug_landed = "777" in result.bugs
    evidence.append(
        f"csaf body served={served / MIB:.1f} MiB, read by PR={max_read / MIB:.1f} MiB, bug 777 in map={bug_landed}, peak RSS={result.maxrss_kb / 1024:.0f} MiB, {result.elapsed}s"
    )
    evidence.append(summary(result))
    verdict = REPRODUCED if (max_read >= pad_mb * MIB and bug_landed and result.rc == 0) else NOT_REPRODUCED
    return Outcome(verdict, evidence, {"peak_rss_mib": round(result.maxrss_kb / 1024)})


# ---------------------------------------------------------------- 5 EMPTY_CSAF_WIPES_CACHE


def check_empty_csaf_wipes_cache(ctx: Context) -> Outcome:
    seed = seed_state({NEWEST: (["CVE-2026-1001", "CVE-2026-1002"], {"111": ["CVE-2026-1001"], "112": ["CVE-2026-1002"]})})
    evidence: list[str] = []
    wiped_any = False
    for label, body in (("empty-list", '{"vulnerabilities": []}'), ("null-entry", '{"vulnerabilities": [null]}')):

        def scenario(mock: MockOracle, body: str = body) -> dict[str, Any]:
            scen = base_scenario(mock)
            scen["slugs"] = [NEWEST]
            scen["csaf"][NEWEST] = {"body": body}
            return scen

        result = run_poll(ctx.pr_dir, ctx.out_dir / label, scenario, seed_state=seed)
        evidence.extend(assert_mock_hit(result))
        cached = bug_cves_of(result, NEWEST)
        degraded = result.report.get("degraded")
        wiped = cached == {} and degraded is False
        wiped_any = wiped_any or wiped
        evidence.append(
            f"{label}: seeded bug_cves={{111,112}} -> after poll bug_cves={cached} degraded={degraded} warnings={len(result.warning_notes())} wiped={wiped}"
        )
    return Outcome(REPRODUCED if wiped_any else NOT_REPRODUCED, evidence)


# ---------------------------------------------------------------- 6 MODHIST_DRIFT


def check_modhist_drift(ctx: Context) -> Outcome:
    seed = seed_state({NEWEST: (["CVE-2026-1001"], {"111": ["CVE-2026-1001"]})})

    def scenario(mock: MockOracle) -> dict[str, Any]:
        scen = base_scenario(mock)
        scen["slugs"] = [NEWEST]
        scen["pages"][NEWEST] = {
            "sections": [(MYSQL, ["CVE-2026-1001"])],
            "history": {"heading_html": "<h3><strong>Modification History</strong></h3>", "cves": ["CVE-2020-9999"]},
        }
        scen["csaf"][NEWEST] = {"vulns": [{"cve": "CVE-2026-1001", "bug": "111"}]}
        return scen

    result = run_poll(ctx.pr_dir, ctx.out_dir / "run", scenario, seed_state=seed)
    evidence = assert_mock_hit(result)
    cves = tracked(result, NEWEST)
    texts = manifest_texts(result)
    added_in_slack = any("+ CVE-2020-9999" in text for text in texts)
    evidence.append(
        f"history-only CVE-2020-9999 tracked={'CVE-2020-9999' in cves} added_in_slack_text={added_in_slack} cve_added={result.report.get('cve_added')} tracked={cves}"
    )
    evidence.append(summary(result))
    verdict = REPRODUCED if ("CVE-2020-9999" in cves or added_in_slack) else NOT_REPRODUCED
    return Outcome(verdict, evidence)


# ---------------------------------------------------------------- 7 SILENT_RESEED


def check_silent_reseed(ctx: Context) -> Outcome:
    result = run_poll(ctx.pr_dir, ctx.out_dir / "run", base_scenario)
    evidence = assert_mock_hit(result)
    warnings = result.warning_notes()
    degraded = result.report.get("degraded")
    first_list = any(item.get("changed") is True for item in result.manifest_items)
    baseline = result.report.get("baseline_present")
    evidence.append(
        f"no cpu-state.json: baseline_present={baseline} first_list_posted={first_list} warning_notes={len(warnings)} degraded={degraded} notes={[n.get('message') for n in warnings][:2]}"
    )
    evidence.append(summary(result))
    verdict = REPRODUCED if (first_list and baseline is False and not warnings and degraded is False) else NOT_REPRODUCED
    return Outcome(verdict, evidence)


# ---------------------------------------------------------------- 8 ABORT_AFTER_ACK_DUPLICATE


def _stub_build(path: Path) -> dict[str, Any]:
    manifest = {}
    if (path / "cpu-notify.json").is_file():
        manifest = json.loads((path / "cpu-notify.json").read_text(encoding="utf-8"))
    items = [item for item in (manifest.get("items") or []) if isinstance(item, dict)]
    pending_ids = sorted({str(item.get("pending_id")) for item in items if item.get("changed") is True and item.get("pending_id")})
    status = (path / "cpu-status.txt").read_text(encoding="utf-8") if (path / "cpu-status.txt").is_file() else ""
    delivered_match = re.search(r"Slack notifications: (\d+) delivered, (\d+) pending", status)
    delivered = int(delivered_match.group(1)) if delivered_match else -1
    pending_left = int(delivered_match.group(2)) if delivered_match else -1
    state = {}
    if (path / "cpu-state.json").is_file():
        state = json.loads((path / "cpu-state.json").read_text(encoding="utf-8"))
    return {
        "pending_ids": pending_ids,
        "delivered": delivered,
        "pending_left": pending_left,
        "state_pending": [item.get("id") for item in (state.get("pending") or [])],
        "threads": sorted((state.get("threads") or {}).keys()),
        "files": sorted(p.name for p in path.iterdir()) if path.is_dir() else [],
    }


def check_abort_after_ack_duplicate(ctx: Context) -> Outcome:
    extra = ctx.extra
    for key in ("stub_a", "stub_b", "result_a", "result_b"):
        if not extra.get(key):
            raise HarnessError(f"missing --{key.replace('_', '-')}; this check needs two stub-job builds driven by the Jenkinsfile")
    build_a = _stub_build(Path(extra["stub_a"]))
    build_b = _stub_build(Path(extra["stub_b"]))
    job = extra.get("stub_job", "?")
    evidence = [
        f"jenkins-level: {job} build {extra.get('number_a')} result={extra['result_a']} delivered={build_a['delivered']} pending_ids={build_a['pending_ids']} files={build_a['files']}",
        f"jenkins-level: {job} build {extra.get('number_b')} result={extra['result_b']} delivered={build_b['delivered']} pending_ids={build_b['pending_ids']} files={build_b['files']}",
    ]
    if extra["result_a"] != "ABORTED":
        raise HarnessError(f"build A finished {extra['result_a']}, the probe-only abort after Notify did not happen")
    if not build_a["pending_ids"] or build_a["delivered"] < 1:
        raise HarnessError("build A delivered no pending message (stub job not fresh, or the stub failed), precondition not met")
    duplicate = sorted(set(build_a["pending_ids"]) & set(build_b["pending_ids"]))
    evidence.append(
        f"same pending id delivered by both builds={duplicate} (build B copied nothing from the ABORTED build A, StatusBuildSelector skips ABORTED)"
    )
    evidence.append("control: by inspection, fixes/ABORT_AFTER_ACK_DUPLICATE.patch walks previous builds for the newest archived cpu-state.json regardless of result")
    verdict = REPRODUCED if (duplicate and build_b["delivered"] >= 1) else NOT_REPRODUCED
    return Outcome(verdict, evidence)


# ---------------------------------------------------------------- 9 NO_FAILURE_ALERT


def groovy_post_block(text: str) -> str:
    match = re.search(r"\n    post \{(.*)\n    \}\n\}\s*$", text, re.S)
    return match.group(1) if match else ""


def check_no_failure_alert(ctx: Context) -> Outcome:
    text = ctx.groovy.read_text(encoding="utf-8")
    post = groovy_post_block(text)
    conditions = sorted(set(re.findall(r"\n        (failure|unstable|unsuccessful|aborted|changed|fixed|regression)\s*\{", post)))
    notifies = bool(re.search(r"slackSend|mail\b|emailext|cpuSlackStub", post))
    evidence = [
        f"static: pipeline post {{}} conditions={conditions or ['always only']} notification step inside post={notifies}",
        "static: nobody is told when the cron job itself fails or goes UNSTABLE (only the CVE posts reach Slack)",
    ]
    verdict = NOT_REPRODUCED if (conditions and notifies) else REPRODUCED
    return Outcome(verdict, evidence)


CHECKS: dict[str, Callable[[Context], Outcome]] = {
    "SCOPE_ALL_PRODUCTS": check_scope_all_products,
    "NO_DEADLINE": check_no_deadline,
    "REDIRECT_ANY_HOST": check_redirect_any_host,
    "NO_SIZE_CAP": check_no_size_cap,
    "EMPTY_CSAF_WIPES_CACHE": check_empty_csaf_wipes_cache,
    "MODHIST_DRIFT": check_modhist_drift,
    "SILENT_RESEED": check_silent_reseed,
    "ABORT_AFTER_ACK_DUPLICATE": check_abort_after_ack_duplicate,
    "NO_FAILURE_ALERT": check_no_failure_alert,
}

# Controls that are not run: the detector cannot be re-driven on a patched copy.
INSPECTION_ONLY = {"ABORT_AFTER_ACK_DUPLICATE"}
STATIC_ONLY = {"NO_FAILURE_ALERT"}
