# PR 4532 reproducers

Bug-reproduction pipeline for [Percona-Lab/jenkins-pipelines PR 4532](https://github.com/Percona-Lab/jenkins-pipelines/pull/4532)
(`check-oracle-cpu`, PS-11606). It clones the PR tree read-only into `pr/`, points the PR's own
`cpu_cves.py` at a mock Oracle on loopback, and judges nine findings. Nothing here edits the PR
files, posts to Slack, or needs a script approval.

## Layout

| Path | Purpose |
|---|---|
| `Jenkinsfile` | Thin Declarative pipeline, one stage per check, each with its own `timeout()`. Label `docker`. |
| `harness/mockoracle.py` | Fake `www.oracle.com`: index, advisory pages with per-product risk matrices, CSAF with `product_tree`, drip, 150 MiB bodies, redirects, an evil host. Logs every request. |
| `harness/rewrite_runner.py` | Runs the PR's `cpu_cves.py` unchanged. Monkeypatches `urllib.request.OpenerDirector.open` to log every original URL (scheme, host) and map `https://www.oracle.com/...` to the mock. |
| `harness/pollrun.py` | One poll in a subprocess with a deadline, plus `assert_mock_hit`, the fail-closed proof that the stub ran. |
| `harness/checks.py` | The nine detectors. Each prints `REPRODUCED`, `NOT_REPRODUCED` or `HARNESS_ERROR` with evidence. |
| `harness/run_check.py` | CLI. With `--control` it copies `ps/jenkins`, applies `fixes/<id>.patch` with `git apply`, and re-runs the detector. |
| `harness/report.py` | Builds `repro-report.json`, the kubectl-style table, and the build description. |
| `fixes/<id>.patch` | One minimal proposed fix per finding. Suggested fixes for the author, applied only to copies. |

## Checks

| Id | What reproduces it | Control |
|---|---|---|
| `SCOPE_ALL_PRODUCTS` | A page with a MySQL and a Java SE risk matrix: the Java CVE lands in the tracked set and its bug id in the map. `LIVE=true` adds the real newest advisory count. | patch narrows `parse_cves` to the MySQL matrix and the CSAF bug ids to MySQL products (one PR unit test then needs updating) |
| `NO_DEADLINE` | Index dripped 1 byte / 5 s: the poll is still running at 90 s. Static: no `timeout()` in options. | 20 s body deadline with `read1`, `timeout(30 min)` in options |
| `REDIRECT_ANY_HOST` | CSAF href on `http://127.0.0.2`, page 301 to `http://127.0.0.3`: both fetched, evil bug id lands in `cpu-bug-cve.json`. | `_follow` rejects anything but https on oracle.com |
| `NO_SIZE_CAP` | 150 MiB CSAF read whole, poll SUCCESS, peak RSS recorded. | 32 MiB body cap |
| `EMPTY_CSAF_WIPES_CACHE` | Seeded bug map, CSAF `{"vulnerabilities": []}` and `[null]`: cache becomes `{}` with `degraded=false`. | empty map is a warning, previous map kept |
| `MODHIST_DRIFT` | `<h3><strong>Modification History</strong></h3>`: the history-only CVE is posted as added. | heading regex tolerates inline tags |
| `SILENT_RESEED` | Missing baseline: first list posted with no warning and `degraded=false`. | warning note on reseed |
| `ABORT_AFTER_ACK_DUPLICATE` | Jenkins-level. Two builds of a fresh stub job: build A acks Slack then aborts, build B copies nothing and delivers the same pending id again. | by inspection: patch walks previous builds for the newest archived `cpu-state.json` regardless of result |
| `NO_FAILURE_ALERT` | Static. `post {}` has only `always`, nobody is told when the watcher fails. | `unsuccessful { slackSend(...) }` |

Build result: `UNSTABLE` when any finding reproduces, `FAILURE` on any `HARNESS_ERROR` or a control
that did not flip, `SUCCESS` only when nothing reproduces.

## Recreate on a Jenkins master

Two throwaway jobs, both pipeline-from-SCM on this repository, no triggers. The stub job must be
fresh (no builds) before `ABORT_AFTER_ACK_DUPLICATE` runs.

```bash
jenkins -i ps80 job create probe-pr4532-oracle-cpu-stub -c stub-job.xml   # ps/jenkins/check_oracle_cpu.groovy, params IGNORE_STATE NOTIFY SLACK_STUB PROBE_ABORT_AFTER_NOTIFY, copyArtifactPermission *
jenkins -i ps80 job create probe-pr4532-repro -c repro-job.xml            # repro/Jenkinsfile, params PR_REPO PR_REF BUGS CONTROL LIVE STUB_JOB
jenkins -i ps80 build probe-pr4532-repro -p PR_REPO=https://github.com/marcinbabij/jenkins-pipelines.git -p PR_REF=<sha> -p BUGS=all -p CONTROL=true -p LIVE=true -p STUB_JOB=probe-pr4532-oracle-cpu-stub
jenkins -i ps80 artifacts probe-pr4532-repro -m 'repro/out/repro-report.json' -D ./out
echo y | jenkins -i ps80 job delete probe-pr4532-repro
echo y | jenkins -i ps80 job delete probe-pr4532-oracle-cpu-stub
```

Locally, without Jenkins (everything except `ABORT_AFTER_ACK_DUPLICATE`):

```bash
git clone --depth 1 https://github.com/marcinbabij/jenkins-pipelines.git pr && git -C pr fetch --depth 1 origin <sha> && git -C pr checkout FETCH_HEAD
for id in SCOPE_ALL_PRODUCTS NO_DEADLINE REDIRECT_ANY_HOST NO_SIZE_CAP EMPTY_CSAF_WIPES_CACHE MODHIST_DRIFT SILENT_RESEED NO_FAILURE_ALERT; do
  python3 -B repro/harness/run_check.py "$id" --pr pr/ps/jenkins --out repro/out --control
done
python3 -B repro/harness/report.py repro/out
```

Python 3.9 or newer, stdlib only, `git` for the patches.
