# probe-pr4532-oracle-cpu

Throwaway workflow probe for [Percona-Lab/jenkins-pipelines PR 4532](https://github.com/Percona-Lab/jenkins-pipelines/pull/4532) (PS-11606, `check-oracle-cpu`).

`ps/jenkins/` is the PR head `14df4a3da7` tree, byte-identical except for `check_oracle_cpu.groovy`:

- Every `slackSend(...)` call is replaced by `cpuSlackStub(...)`, a local function that never contacts Slack.
- A new string parameter `SLACK_STUB` drives the stub: `ok` returns a fake `[channelId, ts, threadId]` map, `null` returns null, `throw` throws.

See `STUB.diff` for the exact change. Used by a temporary pipeline job on one Jenkins master to drive builds B1..B5 (first run, unchanged run, IGNORE_STATE, failed Slack, pending flush). No real Slack post is possible from this tree.
