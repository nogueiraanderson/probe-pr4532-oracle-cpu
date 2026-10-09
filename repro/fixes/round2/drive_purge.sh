#!/usr/bin/env bash
# Drive stub builds 2..12 on ps80 to show artifactNumToKeep=10 purging the
# ABORTED build 1 checkpoint, then build 12 re-posting the acked message.
set -euo pipefail

readonly instance=ps80
readonly job="${STUB_JOB:-probe-pr4532-oracle-cpu-stub-r2}"
readonly out_dir="${OUT_DIR:-/tmp/pr4532-repro/jenkins}"
readonly config=/home/percona/.config/jenkins-cli/config.json
readonly last_quiet_build=11
readonly final_build=12

base_url="$(jq -r --arg i "${instance}" '.[$i].url' "${config}")"
auth="$(jq -r --arg i "${instance}" '.[$i] | "\(.username):\(.token)"' "${config}")"
readonly base_url auth

build_json() {
  local number="$1"
  curl -fsSg -u "${auth}" "${base_url}/job/${job}/${number}/api/json?tree=number,building,result,artifacts[fileName]"
}

wait_for_build() {
  local number="$1"
  local deadline=$((SECONDS + 900))
  local json=""
  while (( SECONDS < deadline )); do
    if json="$(build_json "${number}" 2>/dev/null)"; then
      if [[ "$(jq -r '.building' <<<"${json}")" == "false" ]]; then
        jq -r '.result' <<<"${json}"
        return 0
      fi
    fi
    sleep 20
  done
  echo "TIMEOUT"
  return 1
}

artifact_names() {
  local number="$1"
  build_json "${number}" | jq -r '[.artifacts[].fileName] | join(",")'
}

echo "build 1 artifacts before the run: $(artifact_names 1)"

for number in $(seq 2 "${final_build}"); do
  jenkins -i "${instance}" build "${job}" -p IGNORE_STATE=false -p NOTIFY=none -p SLACK_STUB=ok -p PROBE_ABORT_AFTER_NOTIFY=false >/dev/null
  result="$(wait_for_build "${number}")"
  echo "build ${number} result=${result} artifacts=$(artifact_names "${number}") build1_artifacts=$(artifact_names 1)"
  if (( number <= last_quiet_build )) && [[ "${result}" != "NOT_BUILT" ]]; then
    echo "STOP: build ${number} ended ${result}, expected NOT_BUILT (a real Oracle change or a failure changes the scenario)"
    exit 2
  fi
done

mkdir -p "${out_dir}/build-${final_build}"
jenkins -i "${instance}" artifacts "${job}" -b "${final_build}" --download-all --force -D "${out_dir}/build-${final_build}" >/dev/null
echo "build ${final_build} downloaded: $(find "${out_dir}/build-${final_build}" -type f -printf '%f ')"
echo "DRIVER-DONE"
