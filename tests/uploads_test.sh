#!/bin/bash
# uploads_test.sh
# End to end test of hook uploads: drra submit and send-uploads against
# hook.php on a local "php -S" report server, the built-in parsers, the
# spool and state files, and the server checks (unknown hook, bad
# signature, too soon). With DRSM_DIR set to a DRSM tree that has
# plugins/uploads/ it also runs the DRSM upload probe on the stored data.
#
# Usage: [KEEP=1] [DRSM_DIR=~/git/dr_system_monitor] tests/uploads_test.sh
#
# Needs the agent built (make), php and curl. No root, no network.

TOPdir=$(cd "$(dirname "$0")/.." && pwd)
T=$(mktemp -d)
PORT=$(( 18000 + RANDOM % 2000 ))
SERVER_PID=""
function cleanup() {
    if [ "${SERVER_PID}" != "" ]; then kill "${SERVER_PID}" 2> /dev/null; fi
    if [ "${KEEP}" == "" ]; then rm -rf "${T}"; else echo "Kept ${T}"; fi
}
trap cleanup EXIT
failures=0
function pass() { echo "PASS - $*"; }
function fail() { echo "FAIL - $*"; failures=$((failures + 1)); }
function expect() {
    # $1 == description, $2 == file, $3 == fixed string that must be in it
    if grep -qF -- "${3}" "${2}" 2> /dev/null; then pass "${1}"; else fail "${1}: '${3}' not in ${2}"; fi
}
function reject() {
    if grep -qF -- "${3}" "${2}" 2> /dev/null; then fail "${1}: '${3}' in ${2}"; else pass "${1}"; fi
}

DRRA="${TOPdir}/drra"
if [ ! -x "${DRRA}" ]; then echo "Build the agent first: make"; exit 1; fi
umask 022

# Report server: the pages, server.ini and the hook manifests
mkdir -p "${T}/web/upload" "${T}/data" "${T}/manifests"
cp "${TOPdir}"/php/*.php "${T}/web/upload/"
cat > "${T}/data/server.ini" <<EOF
[paths]
reports_dir = ${T}/data/reports
data_dir = ${T}/data
[registration]
enrollment_token = test-token
auto_approve_with_token = 1
[hooks]
manifest_dir = ${T}/manifests
EOF
function manifest() {
    # $1 == hook ID, $2 == FORMAT, $3 == MIN_INTERVAL_SECONDS
    mkdir -p "${T}/manifests/${1}"
    printf 'NAME=%s\nCATEGORY=hooks\nMODE=probe\nFORMAT=%s\nMAX_BYTES=100000\nKEEP_HISTORY=2\nMIN_INTERVAL_SECONDS=%s\n' "${1}" "${2}" "${3}" > "${T}/manifests/${1}/plugin.conf"
}
manifest openscap_manual xccdf-results 0
manifest app_health json 0
manifest inventory csv 0
manifest backup_job drsm-lines 60
manifest agent_like kv-sections 0
(cd "${T}/web" && LRA_SERVER_INI="${T}/data/server.ini" exec php -S "127.0.0.1:${PORT}" > "${T}/server.log" 2>&1) &
SERVER_PID=$!

# Agent: its INI, upload hook files and spool in the temp tree
mkdir -p "${T}/agent/uploads.d"
cat > "${T}/agent/drra.ini" <<EOF
[delivery]
methods=https
[https]
host=127.0.0.1
port=${PORT}
use_https=0
upload_path=/upload/upload.php
register_path=/upload/register.php
enrollment_token=test-token
[agent]
report_dir=${T}/agent/var
data_dir=${T}/agent/var
log_file=${T}/agent/drra.log
[uploads]
dir=${T}/agent/uploads.d
spool_dir=${T}/agent/spool
EOF
function hook() {
    # $1 == hook ID, $2 == format
    printf '[upload]\nid=%s\ntitle=Test %s\nformat=%s\nkeep_sent=2\n' "${1}" "${1}" "${2}" > "${T}/agent/uploads.d/${1}.ini"
    chmod 600 "${T}/agent/uploads.d/${1}.ini"
}
for h in openscap_manual:xccdf-results app_health:json inventory:csv backup_job:drsm-lines agent_like:kv-sections no_manifest:text; do
    hook "${h%%:*}" "${h#*:}"
done
printf '[upload]\nid=loose\n' > "${T}/agent/uploads.d/loose.ini"
chmod 666 "${T}/agent/uploads.d/loose.ini"
A=("${DRRA}" -c "${T}/agent/drra.ini")
HOSTNAME_A=$("${A[@]}" fingerprint 2> /dev/null | sed -n 's/^Host: //p')
for i in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:${PORT}/upload/hook.php" && break; sleep 0.1; done

"${A[@]}" uploads > "${T}/hooks.out" 2> "${T}/hooks.err"
expect "lists the upload hooks" "${T}/hooks.out" "openscap_manual_status=none"
expect "hook page next to the upload page" "${T}/hooks.out" "Hook page: /upload/hook.php"
expect "group writable hook file is skipped" "${T}/hooks.err" "loose.ini is writable by group or others, skipped"

# Payloads
cat > "${T}/health.json" <<'EOF'
{"status": "ok", "queue": {"depth": 7, "oldest_seconds": 12}, "workers": [{"name": "w1", "up": true}]}
EOF
printf 'Name,Version,Vendor\napp-a,1.2,"Acme, Inc."\napp-b,3.0,Other|Co\n' > "${T}/inventory.csv"
printf 'INFO - nightly backup finished\nDETAIL status=ok\nDETAIL size_gb=118.5\n=== core/cpu [OK] 0s ===\nMETRIC duration_minutes=42\n@@DRSM_END x 0 0\n' > "${T}/backup.txt"
printf 'header line\nAPP:\nversion=2.1\nmessage="all good"\nEND APP\n' > "${T}/agent_like.txt"

"${A[@]}" submit --hook openscap_manual "${TOPdir}/tests/fixtures/xccdf_results.xml" > "${T}/submit.out" 2>&1
expect "submit queues the file" "${T}/submit.out" "Queued ${TOPdir}/tests/fixtures/xccdf_results.xml for hook openscap_manual"
"${A[@]}" submit --hook app_health --now "${T}/health.json" > "${T}/submit2.out" 2>&1
expect "submit --now asks the service" "${T}/submit2.out" "The agent sends it within a few seconds"
expect "send now flag" <(ls -a "${T}/agent/spool") ".send_now"
"${A[@]}" submit --hook inventory "${T}/inventory.csv" > /dev/null 2>&1
"${A[@]}" submit --hook backup_job "${T}/backup.txt" > /dev/null 2>&1
"${A[@]}" submit --hook agent_like "${T}/agent_like.txt" > /dev/null 2>&1
"${A[@]}" submit --hook no_manifest "${T}/backup.txt" > /dev/null 2>&1
"${A[@]}" submit --hook nosuch "${T}/backup.txt" > "${T}/submit3.out" 2>&1
expect "unknown hook is refused" "${T}/submit3.out" "No upload hook nosuch in"
# Files are taken two seconds after they were last changed
sleep 3

"${A[@]}" send-uploads > "${T}/send.out" 2>&1
expect "agent registered" "${T}/send.out" "Registration status from server: approved"
expect "xccdf sent" "${T}/send.out" "Upload openscap_manual sent: STATUS: ok"
expect "xccdf parsed" "${T}/send.out" "format xccdf-results"
expect "no manifest stays spooled" "${T}/send.out" "The server has no manifest for upload hook no_manifest, it stays spooled"
H="${T}/data/hooks/${HOSTNAME_A}"
expect "xccdf counts" "${H}/openscap_manual/latest.lines" "UPLOAD value|fail|2"
expect "xccdf high failure" "${H}/openscap_manual/latest.lines" "UPLOAD value|fail_high|1"
expect "xccdf score" "${H}/openscap_manual/latest.lines" "UPLOAD value|score|62.5"
expect "xccdf rule row with title" "${H}/openscap_manual/latest.lines" "UPLOAD row|high|sshd_disable_root_login|Disable SSH Root Login"
expect "meta names the sender" "${H}/openscap_manual/latest.meta" "SENDER: ${HOSTNAME_A}"
expect "meta has the original file name" "${H}/openscap_manual/latest.meta" "FILE_NAME: xccdf_results.xml"
expect "meta source" "${H}/openscap_manual/latest.meta" "SOURCE: submit"
expect "json flattened" "${H}/app_health/latest.lines" "UPLOAD value|queue.depth|7"
expect "json array" "${H}/app_health/latest.lines" "UPLOAD value|workers.0.up|true"
expect "csv columns" "${H}/inventory/latest.lines" "UPLOAD columns|Name|Version|Vendor"
expect "csv quoted cell" "${H}/inventory/latest.lines" "UPLOAD row|app-a|1.2|Acme, Inc."
expect "csv pipe made safe" "${H}/inventory/latest.lines" "UPLOAD row|app-b|3.0|Other/Co"
expect "csv row count" "${H}/inventory/latest.lines" "UPLOAD value|rows|2"
expect "drsm lines kept" "${H}/backup_job/latest.lines" "INFO - nightly backup finished"
expect "DETAIL becomes a value" "${H}/backup_job/latest.lines" "UPLOAD value|status|ok"
expect "metric kept" "${H}/backup_job/latest.lines" "METRIC duration_minutes=42"
reject "no report section lines" "${H}/backup_job/latest.lines" "=== core/cpu"
reject "no job frame lines" "${H}/backup_job/latest.lines" "@@DRSM_END"
expect "kv sections" "${H}/agent_like/latest.lines" "UPLOAD value|app.message|all good"
expect "payload kept as sent" "${H}/inventory/latest.data" "Acme, Inc."
expect "sent file moved to sent/" <(ls "${T}/agent/spool/inventory/sent") "_inventory.csv"
expect "no manifest still waiting" <(ls "${T}/agent/spool/no_manifest") "_backup.txt"
expect "state ok" "${T}/agent/var/uploads/inventory.state" "status=ok"
expect "state waiting" "${T}/agent/var/uploads/no_manifest.state" "status=waiting"

# The next backup comes too soon for MIN_INTERVAL_SECONDS=60: it waits
"${A[@]}" submit --hook backup_job "${T}/backup.txt" > /dev/null 2>&1
sleep 3
"${A[@]}" send-uploads > "${T}/send2.out" 2>&1
expect "too soon waits" "${T}/send2.out" "the next one goes out next cycle"
"${A[@]}" uploads > "${T}/hooks2.out" 2> /dev/null
expect "report section pending count" "${T}/hooks2.out" "backup_job_pending=1"
expect "report section waiting" "${T}/hooks2.out" "no_manifest_status=waiting"

# A second xccdf upload keeps the first in history/
"${A[@]}" submit --hook openscap_manual "${TOPdir}/tests/fixtures/xccdf_results.xml" > /dev/null 2>&1
sleep 3
"${A[@]}" send-uploads > /dev/null 2>&1
expect "history kept" <(ls "${H}/openscap_manual/history") ".meta"

# Server checks without the agent
curl -s -F hostname="${HOSTNAME_A}" -F timestamp="$(date +%s)" -F nonce=0123456789abcdef0123456789abcdef -F hookId=inventory \
    -F subject="${HOSTNAME_A}" -F signature=AAAA -F envelope=@"${T}/backup.txt" -F payload=@"${T}/backup.txt" \
    "http://127.0.0.1:${PORT}/upload/hook.php" > "${T}/curl1.out"
expect "bad signature refused" "${T}/curl1.out" "STATUS: bad_signature"
curl -s -F hostname="${HOSTNAME_A}" -F timestamp="$(date +%s)" -F nonce=0123456789abcdef0123456789abcdef -F hookId=../x \
    -F subject="${HOSTNAME_A}" -F signature=AAAA "http://127.0.0.1:${PORT}/upload/hook.php" > "${T}/curl2.out"
expect "bad hook ID refused" "${T}/curl2.out" "Invalid hook ID"
curl -s -F hostname=notregistered -F timestamp="$(date +%s)" -F nonce=0123456789abcdef0123456789abcdef -F hookId=inventory \
    -F subject=notregistered -F signature=AAAA "http://127.0.0.1:${PORT}/upload/hook.php" > "${T}/curl3.out"
expect "unregistered host refused" "${T}/curl3.out" "STATUS: not_registered"
reject "no PHP warnings" "${T}/server.log" "PHP Warning"
reject "no PHP notices" "${T}/server.log" "PHP Notice"

# DRSM upload probe on the stored data
if [ "${DRSM_DIR}" != "" ] && [ -f "${DRSM_DIR}/plugins/uploads/upload_probe.sh" ]; then
    (cd "${DRSM_DIR}/plugins/uploads/openscap_manual" && env DRSM_LIB="${DRSM_DIR}/lib" DRSM_TARGET="${HOSTNAME_A}" \
	DRSM_UPLOADS_DIR="${T}/data/hooks" DRSM_UPLOAD_NAME="${HOSTNAME_A}" DRSM_UPLOAD_ID=openscap_manual \
	DRSM_TITLE="Manual OpenSCAP scan" DRSM_DISPLAY=table DRSM_WARN_IF="fail_high > 0" DRSM_CRIT_IF="fail_critical > 0" \
	DRSM_METRICS="score" DRSM_MAX_AGE_HOURS=720 bash ./probe.sh) > "${T}/probe.out" 2>&1
    expect "DRSM probe warns" "${T}/probe.out" "WARNING - ${HOSTNAME_A} Manual OpenSCAP scan: fail_high > 0 (fail_high is 1)"
    expect "DRSM probe metric" "${T}/probe.out" "METRIC openscap_manual_score=62.5"
    expect "DRSM probe rows" "${T}/probe.out" "UPLOAD row|medium|accounts_tmout|Set Interactive Session Timeout"
else
    echo "SKIP - DRSM probe: set DRSM_DIR to a DRSM tree with plugins/uploads"
fi

if [ ${failures} -eq 0 ]; then echo "All tests passed"; else echo "${failures} tests failed"; fi
exit $((failures > 0))
