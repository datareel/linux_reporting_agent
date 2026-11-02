#!/bin/bash
# auth_watch_test.sh
# Tests auth_watch on the fixture logs: scopes and events, the saved
# position in a secure log (also across a rotation), the CSV and lines
# output, and --submit through a built agent (drra -c) to hook.php on a
# local "php -S" report server. With DRSM_DIR set to a DRSM tree it also
# runs the DRSM upload probe on the stored data with this util's
# manifest.
#
# Usage: [KEEP=1] [DRSM_DIR=~/git/dr_system_monitor] utils/auth_watch/tests/auth_watch_test.sh
#
# No root, no network. The agent part needs the agent built (make), php
# and curl, and is skipped without them.

HERE=$(cd "$(dirname "$0")/.." && pwd)
[ "${DRSM_DIR}" != "" ] && DRSM_DIR=$(cd "${DRSM_DIR}" && pwd)
TOPdir=$(cd "${HERE}/../.." && pwd)
AW="${HERE}/auth_watch"
FIX="${HERE}/tests/fixtures"
T=$(mktemp -d)
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

# Scopes and events, RHEL 8 sshd in a secure log
"${AW}" --input "${FIX}/secure_rhel8.log" --trusted "10.0.0.0/8" > "${T}/r8.csv"
expect "csv header" "${T}/r8.csv" "scope,service,event,method,user,source,count,first,last"
expect "remote password failures counted" "${T}/r8.csv" "remote,sshd,failed,password,root,203.0.113.7,2,"
expect "invalid user" "${T}/r8.csv" "remote,sshd,invalid_user,,admin,203.0.113.7,1,"
expect "too many attempts once, not twice" "${T}/r8.csv" "remote,sshd,too_many,,root,203.0.113.7,1,"
expect "closed before auth" "${T}/r8.csv" "remote,sshd,preauth_closed,,root,198.51.100.20,1,"
expect "remote accepted" "${T}/r8.csv" "remote,sshd,accepted,publickey,deploy,198.51.100.44,1,"
expect "cockpit with rhost is remote" "${T}/r8.csv" "remote,cockpit,failed,password,admin,192.0.2.99,1,"
expect "trusted CIDR" "${T}/r8.csv" "trusted,sshd,failed,password,owner,10.1.2.3,1,"
expect "::1 is localhost" "${T}/r8.csv" "localhost,sshd,failed,password,owner,::1,1,"
expect "::ffff:127.0.0.1 is localhost" "${T}/r8.csv" "localhost,sshd,accepted,publickey,owner,::ffff:127.0.0.1,1,"
expect "sudo is local, pam_unix + pam_sss once" "${T}/r8.csv" "local,sudo,failed,password,owner,,1,"
expect "su is local" "${T}/r8.csv" "local,su,failed,password,root,,1,"
expect "polkit is local" "${T}/r8.csv" "local,polkit-1,failed,password,owner,,1,"
expect "console login" "${T}/r8.csv" "local,login,accepted,password,owner,,1,"
reject "sshd pam line not counted twice" "${T}/r8.csv" "remote,sshd,failed,password,,203.0.113.7"
if [ "$(sed -n 2p "${T}/r8.csv" | cut -d, -f1)" == "remote" ] && [ "$(tail -1 "${T}/r8.csv" | cut -d, -f1)" == "local" ]; then
    pass "remote rows first, local last"
else
    fail "row order"
fi

# RHEL 10 sshd-session and sshd-auth in journalctl -o short-iso output
"${AW}" --input "${FIX}/journal_rhel10.log" --format lines > "${T}/r10.lines"
expect "sshd-session invalid user" "${T}/r10.lines" "UPLOAD row|remote|sshd|invalid_user||oracle|2001:db8::5|1|"
expect "keyboard-interactive failure" "${T}/r10.lines" "UPLOAD row|remote|sshd|failed|keyboard-interactive/pam|root|203.0.113.8|1|"
expect "sshd-auth reset before auth" "${T}/r10.lines" "UPLOAD row|remote|sshd|preauth_closed||root|203.0.113.8|1|"
expect "gdm typo is local" "${T}/r10.lines" "UPLOAD row|local|gdm-password|failed|password|owner||1|"
expect "remote_failed value" "${T}/r10.lines" "DETAIL remote_failed=2"
expect "remote_sources value" "${T}/r10.lines" "DETAIL remote_sources=2"
expect "local failures apart" "${T}/r10.lines" "DETAIL local_failed=1"
expect "localhost accepted apart" "${T}/r10.lines" "DETAIL localhost_accepted=1"
expect "table columns" "${T}/r10.lines" "UPLOAD columns|Scope|Service|Event|Method|User|Source|Count|First|Last"
reject "no warnings in the payload, the manifest decides" "${T}/r10.lines" "WARNING - "

# Saved position in a secure log, and a rotation in between
LOG="${T}/secure"
head -5 "${FIX}/secure_rhel8.log" > "${LOG}"
"${AW}" --log "${LOG}" --state "${T}/s.state" > "${T}/p1.csv"
expect "first run reads the file" "${T}/p1.csv" "remote,sshd,failed,password,root,203.0.113.7,1,"
"${AW}" --log "${LOG}" --state "${T}/s.state" > "${T}/p2.csv"
if [ "$(wc -l < "${T}/p2.csv")" == "1" ]; then pass "second run, nothing new"; else fail "second run read old lines"; fi
sed -n 6,8p "${FIX}/secure_rhel8.log" >> "${LOG}"
mv "${LOG}" "${LOG}-20261101"
sed -n 9,10p "${FIX}/secure_rhel8.log" > "${LOG}"
"${AW}" --log "${LOG}" --state "${T}/s.state" > "${T}/p3.csv"
expect "rest of the rotated file" "${T}/p3.csv" "remote,sshd,too_many,,root,203.0.113.7,1,"
expect "new file after the rotation" "${T}/p3.csv" "remote,sshd,accepted,publickey,deploy,198.51.100.44,1,"
reject "rotated file not read twice" "${T}/p3.csv" "invalid_user"
"${AW}" --log "${LOG}" --state "${T}/s.state" --no-save > /dev/null
"${AW}" --log "${LOG}" --state "${T}/s.state" --out "${T}/p4.csv"
if [ "$(wc -l < "${T}/p4.csv")" == "1" ]; then pass "--out, nothing new"; else fail "--out run read old lines"; fi

# --submit through the agent to hook.php, then the DRSM probe
DRRA="${TOPdir}/drra"
if [ ! -x "${DRRA}" ] || ! command -v php > /dev/null || ! command -v curl > /dev/null; then
    echo "SKIP - agent tests: build the agent (make) and install php and curl"
else
    PORT=$(( 20000 + RANDOM % 2000 ))
    mkdir -p "${T}/web/upload" "${T}/data" "${T}/manifests" "${T}/agent/uploads.d"
    cp "${TOPdir}"/php/*.php "${T}/web/upload/"
    cp -r "${HERE}/drsm/uploads/auth_watch" "${T}/manifests/"
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
    (cd "${T}/web" && LRA_SERVER_INI="${T}/data/server.ini" exec php -S "127.0.0.1:${PORT}" > "${T}/server.log" 2>&1) &
    SERVER_PID=$!
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
    cp "${HERE}/auth_watch.ini" "${T}/agent/uploads.d/"
    chmod 600 "${T}/agent/uploads.d/auth_watch.ini"
    for i in $(seq 1 50); do curl -s -o /dev/null "http://127.0.0.1:${PORT}/upload/hook.php" && break; sleep 0.1; done
    HOSTNAME_A=$("${DRRA}" -c "${T}/agent/drra.ini" fingerprint 2> /dev/null | sed -n 's/^Host: //p')

    "${AW}" --input "${FIX}/secure_rhel8.log" --submit --now --drra "${DRRA}" --drra-config "${T}/agent/drra.ini" > "${T}/submit.out" 2>&1
    expect "submit queues the file" "${T}/submit.out" "for hook auth_watch"
    expect "submit --now" "${T}/submit.out" "within a few seconds"
    # The agent takes files two seconds after they were last changed
    sleep 3
    "${DRRA}" -c "${T}/agent/drra.ini" send-uploads > "${T}/send.out" 2>&1
    expect "sent to hook.php" "${T}/send.out" "Upload auth_watch sent: STATUS: ok"
    H="${T}/data/hooks/${HOSTNAME_A}/auth_watch"
    # No --trusted here, so 10.1.2.3 counts as remote too: 5 failures
    expect "server parsed the values" "${H}/latest.lines" "UPLOAD value|remote_failed|5"
    expect "server kept the table" "${H}/latest.lines" "UPLOAD row|remote|sshd|failed|password|root|203.0.113.7|2|"
    expect "meta format" "${H}/latest.meta" "FORMAT: drsm-lines"

    "${AW}" --input "${FIX}/secure_rhel8.log" --submit --hook nosuch --drra "${DRRA}" --drra-config "${T}/agent/drra.ini" > "${T}/submit2.out" 2>&1
    expect "unknown hook fails" "${T}/submit2.out" "drra submit failed"

    if [ "${DRSM_DIR}" != "" ] && [ -f "${DRSM_DIR}/plugins/uploads/upload_probe.sh" ]; then
	P="${T}/drsm_plugins/uploads/auth_watch"
	mkdir -p "${P}"
	cp "${HERE}"/drsm/uploads/auth_watch/* "${P}/"
	cp "${DRSM_DIR}/plugins/uploads/upload_probe.sh" "${T}/drsm_plugins/uploads/"
	# DRSM hands the manifest settings to the probe as DRSM_<NAME>
	(cd "${P}" && eval "$(sed -n 's/^\([A-Z_]*\)=/export DRSM_\1=/p' plugin.conf)" \
	    && DRSM_LIB="${DRSM_DIR}/lib" DRSM_UPLOADS_DIR="${T}/data/hooks" DRSM_UPLOAD_NAME="${HOSTNAME_A}" \
	    DRSM_UPLOAD_ID=auth_watch bash ./probe.sh) > "${T}/probe.out" 2>&1
	expect "probe warns on remote failures" "${T}/probe.out" "remote_failed > 0 (remote_failed is 5)"
	expect "probe metric" "${T}/probe.out" "METRIC auth_watch_remote_failed=5"
	expect "probe table" "${T}/probe.out" "UPLOAD row|remote|sshd|failed|password|root|203.0.113.7|2|"
	reject "local typos do not alert" "${T}/probe.out" "local_failed >"
    else
	echo "SKIP - DRSM probe: set DRSM_DIR to a DRSM tree"
    fi
fi

echo
if [ "${failures}" == "0" ]; then echo "All tests passed"; else echo "${failures} test(s) failed"; fi
[ "${failures}" == "0" ]
