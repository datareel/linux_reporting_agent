#!/bin/bash
# rpm_install_test.sh
# Install tests of the two RHEL 8 packages in UBI 8 containers (podman, no
# root), with FIPS mode off and on (a fips_enabled file mounted over
# /proc/sys/crypto/fips_enabled):
#   - a fresh install of each package, its selftest, rpm -V and removal
#   - linux_reporting_agent-openssl35 refused by its %pre in FIPS mode
#   - an upgrade from an older RPM (OLD) to each package
#   - a switch between the two with dnf install --allowerasing
#   - an upgrade from the 1.1.3 test build with both programs behind an
#     alternatives link (SINGLE): its alternatives entry is removed
# Needs network for dnf.
#
# Usage: tests/rpm_install_test.sh <el8 rpm> <el8 openssl35 rpm> [old el8 rpm] [single-package test build]

BASE="${1:?usage: tests/rpm_install_test.sh <el8 rpm> <el8 openssl35 rpm> [old el8 rpm] [single build]}"
O35="${2:?usage: tests/rpm_install_test.sh <el8 rpm> <el8 openssl35 rpm> [old el8 rpm] [single build]}"
OLD="${3}"
SINGLE="${4}"
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
cp "${BASE}" "${T}/base.rpm"
cp "${O35}" "${T}/o35.rpm"
[ -n "${OLD}" ] && cp "${OLD}" "${T}/old.rpm"
[ -n "${SINGLE}" ] && cp "${SINGLE}" "${T}/single.rpm"
echo 0 > "${T}/fips0"
echo 1 > "${T}/fips1"
cat > "${T}/run.sh" <<'EOF'
# In the container: $1 == fips_enabled, $2 == the test
set -e
# Rootless podman maps only one group: let the drra-upload group be gid 0
groupadd -o -g 0 drra-upload
fail() { echo "FAIL - $*"; exit 1; }
inst() { dnf -q -y --setopt=install_weak_deps=False install "$@" > /tmp/dnf.log 2>&1; }
build() { /usr/sbin/drra -c /dev/null selftest | sed -n 's/^Build: *//p'; }
check() {
    # $1 == the package that must be installed, $2 == the Build line
    rpm -q "$1" > /dev/null || fail "$1 is not installed"
    [ -f /usr/sbin/drra ] && [ ! -L /usr/sbin/drra ] || fail "/usr/sbin/drra is not a plain file"
    [ ! -e /var/lib/alternatives/drra ] || fail "an alternatives entry is left"
    b=$(build)
    case "${b}" in "$2"*) ;; *) fail "selftest Build: '${b}', want '$2'";; esac
    rpm -V "$1" || fail "rpm -V $1"
    echo "PASS - $1: ${b}"
}
remove_all() {
    dnf -q -y remove linux_reporting_agent linux_reporting_agent-openssl35 > /dev/null 2>&1 || :
    [ ! -e /usr/sbin/drra ] || fail "/usr/sbin/drra left after removal"
    echo "PASS - removed"
}
echo "== fips_enabled=$(cat /proc/sys/crypto/fips_enabled): $2"
case "$2" in
    fresh)
	inst /t/base.rpm || { tail /tmp/dnf.log; fail "install"; }
	check linux_reporting_agent "FIPS (system OpenSSL)"
	remove_all
	if [ "$1" = 1 ]; then
	    if inst /t/o35.rpm; then fail "openssl35 installed in FIPS mode"; fi
	    grep -q "FIPS mode is on" /tmp/dnf.log || { tail /tmp/dnf.log; fail "no FIPS message"; }
	    rpm -q linux_reporting_agent-openssl35 > /dev/null && fail "openssl35 left installed"
	    echo "PASS - openssl35 refused: $(grep -m1 'FIPS mode is on' /tmp/dnf.log | sed 's/^ *//')"
	else
	    inst /t/o35.rpm || { tail /tmp/dnf.log; fail "install"; }
	    check linux_reporting_agent-openssl35 "openssl35"
	    remove_all
	fi
	;;
    upgrade)
	inst /t/old.rpm || { tail /tmp/dnf.log; fail "old install"; }
	echo "old: $(/usr/sbin/drra version)"
	inst /t/base.rpm || { tail /tmp/dnf.log; fail "upgrade"; }
	check linux_reporting_agent "FIPS (system OpenSSL)"
	remove_all
	if [ "$1" = 0 ]; then
	    inst /t/old.rpm || fail "old install"
	    dnf -q -y --setopt=install_weak_deps=False install --allowerasing /t/o35.rpm > /tmp/dnf.log 2>&1 || { tail /tmp/dnf.log; fail "upgrade to openssl35"; }
	    rpm -q linux_reporting_agent > /dev/null && fail "the old package is left"
	    check linux_reporting_agent-openssl35 "openssl35"
	    remove_all
	fi
	;;
    switch)
	inst /t/base.rpm || fail "install"
	echo "custom=1" >> /etc/drra/drra.ini
	dnf -q -y install --allowerasing /t/o35.rpm > /tmp/dnf.log 2>&1 || { tail /tmp/dnf.log; fail "switch to openssl35"; }
	rpm -q linux_reporting_agent > /dev/null && fail "linux_reporting_agent left after the switch"
	check linux_reporting_agent-openssl35 "openssl35"
	grep -q "^custom=1" /etc/drra/drra.ini || fail "drra.ini not kept"
	dnf -q -y install --allowerasing /t/base.rpm > /tmp/dnf.log 2>&1 || { tail /tmp/dnf.log; fail "switch back"; }
	check linux_reporting_agent "FIPS (system OpenSSL)"
	grep -q "^custom=1" /etc/drra/drra.ini || fail "drra.ini not kept"
	echo "PASS - switched both ways, drra.ini kept"
	remove_all
	;;
    single)
	rpm -i --nodeps /t/single.rpm > /tmp/rpm.log 2>&1 || { cat /tmp/rpm.log; fail "single install"; }
	[ -L /usr/sbin/drra ] && [ -e /var/lib/alternatives/drra ] || fail "the single build has no alternatives link"
	rpm -Uvh --replacepkgs --replacefiles --nodeps /t/base.rpm > /tmp/rpm.log 2>&1 || { cat /tmp/rpm.log; fail "upgrade"; }
	check linux_reporting_agent "FIPS (system OpenSSL)"
	remove_all
	if [ "$1" = 0 ]; then
	    rpm -i --nodeps /t/single.rpm > /dev/null 2>&1 || fail "single install"
	    dnf -q -y install --allowerasing /t/o35.rpm > /tmp/dnf.log 2>&1 || { tail /tmp/dnf.log; fail "switch to openssl35"; }
	    check linux_reporting_agent-openssl35 "openssl35"
	    remove_all
	fi
	;;
esac
EOF
failed=0
for fips in 0 1; do
    for t in fresh upgrade switch single; do
	[ "${t}" = upgrade ] && [ -z "${OLD}" ] && continue
	[ "${t}" = single ] && [ -z "${SINGLE}" ] && continue
	[ "${t}" = switch ] && [ "${fips}" = 1 ] && continue   # openssl35 does not install in FIPS mode
	podman --storage-opt overlay.ignore_chown_errors=true run --rm \
	    -v "${T}/fips${fips}:/proc/sys/crypto/fips_enabled:ro,z" -v "${T}:/t:ro,z" \
	    registry.access.redhat.com/ubi8/ubi:latest bash /t/run.sh "${fips}" "${t}" || failed=1
    done
done
if [ "${failed}" != 0 ]; then
    echo "rpm_install_test.sh: FAILED"
    exit 1
fi
echo "rpm_install_test.sh: all tests passed"
