#!/bin/bash
# rpm_install_test.sh
# Install tests of the RHEL 8 RPM in UBI 8 containers (podman, no root):
# which build /usr/sbin/drra points to with FIPS mode off and on (a
# fips_enabled file mounted over /proc/sys/crypto/fips_enabled), on a fresh
# install and on an upgrade from an older RPM (whose /usr/sbin/drra is a
# plain file), then rpm -V and removal. Needs network for dnf.
#
# Usage: tests/rpm_install_test.sh <new el8 rpm> [old el8 rpm]

NEW="${1:?usage: tests/rpm_install_test.sh <new el8 rpm> [old el8 rpm]}"
OLD="${2}"
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
cp "${NEW}" "${T}/new.rpm"
[ -n "${OLD}" ] && cp "${OLD}" "${T}/old.rpm"
echo 0 > "${T}/fips0"
echo 1 > "${T}/fips1"
cat > "${T}/run.sh" <<'EOF'
# In the container: $1 == expected fips_enabled, $2 == fresh|upgrade
set -e
# Rootless podman maps only one group: let the drra-upload group be gid 0
groupadd -o -g 0 drra-upload
want=drra-standard
[ "$1" = 1 ] && want=drra-fips
echo "fips_enabled=$(cat /proc/sys/crypto/fips_enabled) $2"
if [ "$2" = upgrade ]; then
    dnf -q -y install /t/old.rpm > /tmp/dnf.log 2>&1 || { tail /tmp/dnf.log; exit 1; }
    [ -f /usr/sbin/drra ] && [ ! -L /usr/sbin/drra ] || { echo "FAIL - old RPM has no plain /usr/sbin/drra"; exit 1; }
fi
dnf -q -y install /t/new.rpm > /tmp/dnf.log 2>&1 || { tail /tmp/dnf.log; exit 1; }
got=$(basename "$(readlink -f /usr/sbin/drra)")
[ "${got}" = "${want}" ] || { echo "FAIL - /usr/sbin/drra -> ${got}, want ${want}"; exit 1; }
echo "PASS - /usr/sbin/drra -> ${got}"
/usr/sbin/drra -c /dev/null selftest > /tmp/selftest.log || { cat /tmp/selftest.log; echo "FAIL - selftest"; exit 1; }
echo "PASS - selftest: $(sed -n 's/^Build: *//p' /tmp/selftest.log)"
rpm -V linux_reporting_agent || { echo "FAIL - rpm -V"; exit 1; }
echo "PASS - rpm -V"
dnf -q -y remove linux_reporting_agent > /dev/null 2>&1
[ ! -e /usr/sbin/drra ] && ! alternatives --display drra > /dev/null 2>&1 || { echo "FAIL - left after removal"; exit 1; }
echo "PASS - removed with its alternatives"
EOF
failed=0
for fips in 0 1; do
    for mode in fresh upgrade; do
	[ "${mode}" = upgrade ] && [ -z "${OLD}" ] && continue
	echo "== FIPS ${fips}, ${mode}"
	podman --storage-opt overlay.ignore_chown_errors=true run --rm \
	    -v "${T}/fips${fips}:/proc/sys/crypto/fips_enabled:ro,z" -v "${T}:/t:ro,z" \
	    registry.access.redhat.com/ubi8/ubi:latest bash /t/run.sh "${fips}" "${mode}" || failed=1
    done
done
if [ "${failed}" != 0 ]; then
    echo "rpm_install_test.sh: FAILED"
    exit 1
fi
echo "rpm_install_test.sh: all tests passed"
