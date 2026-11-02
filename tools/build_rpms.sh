#!/bin/bash
# build_rpms.sh
# Builds the source tarball, the utils asset (tools/build_utils.sh) and
# the RHEL 8, 9 and 10 RPMs in UBI containers with podman. Output goes
# to output/.
#
# Usage: tools/build_rpms.sh [8] [9] [10]     (default: all three)
#
# Builds from the committed tree (git archive HEAD), so commit first.

set -e
TOP="$(cd "$(dirname "$0")/.." && pwd)"
cd "${TOP}"
VERSION=$(sed -n 's/^#define AGENT_VERSION "\(.*\)"/\1/p' src/common.h)
NAME=linux_reporting_agent
RELEASES="${*:-8 9 10}"
OUT="${TOP}/output"
mkdir -p "${OUT}"

if ! git diff --quiet HEAD -- . 2>/dev/null; then
    echo "WARNING - uncommitted changes are not in the build (git archive HEAD)"
fi
TARBALL="${OUT}/${NAME}-${VERSION}.tar.gz"
git archive --format=tar.gz --prefix="${NAME}-${VERSION}/" -o "${TARBALL}" HEAD
echo "Source: ${TARBALL}"
# The utils asset (drra-utils-<version>.tar.gz), published with the RPMs
"${TOP}/tools/build_utils.sh"

for rel in ${RELEASES}; do
    echo "Building RHEL ${rel} RPM"
    # Rootless podman here has no subuids, so ignore chown errors
    podman --storage-opt overlay.ignore_chown_errors=true run --rm \
	-v "${OUT}:/out:z" -v "${TOP}/rpm:/spec:ro,z" \
	"registry.access.redhat.com/ubi${rel}/ubi:latest" bash -c "
set -e
dnf -q -y install rpm-build gcc-c++ make pkgconf-pkg-config openssl-devel libcurl-devel libxml2-devel bzip2-devel zlib-devel systemd-rpm-macros > /tmp/dnf.log 2>&1 || { tail -20 /tmp/dnf.log; exit 1; }
mkdir -p ~/rpmbuild/SOURCES
cp /out/${NAME}-${VERSION}.tar.gz ~/rpmbuild/SOURCES/
rpmbuild -bb --quiet /spec/${NAME}.spec
cp ~/rpmbuild/RPMS/*/${NAME}-*.rpm /out/
"
done
cd "${OUT}" && ls -1 ${NAME}-* && sha256sum ${NAME}-* | grep -v sha256 > ${NAME}-${VERSION}.sha256sum
