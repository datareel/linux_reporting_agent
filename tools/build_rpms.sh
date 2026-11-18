#!/bin/bash
# build_rpms.sh
# Builds the source tarball, the utils asset (tools/build_utils.sh) and
# the RHEL 8, 9 and 10 RPMs in UBI containers with podman. Output goes
# to output/.
#
# Usage: tools/build_rpms.sh [8] [9] [10]     (default: all three)
#
# Builds from the committed tree (git archive HEAD), so commit first.
#
# Every RPM links OpenSSL 3.5 or later (the RPM %check runs
# tools/check_openssl.sh). RHEL 8 builds use EPEL 8's openssl3 and a static
# libcurl built from the curl tarball, which is downloaded once into
# output/ and must match tools/curl.sha256.

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

CURL_VERSION=$(sed -n 's/^%global curl_version //p' rpm/${NAME}.spec)
CURL_TARBALL="curl-${CURL_VERSION}.tar.gz"
case " ${RELEASES} " in
    *" 8 "*)
	if [ ! -f "${OUT}/${CURL_TARBALL}" ]; then
	    curl -sSfL -o "${OUT}/${CURL_TARBALL}.download" "https://curl.se/download/${CURL_TARBALL}"
	    mv "${OUT}/${CURL_TARBALL}.download" "${OUT}/${CURL_TARBALL}"
	fi
	if ! (cd "${OUT}" && grep " ${CURL_TARBALL}\$" "${TOP}/tools/curl.sha256" | sha256sum -c --quiet -); then
	    echo "ERROR - ${OUT}/${CURL_TARBALL} does not match tools/curl.sha256"
	    exit 1
	fi
	;;
esac

for rel in ${RELEASES}; do
    echo "Building RHEL ${rel} RPM"
    if [ "${rel}" = 8 ]; then
	# EPEL 8 has openssl3 (3.5); RHEL 8's openssl-devel is 1.1.1k
	PRE="dnf -q -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm > /tmp/dnf.log 2>&1 || { tail -20 /tmp/dnf.log; exit 1; }"
	DEVEL="openssl3-devel"
	EXTRA="cp /out/${CURL_TARBALL} ~/rpmbuild/SOURCES/"
    else
	PRE=":"
	DEVEL="openssl-devel libcurl-devel"
	EXTRA=":"
    fi
    # Rootless podman here has no subuids, so ignore chown errors
    podman --storage-opt overlay.ignore_chown_errors=true run --rm \
	-v "${OUT}:/out:z" -v "${TOP}/rpm:/spec:ro,z" \
	"registry.access.redhat.com/ubi${rel}/ubi:latest" bash -c "
set -e
${PRE}
dnf -q -y install rpm-build gcc-c++ make binutils pkgconf-pkg-config ${DEVEL} libxml2-devel bzip2-devel zlib-devel systemd-rpm-macros > /tmp/dnf.log 2>&1 || { tail -20 /tmp/dnf.log; exit 1; }
mkdir -p ~/rpmbuild/SOURCES
cp /out/${NAME}-${VERSION}.tar.gz ~/rpmbuild/SOURCES/
${EXTRA}
rpmbuild -bb --quiet /spec/${NAME}.spec
cp ~/rpmbuild/RPMS/*/${NAME}-*.rpm /out/
"
done
cd "${OUT}" && ls -1 ${NAME}-*${VERSION}* && sha256sum ${NAME}-*${VERSION}* | grep -v sha256 > ${NAME}-${VERSION}.sha256sum
