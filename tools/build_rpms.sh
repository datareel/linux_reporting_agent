#!/bin/bash
# build_rpms.sh
# Builds the source tarball, the utils asset (tools/build_utils.sh) and
# the RHEL 8, 9 and 10 RPMs in UBI containers with podman. Output goes
# to output/.
#
# Usage: [JOBS=4] tools/build_rpms.sh [8] [9] [10]     (default: all three)
#
# Builds from the committed tree (git archive HEAD), so commit first.
#
# The RPM %check runs tools/check_openssl.sh: RHEL 9/10 and the RHEL 8
# standard build use OpenSSL 3.5 or later, the RHEL 8 FIPS build RHEL 8's
# OpenSSL 1.1.1. The RHEL 8 standard build has OpenSSL and libcurl built
# in from tarballs downloaded once into output/ and checked against
# tools/bundled.sha256.

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

# RHEL 8: the OpenSSL and curl tarballs built into drra-standard,
# downloaded once into output/ and checked against tools/bundled.sha256
OPENSSL_VERSION=$(sed -n 's/^%global openssl_version //p' rpm/${NAME}.spec)
CURL_VERSION=$(sed -n 's/^%global curl_version //p' rpm/${NAME}.spec)
BUNDLED="openssl-${OPENSSL_VERSION}.tar.gz curl-${CURL_VERSION}.tar.gz"
case " ${RELEASES} " in
    *" 8 "*)
	for t in ${BUNDLED}; do
	    case "${t}" in
		openssl-*) url="https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/${t}" ;;
		curl-*) url="https://curl.se/download/${t}" ;;
	    esac
	    if [ ! -f "${OUT}/${t}" ]; then
		curl -sSfL -o "${OUT}/${t}.download" "${url}"
		mv "${OUT}/${t}.download" "${OUT}/${t}"
	    fi
	    if ! (cd "${OUT}" && grep " ${t}\$" "${TOP}/tools/bundled.sha256" | sha256sum -c --quiet - && grep -q " ${t}\$" "${TOP}/tools/bundled.sha256"); then
		echo "ERROR - ${OUT}/${t} does not match tools/bundled.sha256"
		exit 1
	    fi
	done
	;;
esac

for rel in ${RELEASES}; do
    echo "Building RHEL ${rel} RPM"
    if [ "${rel}" = 8 ]; then
	# drra-standard builds OpenSSL (perl) and curl; drra-fips uses the system ones
	DEVEL="openssl-devel libcurl-devel perl-interpreter perl-IPC-Cmd perl-Data-Dumper perl-Time-Piece"
	EXTRA="for t in ${BUNDLED}; do cp /out/\$t ~/rpmbuild/SOURCES/; done"
    else
	DEVEL="openssl-devel libcurl-devel"
	EXTRA=":"
    fi
    # Rootless podman here has no subuids, so ignore chown errors
    podman --storage-opt overlay.ignore_chown_errors=true run --rm \
	-v "${OUT}:/out:z" -v "${TOP}/rpm:/spec:ro,z" \
	"registry.access.redhat.com/ubi${rel}/ubi:latest" bash -c "
set -e
dnf -q -y install rpm-build gcc-c++ make binutils pkgconf-pkg-config ${DEVEL} libxml2-devel bzip2-devel zlib-devel systemd-rpm-macros > /tmp/dnf.log 2>&1 || { tail -20 /tmp/dnf.log; exit 1; }
mkdir -p ~/rpmbuild/SOURCES
cp /out/${NAME}-${VERSION}.tar.gz ~/rpmbuild/SOURCES/
${EXTRA}
rpmbuild -bb --quiet --define \"_smp_mflags -j${JOBS:-4}\" /spec/${NAME}.spec
cp ~/rpmbuild/RPMS/*/${NAME}-*.rpm /out/
"
done
cd "${OUT}" && ls -1 ${NAME}-*${VERSION}* && sha256sum ${NAME}-*${VERSION}* | grep -v sha256 > ${NAME}-${VERSION}.sha256sum
