#!/bin/bash
# build_utils.sh
# Builds the utils release asset: output/drra-utils-<version>.tar.gz
# (and .sha256sum), published next to the agent RPMs of the same
# release. It holds utils/ without the tests (they need the agent
# source tree, which is in the source tarball): README.md,
# install_util.sh and each util with its README, upload hook file and
# DRSM manifest. Unpacks to drra-utils-<version>/.
#
# Usage: tools/build_utils.sh        (tools/build_rpms.sh runs it too)
#
# Builds from the committed tree (git archive HEAD), so commit first.

set -e
TOP="$(cd "$(dirname "$0")/.." && pwd)"
cd "${TOP}"
VERSION=$(sed -n 's/^#define AGENT_VERSION "\(.*\)"/\1/p' src/common.h)
NAME=drra-utils-${VERSION}
OUT="${TOP}/output"
mkdir -p "${OUT}"

if ! git diff --quiet HEAD -- utils 2>/dev/null; then
    echo "WARNING - uncommitted changes in utils/ are not in the build (git archive HEAD)"
fi
git archive --format=tar.gz --prefix="${NAME}/" --add-file=LICENSE -o "${OUT}/${NAME}.tar.gz" \
    HEAD:utils . ':(exclude,glob)*/tests/**'
cd "${OUT}" && sha256sum "${NAME}.tar.gz" > "${NAME}.tar.gz.sha256sum"
echo "Utils: ${OUT}/${NAME}.tar.gz"
