#!/bin/bash
# check_openssl.sh
# Fails unless a drra binary and every shared library it loads use
# OpenSSL 3.5 (the LTS) or later. Run by "make check-openssl" and by the
# RPM %check on every release build, so an RPM linked to an older OpenSSL
# (such as RHEL 8's 1.1.1k) cannot be built.
#
# Usage: tools/check_openssl.sh [drra binary] [minimum version]
#        (defaults ./drra and 3.5)

BIN="${1:-./drra}"
MIN="${2:-3.5}"
errors=0

fail() {
    echo "ERROR - $*"
    errors=$((errors + 1))
}

if [ ! -x "${BIN}" ]; then
    echo "ERROR - ${BIN} is not an executable"
    exit 1
fi
echo "Checking ${BIN} for OpenSSL ${MIN} or later"

# Libraries the binary itself names
NEEDED=$(readelf -d "${BIN}" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
echo "NEEDED: $(echo ${NEEDED})"
for lib in ${NEEDED}; do
    case "${lib}" in
	libssl.so.3|libcrypto.so.3) ;;
	libssl.so*|libcrypto.so*) fail "${BIN} needs ${lib}" ;;
    esac
done

# Every library that gets loaded, also through libcurl, krb5 and so on
LDD=$(ldd "${BIN}" 2>&1)
if echo "${LDD}" | grep -q "not found"; then
    fail "missing libraries: $(echo "${LDD}" | grep 'not found' | tr -s ' \t' ' ')"
fi
found=0
while read -r name path; do
    case "${name}" in
	libssl.so.3|libcrypto.so.3)
	    found=1
	    real=$(readlink -f "${path}")
	    ver=$(strings -a "${real}" | grep -m1 -oE '^OpenSSL [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2)
	    # libssl has no version text: libssl.so.3.5.5 names it
	    [ -n "${ver}" ] || ver=$(basename "${real}" | sed -n 's/^lib[a-z]*\.so\.\([0-9]*\.[0-9]*\.[0-9]*\)$/\1/p')
	    if [ -z "${ver}" ]; then
		fail "cannot read the OpenSSL version of ${real}"
	    elif [ "$(printf '%s\n%s\n' "${MIN}" "${ver}" | sort -V | head -1)" != "${MIN}" ]; then
		fail "${name} -> ${real} is OpenSSL ${ver}, older than ${MIN}"
	    else
		echo "OK: ${name} -> ${real} (OpenSSL ${ver})"
	    fi
	    ;;
	libssl.so*|libcrypto.so*)
	    fail "loads ${name} -> ${path} (an OpenSSL older than 3)"
	    ;;
    esac
done < <(echo "${LDD}" | awk '$2 == "=>" && $3 != "not" { print $1, $3 }')
[ "${found}" = 1 ] || fail "${BIN} loads no libssl.so.3 or libcrypto.so.3"

# What the binary sees when it runs: library version and libcurl's TLS
if [ "${errors}" = 0 ]; then
    if ! "${BIN}" -c /dev/null selftest; then
	fail "drra selftest failed"
    fi
fi

if [ "${errors}" != 0 ]; then
    echo "check_openssl.sh: ${errors} error(s), ${BIN} must not be released"
    exit 1
fi
echo "check_openssl.sh: OK"
exit 0
