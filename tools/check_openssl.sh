#!/bin/bash
# check_openssl.sh
# Release check of the OpenSSL a drra binary uses. Run by
# "make check-openssl" and by the RPM %check on every build, so an RPM
# with the wrong OpenSSL cannot be built.
#
#   standard (default): drra and every library it loads use OpenSSL MIN
#     (3.5) or later, from shared libraries or built in (RHEL 8 standard
#     build); nothing loads OpenSSL 1.x.
#   --fips: the RHEL 8 FIPS build. drra and its libcurl load RHEL 8's own
#     libssl.so.1.1 and libcrypto.so.1.1 from /usr/lib64, and nothing
#     loads OpenSSL 3.
#
# Both modes then run "drra selftest", which checks the OpenSSL that is
# really in use and that libcurl uses the same one.
#
# Usage: tools/check_openssl.sh [--fips] [drra binary] [minimum version]
#        (defaults ./drra and 3.5)

MODE=standard
if [ "${1}" = "--fips" ]; then
    MODE=fips
    shift
fi
BIN="${1:-./drra}"
MIN="${2:-3.5}"
errors=0

fail() {
    echo "ERROR - $*"
    errors=$((errors + 1))
}

# true when version $1 >= $2
version_ge() {
    [ "$(printf '%s\n%s\n' "${2}" "${1}" | sort -V | head -1)" = "${2}" ]
}

if [ ! -x "${BIN}" ]; then
    echo "ERROR - ${BIN} is not an executable"
    exit 1
fi
if [ "${MODE}" = fips ]; then
    echo "Checking ${BIN}: FIPS build, RHEL 8 system OpenSSL 1.1.1"
else
    echo "Checking ${BIN}: OpenSSL ${MIN} or later"
fi

# Libraries the binary itself names
NEEDED=$(readelf -d "${BIN}" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')
echo "NEEDED: $(echo ${NEEDED})"
for lib in ${NEEDED}; do
    case "${MODE}:${lib}" in
	standard:libssl.so.3|standard:libcrypto.so.3) ;;
	fips:libssl.so.1.1|fips:libcrypto.so.1.1) ;;
	*:libssl.so*|*:libcrypto.so*) fail "${BIN} needs ${lib}" ;;
    esac
done

# Every library that gets loaded, also through libcurl, krb5 and so on
LDD=$(ldd "${BIN}" 2>&1)
if echo "${LDD}" | grep -q "not found"; then
    fail "missing libraries: $(echo "${LDD}" | grep 'not found' | tr -s ' \t\n' ' ')"
fi
shared3=0
fips_ssl=0
fips_crypto=0
while read -r name path; do
    real=$(readlink -f "${path}")
    case "${MODE}:${name}" in
	standard:libssl.so.3|standard:libcrypto.so.3)
	    shared3=1
	    ver=$(strings -a "${real}" | grep -m1 -oE '^OpenSSL [0-9]+\.[0-9]+\.[0-9]+' | cut -d' ' -f2)
	    # libssl has no version text: libssl.so.3.5.5 names it
	    [ -n "${ver}" ] || ver=$(basename "${real}" | sed -n 's/^lib[a-z]*\.so\.\([0-9]*\.[0-9]*\.[0-9]*\)$/\1/p')
	    if [ -z "${ver}" ]; then
		fail "cannot read the OpenSSL version of ${real}"
	    elif ! version_ge "${ver}" "${MIN}"; then
		fail "${name} -> ${real} is OpenSSL ${ver}, older than ${MIN}"
	    else
		echo "OK: ${name} -> ${real} (OpenSSL ${ver})"
	    fi
	    ;;
	fips:libssl.so.1.1|fips:libcrypto.so.1.1)
	    case "${real}" in
		/usr/lib64/*|/lib64/*)
		    echo "OK: ${name} -> ${real} (system OpenSSL)"
		    [ "${name}" = libssl.so.1.1 ] && fips_ssl=1
		    [ "${name}" = libcrypto.so.1.1 ] && fips_crypto=1
		    ;;
		*) fail "${name} -> ${real} is not the system library" ;;
	    esac
	    ;;
	*:libssl.so*|*:libcrypto.so*)
	    fail "loads ${name} -> ${real}"
	    ;;
    esac
done < <(echo "${LDD}" | awk '$2 == "=>" && $3 != "not" { print $1, $3 }')

if [ "${MODE}" = fips ]; then
    [ "${fips_ssl}" = 1 ] || fail "${BIN} does not load the system libssl.so.1.1"
    [ "${fips_crypto}" = 1 ] || fail "${BIN} does not load the system libcrypto.so.1.1"
elif [ "${shared3}" = 0 ]; then
    # Built in (RHEL 8 standard build): read the version from the binary
    ver=$(strings -a "${BIN}" | grep -m1 -oE '^OpenSSL [0-9]+\.[0-9]+\.[0-9]+ ' | cut -d' ' -f2)
    if [ -z "${ver}" ]; then
	fail "${BIN} loads no OpenSSL and has none built in"
    elif ! version_ge "${ver}" "${MIN}"; then
	fail "built-in OpenSSL ${ver} is older than ${MIN}"
    else
	echo "OK: OpenSSL ${ver} built in"
    fi
fi

# What the binary sees when it runs: library version and libcurl's TLS.
# The standard RHEL 8 build fails it on a FIPS mode build host.
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
