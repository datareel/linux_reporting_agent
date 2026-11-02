#!/bin/bash
# install_util.sh
# Installs a util from utils/<name>/ on an agent host: the program in
# /usr/local/libexec/drra-utils/, its upload hook file in
# /etc/drra/uploads.d/ and, with --cron, its schedule in /etc/cron.d/.
# A dry run unless --apply is given. The DRSM manifest
# (utils/<name>/drsm/uploads/<name>) goes on the monitor host by hand.
#
# Usage: sudo utils/install_util.sh <name> [--cron] [--apply]

HERE=$(cd "$(dirname "$0")" && pwd)
NAME=""
CRON=0
APPLY=0
for a in "$@"; do
    case "${a}" in
	--cron) CRON=1 ;;
	--apply) APPLY=1 ;;
	-h|--help) sed -n 2,8p "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
	-*) echo "Unknown option ${a}" >&2; exit 2 ;;
	*) NAME="${a}" ;;
    esac
done
if ! [[ "${NAME}" =~ ^[a-z0-9_]{1,32}$ ]] || [ ! -x "${HERE}/${NAME}/${NAME}" ]; then
    echo "Usage: $0 <name> [--cron] [--apply]   (a folder in ${HERE} with an executable <name>)" >&2
    exit 2
fi
SRC="${HERE}/${NAME}"
LIBEXEC=/usr/local/libexec/drra-utils
UPLOADS_D=/etc/drra/uploads.d

function run()
{
    if [ "${APPLY}" == "1" ]; then
	echo "+ $*"
	"$@" || { echo "ERROR - failed: $*" >&2; exit 1; }
    else
	echo "would run: $*"
    fi
}

if [ "${APPLY}" == "1" ] && [ "$(id -u)" != "0" ]; then
    echo "Run --apply as root" >&2
    exit 1
fi
[ "${APPLY}" == "1" ] || echo "Dry run, nothing is changed (add --apply)"

run install -D -o root -g root -m 0755 "${SRC}/${NAME}" "${LIBEXEC}/${NAME}"
if [ -f "${SRC}/${NAME}.ini" ]; then
    if [ "$(id -u)" == "0" ] && [ ! -d "${UPLOADS_D}" ]; then
	echo "WARNING - ${UPLOADS_D} is missing: install the agent first, or use ${NAME} without --submit"
    fi
    if [ -f "${UPLOADS_D}/${NAME}.ini" ]; then
	echo "${UPLOADS_D}/${NAME}.ini is there already, left as it is"
    else
	run install -o root -g root -m 0600 "${SRC}/${NAME}.ini" "${UPLOADS_D}/${NAME}.ini"
    fi
fi
if [ "${CRON}" == "1" ]; then
    if [ ! -f "${SRC}/${NAME}.cron" ]; then
	echo "ERROR - ${NAME} has no ${NAME}.cron" >&2
	exit 1
    fi
    run install -o root -g root -m 0644 "${SRC}/${NAME}.cron" "/etc/cron.d/${NAME}"
fi
echo "DRSM manifest for the monitor host: ${SRC}/drsm/uploads/${NAME}"
