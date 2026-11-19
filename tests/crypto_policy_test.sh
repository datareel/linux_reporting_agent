#!/bin/bash
# crypto_policy_test.sh
# Checks that the RHEL 8 linux_reporting_agent-openssl35 package follows
# the system crypto policy, in UBI 8 containers (podman, no root), with
# local test servers (RHEL 8's openssl s_server) and, unless NO_NET=1, a
# real handshake with a server that offers ML-KEM:
#   DEFAULT: works with an RSA 2048 server, refuses a TLS 1.1 server
#   LEGACY:  the policy's TLS 1.0 minimum is raised to TLS 1.2 (a TLS 1.1
#            server is refused), RSA 2048 works
#   FUTURE:  an RSA 2048 server certificate is refused (security level 3),
#            RSA 3072 works
#   FIPS policy (without FIPS mode): groups P-256:P-384:P-521 only
#   DEFAULT and FUTURE: X25519MLKEM768 with a server that offers it
#
# Usage: [NO_NET=1] tests/crypto_policy_test.sh <el8 openssl35 rpm>

RPM="${1:?usage: tests/crypto_policy_test.sh <el8 openssl35 rpm>}"
T=$(mktemp -d)
trap 'rm -rf "${T}"' EXIT
cp "${RPM}" "${T}/o35.rpm"
cat > "${T}/run.sh" <<'EOF'
# In the container: $1 == the policy, $2 == 1 for the real handshake
set -e
fail() { echo "FAIL - $*"; exit 1; }
dnf -q -y install libxml2 cpio crypto-policies-scripts openssl > /tmp/dnf.log 2>&1 || { tail /tmp/dnf.log; fail dnf; }
cd /tmp && rpm2cpio /t/o35.rpm | cpio -idm --quiet ./usr/sbin/drra
D=/tmp/usr/sbin/drra
update-crypto-policies --set "$1" > /dev/null 2>&1 || fail "set policy $1"
echo "== policy $(cat /etc/crypto-policies/state/current)"
# Test servers: RSA 2048 and RSA 3072 certificates for localhost
for b in 2048 3072; do
    openssl req -x509 -newkey rsa:$b -nodes -keyout k$b.pem -out c$b.pem -days 2 -subj /CN=localhost \
	-addext subjectAltName=DNS:localhost > /dev/null 2>&1
done
# The test servers (RHEL 8's platform-python, OpenSSL 1.1.1) set their own
# security level and TLS versions, so they offer what each test needs
# whatever the container's policy says (openssl s_server -www does not
# answer HEAD, which drra selftest sends)
# Python 3.6 has no ssl.TLSVersion: TLS versions come from OpenSSL options
# and the server's own OpenSSL config (TLS 1.0 and up, security level 0)
cat > /tmp/srv.cnf <<'EOC'
openssl_conf = default_modules
[default_modules]
ssl_conf = ssl_module
[ssl_module]
system_default = sd
[sd]
CipherString = DEFAULT:@SECLEVEL=0
MinProtocol = TLSv1
EOC
cat > /tmp/srv.py <<'EOP'
import http.server, ssl, sys
port, cert, key, maxv = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4]
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.set_ciphers('DEFAULT:@SECLEVEL=0')
if maxv == '1.1':
    ctx.options |= ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3
ctx.load_cert_chain(cert, key)
class H(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200); self.send_header('Content-Length', '0'); self.end_headers()
    do_GET = do_HEAD
    def log_message(self, *a): pass
s = http.server.HTTPServer(('127.0.0.1', port), H)
s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
EOP
srv() { OPENSSL_CONF=/tmp/srv.cnf /usr/libexec/platform-python /tmp/srv.py "$1" "c$2.pem" "k$2.pem" "$3" > /tmp/srv$1.log 2>&1 & }
srv 4431 2048 1.3
srv 4432 3072 1.3
srv 4433 2048 1.1
sleep 2
for p in 4431 4432 4433; do [ -s /tmp/srv$p.log ] && { cat /tmp/srv$p.log; fail "test server $p"; }; done
ini() { printf '[https]\nca_file=/tmp/c%s.pem\n' "$1" > /tmp/drra$1.ini; }
ini 2048; ini 3072
out=$($D -c /tmp/drra2048.ini selftest 2>&1 || true)
echo "${out}" | grep "^Crypto policy" | sed 's/^/  /'
echo "${out}" | grep "^TLS groups" | sed 's/^/  /'
echo "${out}" | grep -q "NOT applied" && fail "a policy setting was not applied"
conn() { $D -c /tmp/drra$2.ini selftest "https://localhost:$1/" 2>&1 | grep -E "^HTTP|^ERROR" | head -1; }
r2048=$(conn 4431 2048); r3072=$(conn 4432 3072); r11=$(conn 4433 2048)
echo "  RSA 2048 server: ${r2048}"
echo "  RSA 3072 server: ${r3072}"
echo "  TLS 1.1 server:  ${r11}"
case "${r11}" in ERROR*) ;; *) fail "a TLS 1.1 server was accepted";; esac
case "${r3072}" in HTTP*) ;; *) fail "the RSA 3072 server failed";; esac
case "$1" in
    FUTURE) case "${r2048}" in ERROR*) ;; *) fail "FUTURE accepted an RSA 2048 server";; esac ;;
    *) case "${r2048}" in HTTP*) ;; *) fail "$1 refused an RSA 2048 server";; esac ;;
esac
case "$1" in
    LEGACY) echo "${out}" | grep -q "raised to TLSv1.2" || fail "LEGACY minimum not raised" ;;
    FIPS) echo "${out}" | grep -q "^TLS groups: *P-256:P-384:P-521" || fail "FIPS policy groups" ;;
esac
if [ "$2" = 1 ] && [ "$1" != FIPS ] && [ "$1" != LEGACY ]; then
    pq=$($D -c /dev/null selftest https://pq.cloudflareresearch.com/ 2>&1 | grep -E "^HTTP|^ERROR" | head -1)
    echo "  pq.cloudflareresearch.com: ${pq}"
    case "${pq}" in *X25519MLKEM768*) ;; *) fail "no X25519MLKEM768 under $1";; esac
fi
echo "PASS - $1"
EOF
failed=0
net=1
[ "${NO_NET:-0}" = 1 ] && net=0
for p in DEFAULT LEGACY FUTURE FIPS; do
    podman --storage-opt overlay.ignore_chown_errors=true run --rm -v "${T}:/t:ro,z" \
	registry.access.redhat.com/ubi8/ubi:latest bash /t/run.sh "${p}" "${net}" || failed=1
done
if [ "${failed}" != 0 ]; then
    echo "crypto_policy_test.sh: FAILED"
    exit 1
fi
echo "crypto_policy_test.sh: all tests passed"
