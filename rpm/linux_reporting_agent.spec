# DataReel Reporting Agent for Linux
# Built by tools/build_rpms.sh from the source tarball
# linux_reporting_agent-%{agent_version}.tar.gz

%global agent_version 1.1.3
# RHEL 8 has two packages, like DRCM and DRLB (build the second with
# --define "openssl35 1"):
#   linux_reporting_agent: RHEL 8's own OpenSSL 1.1.1 and libcurl, so
#     crypto-policies and FIPS mode apply. No ML-KEM. The package for hosts
#     in FIPS mode.
#   linux_reporting_agent-openssl35: OpenSSL 3.5 and libcurl (versions
#     below) built in (static), hybrid post-quantum key exchange
#     (X25519MLKEM768, then X25519 and P-256). Its OpenSSL is not FIPS
#     validated: it will not install on a host in FIPS mode (%pre) and
#     refuses to run in FIPS mode (exit 78). Provides linux_reporting_agent
#     and conflicts with it; switch with
#     dnf install --allowerasing ./<other package>.rpm
# tools/build_rpms.sh puts the OpenSSL and curl tarballs (checked against
# tools/bundled.sha256) next to the agent tarball.
# RHEL 9 and 10: one package on the system OpenSSL (3.5 or later) and libcurl.
%global pkgbase linux_reporting_agent
%global openssl_version 3.5.9
%global curl_version 8.23.0
%global min_openssl 3.5
%if 0%{?rhel} == 8 && 0%{?openssl35}
%global drra_openssl35 1
%endif

Name:           %{pkgbase}%{?drra_openssl35:-openssl35}
Version:        1.1.3
Release:        1%{?dist}
Summary:        DataReel Reporting Agent for Linux: host reports and vulnerability scans for DRSM
License:        GPL-3.0-or-later
URL:            https://datareel.com/
Source0:        %{pkgbase}-%{agent_version}.tar.gz
%if 0%{?drra_openssl35}
Source1:        https://curl.se/download/curl-%{curl_version}.tar.gz
Source2:        https://github.com/openssl/openssl/releases/download/openssl-%{openssl_version}/openssl-%{openssl_version}.tar.gz
%endif

BuildRequires:  gcc-c++ make pkgconf-pkg-config binutils
BuildRequires:  libxml2-devel bzip2-devel zlib-devel
BuildRequires:  systemd-rpm-macros
%if 0%{?drra_openssl35}
# OpenSSL 3.5 and libcurl built in
BuildRequires:  perl-interpreter perl-IPC-Cmd perl-Data-Dumper perl-Time-Piece
Provides:       %{pkgbase} = %{version}-%{release}
Conflicts:      %{pkgbase}
Provides:       bundled(openssl) = %{openssl_version}
Provides:       bundled(curl) = %{curl_version}
%else
%if 0%{?rhel} == 8
# RHEL 8's own OpenSSL 1.1.1 (FIPS) and libcurl
BuildRequires:  openssl-devel libcurl-devel
Requires:       openssl-libs%{?_isa} libcurl%{?_isa}
%else
BuildRequires:  openssl-devel >= 1:%{min_openssl} libcurl-devel
Requires:       openssl-libs%{?_isa} >= 1:%{min_openssl} libcurl
%endif
%endif
Requires(pre):  shadow-utils
Requires:       libxml2 bzip2-libs zlib
# OVAL vulnerability scans (RHEL 8 and 9) and compliance scans
Recommends:     openscap-scanner
Suggests:       scap-security-guide samba-client openssh-clients
%{?systemd_requires}

%description
The DataReel Reporting Agent for Linux runs as a systemd service and
sends a report about the host every 15 minutes: system and hardware,
CPU, memory, disk and network use, logged in users, SELinux, firewall
and SSH settings, failed services, pending updates, the Red Hat
security advisories that apply (OpenSCAP OVAL scan, Red Hat CSAF/VEX
data or dnf updateinfo) and the installed packages. Reports go to a web server as signed HTTPS
uploads, or to a CIFS share or SCP server. The host only makes outgoing
connections, so it can be monitored over the internet. DataReel System
Monitor (DRSM) reads the reports with its linux plugins.
%if 0%{?drra_openssl35}

This RHEL 8 package has OpenSSL 3.5 and libcurl built in, with hybrid
post-quantum TLS key exchange. It is not for hosts in FIPS mode: use the
linux_reporting_agent package there.
%endif

%prep
%setup -q -n %{pkgbase}-%{agent_version}
%if 0%{?drra_openssl35}
%setup -q -T -D -a 1 -a 2 -n %{pkgbase}-%{agent_version}
%endif

%build
%if 0%{?drra_openssl35}
B=$PWD/bundled
# OpenSSL, static, providers built in. Its own settings folder
# (/etc/drra/openssl, empty): RHEL 8's openssl.cnf and crypto-policies are
# for OpenSSL 1.1.1 and the FIPS package.
pushd openssl-%{openssl_version}
./Configure linux-x86_64 --prefix=$B --libdir=lib --openssldir=/etc/drra/openssl \
  no-shared no-module no-legacy no-engine no-tests no-docs no-apps no-ssl3 no-comp -fPIC
make %{?_smp_mflags}
make install_sw
popd
# libcurl, static, only HTTP and HTTPS, on that OpenSSL (not the system
# 1.1.1 headers), the system CA bundle
pushd curl-%{curl_version}
./configure --prefix=$B --disable-shared --enable-static --with-pic \
  --with-openssl=$B --with-zlib --with-ca-bundle=/etc/pki/tls/certs/ca-bundle.crt --without-ca-path \
  --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-dict \
  --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smtp --disable-gopher \
  --disable-mqtt --disable-websockets --disable-ntlm --disable-manual --disable-docs \
  --without-libpsl --without-brotli --without-zstd --without-nghttp2 --without-nghttp3 \
  --without-libidn2 --without-libssh2 --without-libssh --without-gssapi --without-libgsasl \
  CPPFLAGS="-I$B/include" LDFLAGS="-L$B/lib" LIBS="-ldl -lpthread" \
  PKG_CONFIG_PATH="$B/lib/pkgconfig" PKG_CONFIG_LIBDIR="$B/lib/pkgconfig"
make %{?_smp_mflags}
make install
popd
make %{?_smp_mflags} CXXFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}" DEFINES=-DDRRA_BUNDLED_OPENSSL \
  SSL_CFLAGS="-I$B/include" SSL_LIBS="$B/lib/libssl.a $B/lib/libcrypto.a -ldl -lpthread" \
  CURL_CFLAGS="-I$B/include" CURL_LIBS="$B/lib/libcurl.a -lz"
%else
%if 0%{?rhel} == 8
make %{?_smp_mflags} CXXFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}" DEFINES=-DDRRA_FIPS_BUILD
%else
make %{?_smp_mflags} CXXFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}"
%endif
%endif

%check
%if 0%{?rhel} == 8 && !0%{?drra_openssl35}
# RHEL 8 FIPS package: RHEL 8's own libssl.so.1.1, nothing from OpenSSL 3
tools/check_openssl.sh --fips ./drra
%else
# OpenSSL 3.5 or later, built in or shared
tools/check_openssl.sh ./drra %{min_openssl}
%endif

%install
make install DESTDIR=%{buildroot} UNITDIR=%{_unitdir}
install -d -m 0755 %{buildroot}%{_docdir}/%{pkgbase}
install -m 0644 README.md LICENSE AGENTS.md CLAUDE.md GEMINI.md %{buildroot}%{_docdir}/%{pkgbase}/
cp -a php drsm docs %{buildroot}%{_docdir}/%{pkgbase}/
rm -f %{buildroot}%{_docdir}/%{pkgbase}/docs/make_docs_html.py %{buildroot}%{_docdir}/%{pkgbase}/docs/security_design.php

%pre
%if 0%{?drra_openssl35}
# Its OpenSSL is not FIPS validated: not for a host in FIPS mode
if [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" = "1" ]; then
    echo "ERROR - FIPS mode is on: %{name} has its own OpenSSL 3.5, which is not FIPS validated." >&2
    echo "        Install the %{pkgbase} package (RHEL 8's FIPS OpenSSL 1.1.1) instead." >&2
    exit 1
fi
%endif
# Members of drra-upload may queue reports from other tools (drra submit)
getent group drra-upload >/dev/null || groupadd -r drra-upload
exit 0

%post
# The other RHEL 8 package (linux_reporting_agent / -openssl35) in the same
# transaction is a switch (dnf install --allowerasing): leave the service as it is
drra_other_build() { rpm -q %{pkgbase} %{pkgbase}-openssl35 2>/dev/null | grep -v -e 'not installed' -e "^%{name}-%{version}-%{release}" | grep -q . ; }
if [ $1 -eq 1 ] && ! drra_other_build; then
    systemctl preset drra.service >/dev/null 2>&1 || :
fi

%preun
drra_other_build() { rpm -q %{pkgbase} %{pkgbase}-openssl35 2>/dev/null | grep -v -e 'not installed' -e "^%{name}-%{version}-%{release}" | grep -q . ; }
if [ $1 -eq 0 ] && ! drra_other_build; then
    # Removal, not an upgrade or a switch to the other RHEL 8 package
    systemctl --no-reload disable drra.service >/dev/null 2>&1 || :
    systemctl stop drra.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ]; then
    systemctl try-restart drra.service >/dev/null 2>&1 || :
fi

%posttrans
# A test build of 1.1.3 had both RHEL 8 builds in one package behind an
# alternatives link: drop its leftover alternatives entry
if [ -e /var/lib/alternatives/drra ] && [ ! -L %{_sbindir}/drra ]; then
    rm -f /var/lib/alternatives/drra
    [ -L /etc/alternatives/drra ] && rm -f /etc/alternatives/drra
fi
# A switch between the RHEL 8 packages: a running service picks up the new program
systemctl try-restart drra.service >/dev/null 2>&1 || :
exit 0

%files
%{_sbindir}/drra
%{_unitdir}/drra.service
%dir %attr(0700,root,root) %{_sysconfdir}/drra
%config(noreplace) %attr(0600,root,root) %{_sysconfdir}/drra/drra.ini
%dir %attr(0755,root,root) %{_sysconfdir}/drra/report.d
%config(noreplace) %{_sysconfdir}/logrotate.d/drra
%dir %attr(0700,root,root) %{_localstatedir}/lib/drra
%dir %attr(0750,root,root) %{_localstatedir}/log/drra
%dir %attr(0700,root,root) %{_sysconfdir}/drra/uploads.d
%dir %attr(0755,root,root) %{_localstatedir}/spool/drra
%dir %attr(2770,root,drra-upload) %{_localstatedir}/spool/drra/uploads
%{_docdir}/%{pkgbase}

%changelog
* Thu Nov 19 2026 DataReel Software Development - 1.1.3-1
- OpenSSL 3.5 or later on every package, RHEL 8 included. RHEL 8 has two
  packages, like DRCM and DRLB: linux_reporting_agent uses RHEL 8's own
  OpenSSL 1.1.1 and libcurl, so crypto-policies and FIPS mode apply (the
  package for hosts in FIPS mode); linux_reporting_agent-openssl35 has
  OpenSSL 3.5.9 and libcurl 8.23.0 built in, follows the system crypto
  policy, and offers hybrid post-quantum key exchange (X25519MLKEM768
  first). It will not install or run in FIPS mode. Switch between them
  with dnf install --allowerasing.
- RHEL 9 and 10 RPMs require openssl-libs 3.5 or later
- [https] tls_groups sets the TLS key exchange groups
- TLS 1.2 is the oldest TLS version the agent uses, whatever the crypto policy
- The log line of each upload and registration names the TLS version,
  cipher and key exchange group
- drra selftest [URL]: the build, OpenSSL, libcurl, FIPS mode and crypto
  policy, and the TLS version, cipher and key exchange group of a test
  connection
- The RPM build fails unless each binary uses the OpenSSL it must
  (tools/check_openssl.sh, make check-openssl)
- Security design white paper (docs/security_design.html, with quantum
  computing) and AI-assisted guide (AGENTS.md, CLAUDE.md, GEMINI.md),
  installed with the HTML documentation in the doc folder

* Sun Nov 01 2026 DataReel Software Development - 1.1.2-1
- CSAF/VEX scans use Red Hat's advisory severity from dnf instead of the
  worst CVE severity (an Important kernel update was counted as Critical)

* Sun Nov 01 2026 DataReel Software Development - 1.1.1-1
- Scans by hand: "drra scan" sends a report with the results right away,
  and with [scan] enabled=0 every report carries the last manual scan
  (mode=manual) instead of "disabled"

* Fri Oct 30 2026 DataReel Software Development - 1.1-1
- Release 1.1: first stable release of the 1.0 betas; HTML documentation
  set (docs/, tools/gen_docs.py)

* Thu Oct 29 2026 DataReel Software Development - 1.0-0.beta2
- Report hooks: scripts in /etc/drra/report.d run with each report and
  their output goes in a HOOKS section for DRSM ([hooks] in drra.ini)
- Hook uploads: files from other tools (drra submit, /var/spool/drra/uploads)
  sent to hook.php on the report server ([uploads] in drra.ini)

* Thu Oct 29 2026 DataReel Software Development - 1.0-0.beta1
- First beta: C++ agent, signed HTTPS uploads, CIFS and SCP delivery,
  OpenSCAP OVAL, CSAF/VEX (RHEL 10) and dnf vulnerability scans,
  compliance scans, DRSM plugins
