# DataReel Reporting Agent for Linux
# Built by tools/build_rpms.sh from the source tarball
# linux_reporting_agent-%{agent_version}.tar.gz

%global agent_version 1.1.3
# RHEL 8 has two builds of drra in one RPM, chosen with alternatives:
#   drra-standard: OpenSSL 3.5 and libcurl (versions below) built in
#     (static), hybrid post-quantum key exchange (X25519MLKEM768, then
#     X25519 and P-256). Its OpenSSL is not FIPS validated: it refuses to
#     run in FIPS mode.
#   drra-fips: RHEL 8's own OpenSSL 1.1.1 and libcurl, so crypto-policies
#     and FIPS mode apply. No ML-KEM.
# Installing picks drra-fips when /proc/sys/crypto/fips_enabled is 1.
# tools/build_rpms.sh puts the OpenSSL and curl tarballs (checked against
# tools/bundled.sha256) next to the agent tarball.
# RHEL 9 and 10 use the system OpenSSL (3.5 or later) and libcurl.
%global openssl_version 3.5.9
%global curl_version 8.23.0
%global min_openssl 3.5

Name:           linux_reporting_agent
Version:        1.1.3
Release:        1%{?dist}
Summary:        DataReel Reporting Agent for Linux: host reports and vulnerability scans for DRSM
License:        GPL-3.0-or-later
URL:            https://datareel.com/
Source0:        %{name}-%{agent_version}.tar.gz
%if 0%{?rhel} == 8
Source1:        https://curl.se/download/curl-%{curl_version}.tar.gz
Source2:        https://github.com/openssl/openssl/releases/download/openssl-%{openssl_version}/openssl-%{openssl_version}.tar.gz
%endif

BuildRequires:  gcc-c++ make pkgconf-pkg-config binutils
BuildRequires:  libxml2-devel bzip2-devel zlib-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  openssl-devel libcurl-devel
%if 0%{?rhel} == 8
# The bundled OpenSSL build
BuildRequires:  perl-interpreter perl-IPC-Cmd perl-Data-Dumper perl-Time-Piece
# drra-fips
Requires:       openssl-libs%{?_isa} libcurl%{?_isa}
Requires(posttrans): chkconfig
Requires(preun): chkconfig
Provides:       bundled(openssl) = %{openssl_version}
Provides:       bundled(curl) = %{curl_version}
%else
BuildRequires:  openssl-devel >= 1:%{min_openssl}
Requires:       openssl-libs%{?_isa} >= 1:%{min_openssl} libcurl
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

%prep
%setup -q -n %{name}-%{agent_version}
%if 0%{?rhel} == 8
%setup -q -T -D -a 1 -a 2 -n %{name}-%{agent_version}
%endif

%build
%if 0%{?rhel} == 8
B=$PWD/bundled
# OpenSSL, static, providers built in. Its own settings folder
# (/etc/drra/openssl, empty): RHEL 8's openssl.cnf and crypto-policies are
# for OpenSSL 1.1.1 and the FIPS build.
pushd openssl-%{openssl_version}
./Configure linux-x86_64 --prefix=$B --libdir=lib --openssldir=/etc/drra/openssl \
  no-shared no-module no-legacy no-engine no-tests no-docs no-apps no-ssl3 no-comp -fPIC
make %{?_smp_mflags}
make install_sw
popd
# libcurl, static, only HTTP and HTTPS, on that OpenSSL (not the system
# 1.1.1 headers from openssl-devel), the system CA bundle
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
mv drra drra-standard
make clean
make %{?_smp_mflags} CXXFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}" DEFINES=-DDRRA_FIPS_BUILD
mv drra drra-fips
cp -p drra-standard drra
%else
make %{?_smp_mflags} CXXFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}"
%endif

%check
%if 0%{?rhel} == 8
# Standard: OpenSSL 3.5 or later. FIPS: RHEL 8's libssl.so.1.1.
tools/check_openssl.sh ./drra-standard %{min_openssl}
tools/check_openssl.sh --fips ./drra-fips
%else
# No RPM linked to an OpenSSL older than 3.5
tools/check_openssl.sh ./drra %{min_openssl}
%endif

%install
make install DESTDIR=%{buildroot} UNITDIR=%{_unitdir}
install -d -m 0755 %{buildroot}%{_docdir}/%{name}
install -m 0644 README.md LICENSE %{buildroot}%{_docdir}/%{name}/
cp -a php drsm %{buildroot}%{_docdir}/%{name}/
%if 0%{?rhel} == 8
# /usr/sbin/drra is an alternatives link to one of the two builds
install -d -m 0755 %{buildroot}%{_libexecdir}/drra
install -m 0755 drra-standard drra-fips %{buildroot}%{_libexecdir}/drra/
rm -f %{buildroot}%{_sbindir}/drra
touch %{buildroot}%{_sbindir}/drra
%endif

%pre
# Members of drra-upload may queue reports from other tools (drra submit)
getent group drra-upload >/dev/null || groupadd -r drra-upload
exit 0

%post
%systemd_post drra.service

%preun
%systemd_preun drra.service
%if 0%{?rhel} == 8
if [ $1 -eq 0 ]; then
    %{_sbindir}/alternatives --remove drra %{_libexecdir}/drra/drra-standard
    %{_sbindir}/alternatives --remove drra %{_libexecdir}/drra/drra-fips
fi
%endif

%postun
%systemd_postun_with_restart drra.service

%if 0%{?rhel} == 8
%posttrans
# After an upgrade from 1.1.2 or older /usr/sbin/drra is still the old
# binary (a plain file): the alternatives link replaces it
if [ -f %{_sbindir}/drra ] && [ ! -L %{_sbindir}/drra ]; then
    rm -f %{_sbindir}/drra
fi
%{_sbindir}/alternatives --install %{_sbindir}/drra drra %{_libexecdir}/drra/drra-standard 20
%{_sbindir}/alternatives --install %{_sbindir}/drra drra %{_libexecdir}/drra/drra-fips 10
# FIPS mode: the FIPS build (the standard build does not run in FIPS mode)
if [ "$(cat /proc/sys/crypto/fips_enabled 2>/dev/null)" = "1" ]; then
    %{_sbindir}/alternatives --set drra %{_libexecdir}/drra/drra-fips
fi
# A running service picks up the new link
systemctl try-restart drra.service >/dev/null 2>&1 || :
%endif

%files
%if 0%{?rhel} == 8
%ghost %{_sbindir}/drra
%dir %{_libexecdir}/drra
%{_libexecdir}/drra/drra-standard
%{_libexecdir}/drra/drra-fips
%else
%{_sbindir}/drra
%endif
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
%{_docdir}/%{name}

%changelog
* Wed Nov 18 2026 DataReel Software Development - 1.1.3-1
- RHEL 8: two builds in the RPM, /usr/sbin/drra is an alternatives link:
  drra-standard has OpenSSL 3.5.9 and libcurl 8.23.0 built in, with hybrid
  post-quantum key exchange (X25519MLKEM768, then X25519 and P-256), and
  refuses to run in FIPS mode; drra-fips uses RHEL 8's OpenSSL 1.1.1 and
  libcurl, so crypto-policies and FIPS mode apply. Installing picks
  drra-fips when FIPS mode is on.
- RHEL 9 and 10 RPMs require openssl-libs 3.5 or later
- [https] tls_groups sets the TLS key exchange groups
- TLS 1.2 is the oldest TLS version the agent uses, whatever the crypto policy
- The log line of each upload and registration names the TLS version,
  cipher and key exchange group
- drra selftest [URL]: the build, OpenSSL, libcurl and FIPS mode, and the
  TLS version, cipher and key exchange group of a test connection
- The RPM build fails unless each binary uses the OpenSSL it must
  (tools/check_openssl.sh, make check-openssl)

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
