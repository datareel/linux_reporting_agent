# DataReel Reporting Agent for Linux
# Built by tools/build_rpms.sh from the source tarball
# linux_reporting_agent-%{agent_version}.tar.gz

%global agent_version 1.1.3
# RHEL 8: the system OpenSSL is 1.1.1k and libcurl uses it, so the agent
# links EPEL's openssl3 (3.5) and a static libcurl built against it.
# tools/build_rpms.sh puts the curl tarball (checked against tools/curl.sha256)
# next to the agent tarball.
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
%endif

BuildRequires:  gcc-c++ make pkgconf-pkg-config binutils
BuildRequires:  libxml2-devel bzip2-devel zlib-devel
BuildRequires:  systemd-rpm-macros
%if 0%{?rhel} == 8
# openssl3 is in EPEL 8; openssl-devel (1.1.1) must not be in the buildroot
BuildRequires:  openssl3-devel >= %{min_openssl}
BuildConflicts: openssl-devel < 1:3
Requires:       openssl3-libs%{?_isa} >= %{min_openssl}
Provides:       bundled(curl) = %{curl_version}
%else
BuildRequires:  openssl-devel >= 1:%{min_openssl} libcurl-devel
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
%setup -q -T -D -a 1 -n %{name}-%{agent_version}
%endif

%build
%if 0%{?rhel} == 8
# Static libcurl with only HTTP and HTTPS, on openssl3, CA bundle of the system
CURL_PREFIX=$PWD/curl-static
pushd curl-%{curl_version}
./configure --prefix=$CURL_PREFIX --disable-shared --enable-static --with-pic \
  CPPFLAGS="$(pkg-config --cflags openssl3)" LDFLAGS="$(pkg-config --libs-only-L openssl3)" \
  --with-openssl --with-zlib --with-ca-bundle=/etc/pki/tls/certs/ca-bundle.crt --without-ca-path \
  --disable-ftp --disable-file --disable-ldap --disable-ldaps --disable-rtsp --disable-dict \
  --disable-telnet --disable-tftp --disable-pop3 --disable-imap --disable-smtp --disable-gopher \
  --disable-mqtt --disable-websockets --disable-ntlm --disable-manual --disable-docs \
  --without-libpsl --without-brotli --without-zstd --without-nghttp2 --without-nghttp3 \
  --without-libidn2 --without-libssh2 --without-libssh --without-gssapi --without-libgsasl
make %{?_smp_mflags}
make install
popd
make %{?_smp_mflags} CXXFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}" \
  SSL_CFLAGS="$(pkg-config --cflags openssl3)" SSL_LIBS="$(pkg-config --libs openssl3)" \
  CURL_CFLAGS="-I$CURL_PREFIX/include" CURL_LIBS="$CURL_PREFIX/lib/libcurl.a -lz -lpthread"
%else
make %{?_smp_mflags} CXXFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}"
%endif

%check
# No RPM linked to an OpenSSL older than %{min_openssl}
tools/check_openssl.sh ./drra %{min_openssl}

%install
make install DESTDIR=%{buildroot} UNITDIR=%{_unitdir}
install -d -m 0755 %{buildroot}%{_docdir}/%{name}
install -m 0644 README.md LICENSE %{buildroot}%{_docdir}/%{name}/
cp -a php drsm %{buildroot}%{_docdir}/%{name}/

%pre
# Members of drra-upload may queue reports from other tools (drra submit)
getent group drra-upload >/dev/null || groupadd -r drra-upload
exit 0

%post
%systemd_post drra.service

%preun
%systemd_preun drra.service

%postun
%systemd_postun_with_restart drra.service

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
%{_docdir}/%{name}

%changelog
* Wed Nov 18 2026 DataReel Software Development - 1.1.3-1
- OpenSSL 3.5 or later on every release: the RHEL 8 RPM links EPEL's
  openssl3 (3.5) and a static libcurl %{curl_version} built against it
  instead of RHEL 8's OpenSSL 1.1.1k; RHEL 9 and 10 RPMs require
  openssl-libs 3.5 or later
- TLS 1.2 is the oldest TLS version the agent uses, whatever the crypto policy
- drra selftest [URL]: the OpenSSL and libcurl in use, and the TLS version,
  cipher and key exchange group of a test connection
- The RPM build fails unless drra and every library it loads use OpenSSL
  3.5 or later (tools/check_openssl.sh, make check-openssl)

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
