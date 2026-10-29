# DataReel Reporting Agent for Linux
# Built by tools/build_rpms.sh from the source tarball
# linux_reporting_agent-%{agent_version}.tar.gz

%global agent_version 1.0-beta1

Name:           linux_reporting_agent
Version:        1.0
Release:        0.beta2%{?dist}
Summary:        DataReel Reporting Agent for Linux: host reports and vulnerability scans for DRSM
License:        GPL-3.0-or-later
URL:            https://datareel.com/
Source0:        %{name}-%{agent_version}.tar.gz

BuildRequires:  gcc-c++ make pkgconf-pkg-config
BuildRequires:  openssl-devel libcurl-devel libxml2-devel bzip2-devel zlib-devel
BuildRequires:  systemd-rpm-macros
Requires:       openssl-libs libcurl libxml2 bzip2-libs zlib
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

%build
make %{?_smp_mflags} CXXFLAGS="%{optflags}" LDFLAGS="%{build_ldflags}"

%install
make install DESTDIR=%{buildroot} UNITDIR=%{_unitdir}
install -d -m 0755 %{buildroot}%{_docdir}/%{name}
install -m 0644 README.md LICENSE %{buildroot}%{_docdir}/%{name}/
cp -a php drsm %{buildroot}%{_docdir}/%{name}/

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
%{_docdir}/%{name}

%changelog
* Thu Oct 29 2026 DataReel Software Development - 1.0-0.beta2
- Report hooks: scripts in /etc/drra/report.d run with each report and
  their output goes in a HOOKS section for DRSM ([hooks] in drra.ini)

* Thu Oct 29 2026 DataReel Software Development - 1.0-0.beta1
- First beta: C++ agent, signed HTTPS uploads, CIFS and SCP delivery,
  OpenSCAP OVAL, CSAF/VEX (RHEL 10) and dnf vulnerability scans,
  compliance scans, DRSM plugins
