# DataReel Reporting Agent for Linux

A small C++ service for RHEL 8, 9 and 10 (and other dnf based systems)
that sends a report about its host every 15 minutes to a report server.
DataReel System Monitor (DRSM) reads the reports and shows them on its
dashboard, with alerts and trends. The host makes only outgoing HTTPS
connections, so it can be monitored over the internet from behind NAT
or a firewall, with no SSH access from the monitor.

It is the Linux counterpart of the DataReel Reporting Agent for Windows
and uses the same signed upload protocol. Hosts that DRSM can reach over
SSH can still be monitored without an agent (DRSM's clientless BASH
plugins); the agent is for hosts it cannot reach.

## What a report holds

| Section | Contents |
| --- | --- |
| SYSTEM | Release, kernel, vendor, model, serial number, virtualization, time zone |
| IP ADDRESS | IPv4 and IPv6 addresses of the interfaces that are up |
| PERFORMANCE | CPU use (5 second sample), iowait, steal, load, memory, swap, processes, uptime |
| DISK USAGE | Size, use and inode use of every local file system |
| NETWORK | Traffic, errors and drops of each interface |
| USERS, ACCOUNTS | Logged in sessions, accounts with a login shell |
| SECURITY | SELinux, firewalld or nftables, auditd, FIPS, sshd root and password login, automatic updates |
| FAILED SERVICES | Failed systemd units |
| UPDATES | Pending package updates, last package install, restart needed for a new kernel |
| VULNERABILITIES | Security advisories that apply, with severity, CVEs and fixed packages |
| COMPLIANCE | SCAP Security Guide profile score and failed rules (optional) |
| INSTALLED PACKAGES | Every package with version and install time |

## Vulnerability scans

Once a day the agent lists the Red Hat security advisories (RHSA) that
the installed packages still need:

* **RHEL 8 and 9:** OpenSCAP, `oscap oval eval` against Red Hat's OVAL
  feed (security.access.redhat.com/data/oval/v2). The feed is
  downloaded only when it changes. The OpenSCAP HTML report goes to the
  server too.
* **RHEL 10:** Red Hat publishes no OVAL feed for RHEL 10, only CSAF/VEX
  files (one JSON file per CVE, 400 MB in all). `php/vex_sync.php` runs
  daily on the report server and builds a small index of the RHEL 10
  packages each CVE is fixed in, and of the packages Red Hat lists as
  affected with no fix yet. Agents download the index from
  `vex_index.php` when it changes and compare it with their packages
  using rpm's version rules. This also reports the CVEs that have no
  update yet, which `dnf updateinfo` cannot. An agent with no report
  server, or that cannot read the index, uses `dnf updateinfo` (the
  same Red Hat errata, plus EPEL).

`[scan] source=oval` with `oval_feed_url` forces OpenSCAP with any feed,
for example a local copy on a host with no internet access. A
compliance scan runs too when `[scan] compliance_profile` is set, for
example `cis_server_l1` or `stig` (needs `scap-security-guide`).

## Install

```
# dnf install ./linux_reporting_agent-1.0-0.beta1.el9.x86_64.rpm
# dnf install openscap-scanner          # RHEL 8 and 9 scans
# vi /etc/drra/drra.ini                 # [https] host, enrollment_token
# drra report | less                    # look at a report, nothing is sent
# drra fingerprint                      # key fingerprint for admin.php
# systemctl enable --now drra
# tail /var/log/drra/drra.log
```

Commands: `drra run` (the service), `once`, `report`, `scan`,
`register`, `fingerprint`, `config`, `version`. `systemctl reload drra`
sends a report now. Settings are read again before every report.

## Report server

The PHP pages in `php/` receive the uploads:

```
$ php/install_server.sh /var/www/html/linux /var/lib/linux_reporting_agent            # dry run
$ php/install_server.sh --apply --admin-user admin /var/www/html/linux /var/lib/linux_reporting_agent
```

* `register.php` registers an agent's certificate. With the
  `enrollment_token` from `server.ini` an agent is approved
  automatically, otherwise an admin approves it on `admin.php` after
  checking the key fingerprint (`drra fingerprint`).
* `upload.php` accepts a report only when it is signed with the key of
  an approved agent (RSA 3072, SHA-256, with a time stamp and a one time
  nonce), and saves it as `<host>_linux_report_agent.txt`, plus the
  OpenSCAP HTML reports, in `reports_dir`.
* `admin.php` approves, revokes and deletes agents. It can use the DRSM
  dashboard login (`--drsm-login`).
* `vex_sync.php` (cron, not a web page) builds the RHEL 10 CSAF/VEX
  index that `vex_index.php` serves. The first run downloads Red Hat's
  full VEX archive (about 400 MB, needs `zstd`); later runs fetch only
  the CVE files that changed.

The agent can also copy the report to a CIFS share (`smbclient`) or an
SCP server (`[delivery] methods=https,scp`).

## DRSM

`drsm/` holds the DRSM side. `drsm/install.sh` (dry run, then
`--apply`) copies it into a DRSM installation:

* `collectors/lra.sh`: hosts with `COLLECTOR=lra` are checked from
  their last report; DRSM never connects to them.
* `plugins/linux/`: `checkin` (report age, agent version, host facts),
  `resources` (CPU, load, memory, swap, disks, network, with the same
  metrics as the SSH plugins, so trends work), `updates`, `security`
  and `vulnerabilities` (an error for critical advisories, a warning
  for important ones, critical CVEs with no fix yet, an old or failed
  scan, a low compliance score).
* `utils/lra_hosts.sh`: makes a host file for every agent report.
* `www/php/vulnerabilities.php`: the Vulnerabilities page, with every
  host's advisory counts, the advisories that affect the most hosts and
  each host's advisories, fixed packages, CVEs and compliance results.
  `scap_report.php` shows the OpenSCAP HTML report, sandboxed.

Set `LRA_REPORTS_DIR` (the server's `reports_dir`) in
`etc/hosts/_defaults.conf`, and in the dashboard's `config/drsm.php`:

```
$NAVextra[] = array("label" => "Vulnerabilities", "url" => "{$WWWvpath}/php/vulnerabilities.php", "icon" => "lock");
$LRAreportsDir = "/var/www/html/linux/reports";   // only where the uploads land
```

## Build

```
# dnf install gcc-c++ make openssl-devel libcurl-devel libxml2-devel bzip2-devel zlib-devel
$ make
$ tools/build_rpms.sh          # RHEL 8, 9 and 10 RPMs in UBI containers (podman)
$ tests/drsm_test.sh           # DRSM plugins and pages against a DRSM checkout
```

## License

GNU General Public License version 3, see LICENSE.
