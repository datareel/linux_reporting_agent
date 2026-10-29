# Hand-off: DataReel Reporting Agent for Linux → DRSM

For the DataReel System Monitor (DRSM) project. Written 2026-10-29 by the
Linux Reporting Agent project. It says what exists, where it is, and what
the DRSM project has to do to bring it into DRSM.

## Summary

The DataReel Reporting Agent for Linux (`drra`, 1.0-beta1) is a C++ systemd
service for RHEL 8, 9 and 10. Every 15 minutes it sends a report on its host
to a report server. It sends signed HTTPS POSTs to `register.php` and
`upload.php`, using the same protocol as the Windows agent. The host only
makes outgoing TLS connections, so DRSM can monitor it over the internet,
from behind NAT, without SSH.

DRSM's BASH-over-SSH plugins stay as the **clientless** mode. This agent is
for hosts DRSM cannot reach. On the DRSM side it adds a **push collector**
(`COLLECTOR=lra`), five `linux/*` plugins and a **Vulnerabilities** page.

The DRSM files are written and tested against DRSM `master` 285641f
(version 1.33), but they are **not in the DRSM repo yet**. They live in the
agent repo under `drsm/`, laid out like DRSM's own tree. That's because the
shared DRSM checkout on drworkstation2 was on another thread's branch
(`drcm-cluster-plugin`) and was left alone.

## Where things are

| What | Where |
| --- | --- |
| Agent repo | `~/git/linux_reporting_agent` on drworkstation2, branch `main`. Not pushed yet: the AWS bare repo `git@aws-git:datareel/linux_reporting_agent` is still to be created by dougg. |
| DRSM files | `drsm/` in the agent repo (mirrors DRSM paths) |
| DRSM test | `tests/drsm_test.sh` in the agent repo (installs `drsm/` into a scratch copy of a DRSM checkout and runs it; 33 checks) |
| Report server pages | `php/` in the agent repo (`register.php`, `upload.php`, `admin.php`, `vex_index.php`, `vex_sync.php`, `lra_lib.php`, `lra_auth.php`, `install_server.sh`, `server.ini.example`) |
| Local install (test) | `/var/www/datareel/dashboard/linux/upload` (pages) and `/var/www/datareel/dashboard/linux/data` (server.ini, agents, reports, vex; blocked from the web). Uses the DRSM dashboard login (`login = drsm`). Enrollment token in `~/.lra_dashboard_enrollment_token`. |
| RPMs | `output/` in the agent repo, built by `tools/build_rpms.sh` (UBI 8/9/10 containers) |

## Files to bring into DRSM

Copy these into the DRSM repo at the same paths. Alternatively,
`drsm/install.sh -t <DRSMHOME>` (dry run, then `--apply`) copies them into
an installation.

```
collectors/lra.sh                      push collector: runs linux/* in place on the report
plugins/linux/lra_report.sh            shared report functions (lra_section, lra_kv, lra_value ...)
plugins/linux/checkin/                 report age, agent version, host facts (DETAIL lines)
plugins/linux/resources/               CPU, load, memory, swap, disks, inodes, network
plugins/linux/updates/                 pending updates, days since last update, reboot needed
plugins/linux/security/                SELinux, firewall, auditd, sshd, failed units
plugins/linux/vulnerabilities/         advisories, unfixed CVEs, compliance (VULN lines)
utils/lra_hosts.sh                     host file per agent report (dry run unless --apply)
etc/hosts/linux_agent.conf_example     example host file
www/php/drsm_vulns.php                 VULN line parser and helpers
www/php/vulnerabilities.php            Vulnerabilities page (fleet view and ?n=<host>)
www/php/scap_report.php                serves the OpenSCAP HTML report, CSP sandbox
```

The metrics use the same names as the core and storage plugins
(`cpu_used_pct`, `load_15m`, `mem_available_mb`, `swap_used_mb`,
`disk_used_pct{mount=}`, `nic_rx_bytes{nic=}` ... plus `sample_etime`), so
the trends page works unchanged. There are new metrics too: `vuln_critical`,
`vuln_important`, `vuln_moderate`, `vuln_low`, `vuln_total`, `vuln_cves`,
`vuln_unfixed`, `compliance_score`, `compliance_fail`, `updates_pending`,
`updates_last_days`, `reboot_required`, `failed_units`,
`lra_report_age_seconds`, `user_sessions`.

## What the DRSM project needs to do

1. **Branch:** start a DRSM branch, for example `linux-agent-plugin`, from
   `aws/master`, and copy the files above.
2. **Menu:** in `www/php/default_header.php`, add the Vulnerabilities
   item the same way Clusters is added. `drsm_vulns_present()` in
   `drsm_vulns.php` mirrors `drsm_clusters_present()`, and the page uses
   active key `vulnerabilities` and icon `lock`. Until then, sites use
   `$NAVextra[]`, which is what the agent README tells people.
3. **Load the helper:** require `drsm_vulns.php` from `drsm_lib.php`, next
   to `drsm_clusters.php`. Then the pages can drop their own require.
4. **Config:** document `$LRAreportsDir` in the dashboard config
   (`config/drsm.php` example and `make_web_demo.sh`). It's the report
   server's `reports_dir`, only needed where the uploads land, and only for
   the OpenSCAP HTML links. The hosted HostGator dashboard gets just the
   DRSM reports through `drsm_web_sync.sh`, so the VULN data shows there
   but the HTML link doesn't.
5. **Docs:** add the five `linux/*` plugins to the table in `PLUGINS.md`,
   and write a "Linux agent hosts" section like "Windows hosts". Also
   update the `docs/` pages (`plugins.html`, `dashboard.html`), regenerate
   `llms*.txt`, add a CHANGELOG entry under Unreleased, and update
   AGENTS.md (the `lra` collector, the `linux/*` plugins, the VULN line
   format below).
6. **Tests:** port `tests/drsm_test.sh` from the agent repo into DRSM
   `tests/` (as `lra_test.sh`, or as cases in `drsm_run_test.sh` and
   `www_test.sh`). It needs `tests/fixtures/web1_linux_report_agent.txt`
   from the agent repo. Then run every `tests/*.sh`.
7. **Path rule check:** `scap_report.php` takes `?n=<host>&kind=scap|compliance`.
   The host goes through `drsm_valid_host()` and the file name is built
   from fixed parts in `$LRAreportsDir`, so no request path is used.
   Re-check this against AGENTS.md's "pages never read a path taken from
   the request" rule.
8. **Live deploy (only with dougg's go):**
   - Copy into `~/drsm` and the local dashboard.
   - Set `LRA_REPORTS_DIR=/var/www/datareel/dashboard/linux/data/reports`
     in `~/drsm/etc/hosts/_defaults.conf`. The user running DRSM needs read
     access; the reports are mode 0644 under an ACL'd directory.
   - Add `$LRAreportsDir` and the menu item to the local
     `config/drsm.php`.
   - Run `utils/lra_hosts.sh` once agents report.
   - The HostGator copy of the pages is a separate, staged step that dougg
     uploads.
9. **Version:** this is new beta functionality, so record it the DRSM way
   (see the drsm-release memory) when it's merged.

## Report and line formats (contract)

The agent report is `<host>_linux_report_agent.txt`. It has `KEY: value`
headers (`VERSION`, `PLATFORM: linux`, `HOSTNAME`, `ETIME`, `DATETIME`),
then `NAME:` … `END NAME` sections of `name=value` lines. Values with
spaces are quoted with `\"` and `\\` escapes. The sections are SYSTEM,
IP ADDRESS, PERFORMANCE, DISK USAGE, NETWORK, USERS, ACCOUNTS, SECURITY,
FAILED SERVICES, UPDATES, VULNERABILITIES, COMPLIANCE (optional) and
INSTALLED PACKAGES. The OpenSCAP HTML reports are
`<host>_linux_scap_report.html` and `<host>_linux_compliance_report.html`.

`linux/vulnerabilities` prints these lines for the page:

```
VULN summary|source|scan_etime|critical|important|moderate|low|unknown|total|cves|status|unfixed
VULN advisory|id|severity|issued|cves|packages|title
VULN unfixed|cve|severity|packages|state
VULN compliance|profile|score|pass|fail|scan_etime
VULN rule|rule|severity
```

`source` is one of:

- `oval`: OpenSCAP against Red Hat's OVAL feed, used on RHEL 8 and 9.
- `csaf`: the report server's index of Red Hat CSAF/VEX, plus dnf errata
  newer than VEX. Used on RHEL 10, which has no OVAL feed.
- `dnf`: dnf updateinfo, the fallback.

`status` is `ok`, `failed`, `pending` or `disabled`. `unfixed` is empty
when the source cannot tell.

States:

- **ERROR:** an advisory at or above `CRIT_SEVERITY` (Critical).
- **WARNING:** an advisory at or above `WARN_SEVERITY` (Important), an
  unfixed CVE at or above `UNFIXED_WARN_SEVERITY` (Critical), a scan
  older than `SCAN_MAX_AGE_DAYS` (3), a failed scan, or a compliance
  score below `COMPLIANCE_MIN_SCORE`.

## CSAF/VEX for RHEL 10 (server job)

`php/vex_sync.php` runs from cron on the report server (CLI only, and
blocked from the web by `.htaccess`). It builds `data/vex/vex_rhel10.tsv.gz`,
about 2 MB, from https://security.access.redhat.com/data/csaf/v2/vex/.

- The first run streams the 400 MB archive (needs `zstd`), about 35 minutes.
- Daily runs fetch only the files `changes.csv` lists, about 20 seconds.
- `vex_index.php?rhel=10` serves the index with If-Modified-Since.

A cron entry for the local install is **not set up yet**; it's for dougg
to add, for example `/etc/cron.d`:

```
30 5 * * * datareel LRA_SERVER_INI=/var/www/datareel/dashboard/linux/data/server.ini php /var/www/datareel/dashboard/linux/upload/vex_sync.php --releases 10
```

The local data dir already has an index built 2026-10-29.

## Tested

- **drworkstation2 (RHEL 10.2):**
  - A report builds in 20 s.
  - The CSAF + dnf scan finds 54 advisories (1 critical) and 7,031
    unfixed CVEs (1 critical, 331 important).
- **RHEL 8 and 9 containers:** the OpenSCAP OVAL scan works. RHEL 9 found
  a deliberately downgraded openssl.
- **RHEL 9 container under systemd:** the RPM's service ran with the
  hardened unit and uploaded its report and HTML.
- **TLS:** the agent refuses a self-signed server certificate without
  `ca_file`, and does a full chain and host name check with a test CA.
  RHEL 10 (CSAF index), 9 and 8 (OpenSCAP plus HTML) containers then
  registered and uploaded over TLS to the local dashboard pages. The test
  hosts `lra-test-rhel8/9/10` are in
  `/var/www/datareel/dashboard/linux/data/{agents,reports}`; delete them
  on `admin.php` when they are no longer needed.
- **DRSM:** `tests/drsm_test.sh` passes against DRSM master 285641f. It
  covers collector, plugins, `lra_hosts.sh`, Vulnerabilities page fleet,
  severity filter and host views, and the HTML viewer, including a bad
  host name.

## Open questions (dougg)

- Link DataReel 7, or keep plain C++ with system libraries (current)?
- Compliance scan off by default (current)?
- License: GPLv3 like DRSM (current).
