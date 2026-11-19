# DataReel Reporting Agent for Linux: AI-assisted install, build, upgrade and support

This file is for AI-assisted work on the DataReel Reporting Agent for
Linux (`drra`, package `linux_reporting_agent`): the `drra` systemd
service and its commands, the PHP report server pages (`register.php`,
`upload.php`, `hook.php`, `admin.php`, `vex_index.php`, `vex_sync.php`),
the DataReel System Monitor (DRSM) collector and plugins in `drsm/`, and
the utils in `utils/`. It tells an AI agent (Gemini CLI, Claude Code,
GitHub Copilot, Codex and others) how to assist a site's own
administrators and developers to set up the report server, install the
agent on RHEL 8, 9 and 10 hosts, approve them, upgrade older releases to
the current release, 1.1.3, build it from source, maintain a fork, and
troubleshoot. The agent assists; it does not replace the administrators
or DataReel support, and it never acts autonomously (section 0). The
people review and approve every step, and problems the agent cannot
solve go to DataReel (section 9.4). `GEMINI.md` and `CLAUDE.md` in this
folder only import this file.

The full documentation is `README.md` and the HTML pages in `docs/`
(install, report server, approving hosts, configuration, reports and
DRSM, vulnerability scans, hooks, security, building, troubleshooting,
what's new), also at https://datareel.com/linux_reporting_agent/. The
security design is described at
https://datareel.com/linux_reporting_agent/security_design.php
(`docs/security_design.html` in this folder). This file points to them
instead of repeating them. When this file and the README or the code
disagree, the README and the code win: say so to the person you work for.

## Before you use AI assistance

**Review all of your agency's or company's AI usage policies, and get formal
written approval from your management team, in the form of a business use
case and justification, before you use any AI assistance with the
Reporting Agent.** AI desktops and command line tools may be used with this
guide only in strict compliance with those policies and that approval.

- **Use only approved enterprise AI models.** An AI agent working with the
  Reporting Agent may process potentially sensitive data: host names,
  user names, IP addresses, serial numbers, installed packages, pending
  updates, the security advisories and CVEs a host still needs, SELinux,
  firewall and SSH settings, server names, command output and logs. A
  fleet inventory with its missing fixes tells an attacker where to look,
  so treat it as sensitive. Use only your agency's or company's enterprise
  AI models that have built-in safeguards against disclosing information
  and that guarantee your internal information will not be used to train
  public models.
- **Warning: public or free AI tools, open source AI models and self-built
  AI models** may expose your information to public learning models or to
  other parties, depending on how the model is hosted, configured and
  licensed. Use them only after a comprehensive review of what information
  might be exposed and what the potential risks are.
- The entire risk of AI-assisted use rests with the user. DataReel cannot
  be held accountable for actions taken, commands run or other outcomes of
  AI assistance (see https://datareel.com/terms.php).
- **No endorsement.** Any mention of a specific AI tool, model or product
  in this guide, such as Gemini, Gemini CLI, Claude Code or GitHub Copilot,
  is a reference only. It is not an endorsement or a recommendation to use
  that product. Product names are trademarks of their respective owners.

**For the agent:** at the start of a session, ask the person to confirm
that this AI-assisted use is approved under their organization's AI usage
policy and that you are an approved enterprise AI model. If they cannot
confirm it, stop and do not ask for or read any data from their systems.

## 0. Human in the loop: the agent never acts on its own

AI-assisted means the agent assists a person; it never acts
autonomously. Every change to a host, the report server or a
registration is made by a person or explicitly approved by one, one step
at a time.

- **Advisory mode is the default.** The agent explains the next step and
  prints the exact command and the computer it is for (an agent host, the
  report server or the DRSM monitor host). The person runs it and pastes
  back only output that holds no secret (rule 1). Use this mode unless the
  organization allows the agent to run tools.
- **If tool execution is allowed,** each command still needs its own
  explicit approval before it runs. Never use auto-approve modes: no
  Gemini CLI `--yolo` or auto-accept, no Claude Code permission bypass
  (`--dangerously-skip-permissions`, bypass mode), no auto-run in other
  agents. Commands that type or store a secret (rule 1) are run by the
  person, never by the agent.
- **No unattended work:** no scheduled, background, batch or scripted
  runs of changing commands, and no loops over hosts that the person has
  not approved as one listed step. Rolling the RPM out to many hosts
  (Ansible, Satellite, a kickstart, a `for` loop over `ssh`) is the site's
  own deployment process: the agent helps write and check it, and the
  people run the rollout, starting with one test host.
- **Read-only checks first** (section 9.1); they are shown and approved
  the same way.

**Works with strict AI policies.** These files contain no code that runs
by itself: `AGENTS.md`, `GEMINI.md` and `CLAUDE.md` are text. Everything in
this guide works in advisory mode, with no tool execution by the agent.

## 1. Rules for agents (read these first)

The Reporting Agent decides which hosts a report server trusts, and its
reports describe every host in a fleet and the fixes each one is
missing. A wrong step can let a host that is not yours send reports, stop
a fleet from reporting, or expose the inventory. Follow these rules on
every task:

1. **Never see a secret.** Never ask for, read, store or repeat the
   enrollment token, the agent's private key (`/var/lib/drra/agent_key.pem`),
   a CIFS share login (`/etc/drra/cifs_credentials`), an SCP private key
   (`/etc/drra/id_ed25519`), an admin or dashboard password, or the
   contents of `server.ini`, `admin.htpasswd` or the DRSM
   `config/drsm.php`. Ask for the name of a setting and whether it is set,
   never its value. `drra config` prints `enrollment_token=(set)`, never
   the token. The person types secrets themselves: `htpasswd` at its
   prompt, and the token into `drra.ini` or `server.ini` with an editor.
2. **The agent key stays on its host.** Never suggest copying
   `agent_key.pem` to another host, reading it, changing its mode (0600,
   root) or deleting it: a host with a new key has to be approved again
   (`key_mismatch`). A cloned virtual machine image must not carry a key
   (remove `/var/lib/drra/agent_*.pem` in the template, with the person's
   OK).
3. **Show, then the person runs or approves it.** Before any command that
   changes a host, the report server or a registration (`dnf install`,
   `dnf remove`, `systemctl enable`, `start`, `restart` or `stop drra`,
   `dnf install --allowerasing` (a switch between the RHEL 8 packages),
   `drra once`, `drra scan` (it sends a
   report), `drra register`, `drra submit`, `drra send-uploads`, edits to
   `drra.ini`, `server.ini`, `.htaccess`, ACLs or SELinux labels,
   `install_server.sh --apply`, `drsm/install.sh --apply`, `vex_sync.php`
   and its cron line, and Approve, Revoke or Delete registration on
   `admin.php`), print the command or the action and the computer. In
   advisory mode the person runs it; otherwise wait for an explicit yes
   for that one step (section 0).
4. **Check the fingerprint before an approval.** A host is approved on
   `admin.php` only after the person has matched its key fingerprint with
   the output of `drra fingerprint` on that host. Never suggest approving
   a pending host nobody can vouch for, and never suggest deleting a
   registration to clear a `key_mismatch` before the person knows why the
   key changed.
5. **Back up before changing.** Before a change on the report server, the
   person copies `server.ini`, the `agents` folder and the pages folder to
   a dated backup only they can read. Before an upgrade, keep the old RPM
   and `/etc/drra`. Never delete reports, registrations, nonces, hook
   data, the VEX index or `/var/lib/drra`; move aside only with the
   person's OK.
6. **Dry runs first.** `install_server.sh` and `drsm/install.sh` only show
   what they would do until run with `--apply`; `vex_sync.php` has
   `--dry-run`: run them that way first and read the list. Test a new
   release or a new setting on one host, with `drra report` (prints a
   report, sends nothing), `drra scan --no-send` and `drra selftest`.
7. **Stop on any failed check.** If a check fails or the output is not what
   this guide or the README says to expect, stop and report. Do not
   improvise a fix on the report server or across a fleet.
8. **Never weaken a safeguard.** Do not suggest `use_https=0` or
   `verify_peer=0` outside a test server, `require_remote_user = 0`,
   `auto_approve_with_token = 1` without the person's decision, a larger
   `max_clock_skew_seconds` to hide a wrong clock,
   `strict_host_key_checking=accept-new` without the person's decision, a
   `tls_groups` list without the hybrid group on a build that has it, the
   `linux_reporting_agent-openssl35` package on a host in FIPS mode,
   turning FIPS
   mode or SELinux off, loosening the systemd unit's protections, putting
   `DATA_DIR` in the web root without its `Require all denied`, removing
   the `.htaccess` login, or turning off signature, nonce or timestamp
   checks in the PHP pages. Report instead of working around a check.
9. **FIPS mode is the site's decision.** Never suggest `fips-mode-setup
   --enable` or `--disable`, a reboot, or a crypto policy change
   (`update-crypto-policies`) without the person's decision and their
   security office's approval. On RHEL 8, which package is installed is
   the site's decision too: `linux_reporting_agent` (RHEL 8's FIPS
   OpenSSL 1.1.1) is the one for hosts in FIPS mode, and the
   `-openssl35` package refuses to install there.
10. **No secrets or site data in files you write** (tokens, passwords,
    keys, server names, host names, user names), unless the person asks
    for that file on their own systems. Examples use `reports.example.com`
    and `web-01`.
11. **Reports are site data.** Ask only for the report section or log
    lines a task needs, not whole reports or the reports folder, and leave
    out names when the person asks. Never send reports anywhere outside
    the site.
12. **Keep a log.** List each command, on which computer, and its result
    (exit code and non-secret output), and give it to the person at the
    end.

## 2. What the Reporting Agent is

A C++ systemd service for RHEL 8, 9 and 10 (and rebuilds such as Rocky
Linux and AlmaLinux) that sends a plain text report about its host every
15 minutes to a report server over HTTPS, to a CIFS share or to an SSH
server (SCP). On its first run it makes a 3072-bit RSA key
(`/var/lib/drra/agent_key.pem`, mode 0600) and a self-signed certificate,
registers the certificate with `register.php`, and signs every upload
(RSA PKCS#1 v1.5 with SHA-256 over the host name, a timestamp, a one-time
nonce and the SHA-256 of the report). The report server keeps reports
only from approved hosts. The service only makes outgoing connections;
nothing connects to it. DRSM reads the reports and never connects to an
agent host. Vulnerability scans run by hand (`drra scan`) unless the site
turns on `[scan] enabled=1`. The design is at
https://datareel.com/linux_reporting_agent/security_design.php.

| Item | Where |
| --- | --- |
| Service | `drra.service` (root, hardened unit, restarts on failure but not after exit 78) |
| Program | `/usr/sbin/drra` |
| RHEL 8 packages | `linux_reporting_agent` (RHEL 8's FIPS OpenSSL 1.1.1 and libcurl, crypto policy and FIPS mode apply) or `linux_reporting_agent-openssl35` (OpenSSL 3.5 and libcurl built in, follows the crypto policy, hybrid post-quantum key exchange, not for FIPS mode); one at a time |
| Settings | `/etc/drra/drra.ini` (mode 0600, root), read again before every report |
| Agent data (root only) | `/var/lib/drra`: `agent_key.pem`, `agent_cert.pem`, `registration_status.txt`, the report, scan results, `known_hosts` |
| Log | `/var/log/drra/drra.log`, `journalctl -u drra` |
| Report | `<hostname>_linux_report_agent.txt` (and `<hostname>_linux_scap_report.html` after an OVAL scan) |
| Hooks | `/etc/drra/report.d` (report hooks), `/etc/drra/uploads.d` and `/var/spool/drra/uploads` (hook uploads, group `drra-upload`) |
| Report server | `WEB_DIR/upload/*.php`; `DATA_DIR/server.ini`, `agents/`, `nonces/`, `reports/`, `hooks/`, `vex/`, `admin.htpasswd` |
| DRSM | `lra` collector, `linux/*` plugins and the Vulnerabilities page (`drsm/install.sh` dry run, then `--apply`) |

Read-only checks (they change nothing and need no secret), on the agent
host as root:

```
drra version
drra selftest                       # build, OpenSSL, libcurl, FIPS mode; exit 1 if the OpenSSL is wrong
drra selftest https://reports.example.com/   # also the TLS version, cipher and key exchange group
drra config                         # settings in use; the token shows as (set)
drra fingerprint                    # key fingerprint and registration state
drra report | less                  # a full report on the screen, nothing is sent (site data, rule 11)
drra uploads                        # upload hooks and their state
systemctl status drra
tail -50 /var/log/drra/drra.log
rpm -q linux_reporting_agent linux_reporting_agent-openssl35   # RHEL 8: which package
cat /proc/sys/crypto/fips_enabled   # 1 = FIPS mode
rpm -q linux_reporting_agent
```

`drra scan --no-send` runs the vulnerability scan and prints it without
sending (seconds with CSAF or dnf, minutes and about 800 MB of memory
with OVAL). `drra once` and `drra scan` **send** a report, so they are
changing steps (rule 3).

Exit codes: 0 ok, 1 error (the log line says which), 2 usage, 78 the
RHEL 8 openssl35 package refused to run in FIPS mode (switch to the
`linux_reporting_agent` package, section 5).

On the report server: `ls -l` and `ls -Z` of `DATA_DIR`, the Apache error
log, and `admin.php` (read the list; do not press buttons without the
person, rule 3).

## 3. Repository layout and building (development work)

| Path | Contents |
| --- | --- |
| `src/drra.cpp` | Commands and the service loop |
| `src/common.cpp`, `common.h` | Settings, logging, helpers, `AGENT_VERSION`, build variants |
| `src/collect.cpp` | The report sections |
| `src/scan.cpp` | OpenSCAP OVAL, CSAF/VEX and dnf vulnerability scans, compliance scans |
| `src/agent_auth.cpp` | Key, certificate, signing, registration and uploads (OpenSSL, libcurl) |
| `src/deliver.cpp` | HTTPS, CIFS (`smbclient`) and SCP delivery |
| `src/hooks.cpp`, `uploads.cpp` | Report hooks and hook uploads |
| `src/tlscheck.cpp`, `compat.h` | `drra selftest`, the TLS log line, TLS settings |
| `php/` | Report server pages, `install_server.sh`, `server.ini.example`, `vex_sync.php` |
| `drsm/` | DRSM collector, `linux/*` plugins, Vulnerabilities page, `install.sh` |
| `utils/` | Standalone report programs that send through the agent (`auth_watch`) |
| `rpm/linux_reporting_agent.spec`, `tools/build_rpms.sh` | RPMs for RHEL 8, 9 and 10 in UBI containers (podman) |
| `tools/check_openssl.sh`, `tools/bundled.sha256` | The OpenSSL release check, the pinned OpenSSL and curl tarballs |
| `tools/gen_docs.py` | The `docs/` pages (edit the script, not the pages) |
| `docs/` | HTML documentation; `security_design.html` is made by `docs/make_docs_html.py` from `docs/security_design.php`, the website page |

Build on RHEL 10 or 9: `dnf install gcc-c++ make openssl-devel
libcurl-devel libxml2-devel bzip2-devel zlib-devel`, then `make` and
`make check-openssl` (fails unless the binary and every library it loads
use OpenSSL 3.5 or later). RHEL 8's own OpenSSL is 1.1.1: build the RHEL 8
RPMs with `tools/build_rpms.sh 8`, which builds `linux_reporting_agent`
on the system libraries and `linux_reporting_agent-openssl35` (rpmbuild
`--define "openssl35 1"`) with OpenSSL 3.5.9 and libcurl built in. Never suggest EPEL's `openssl3` packages for a release build
(not Red Hat, no FIPS provider).

`tools/build_rpms.sh [8] [9] [10]` builds from `git archive HEAD` (commit
first), runs `tools/check_openssl.sh` on each binary in the RPM `%check`,
and scans every RPM and tarball against the release blocklist
(`DRRA_RELEASE_BLOCKLIST`, kept outside the repository).

Build in a copy of the source (for example from `git archive`), not in
the clone you commit from, and stage files by name: never commit `drra`,
`.o` files or `output/`.

Tests: `tests/uploads_test.sh` (register, signed uploads and hook uploads
against `php -S`), `tests/drsm_test.sh` (DRSM plugins and pages against a
DRSM checkout), `tests/rpm_install_test.sh <el8 rpm> [older el8 rpm]`
(RHEL 8 build choice, upgrade and removal in UBI 8 containers). Test on a
test host or container, never on a production host. Check PHP changes
with `php -l` on every page.

Every release bumps `AGENT_VERSION` in `src/common.h`, `Version` and
`agent_version` in the spec with a `%changelog` entry, `VERSION` and the
changelog in `tools/gen_docs.py` (then `python3 tools/gen_docs.py docs`),
and the versions in this file and `README.md`.

## 4. Setting up the report server

README "Report server" and `docs/server.html`.

1. Apache with PHP 7.4 or later and the OpenSSL extension, and HTTPS with
   a certificate the agent hosts trust (or a private CA, `ca_file` in
   `drra.ini`). For hybrid post-quantum key exchange the web server's TLS
   library must offer X25519MLKEM768 (OpenSSL 3.5 or later); otherwise
   connections use classical key exchange (security design, section 12).
2. `php/install_server.sh WEB_DIR DATA_DIR` (dry run, read the list), then
   with the person's OK `--apply` (add `--admin-user NAME`, or
   `--drsm-login <dashboard>/config/drsm.php` under a DRSM dashboard).
   It never overwrites an existing `server.ini` or `admin.htpasswd`. Keep
   `DATA_DIR` outside the web root when the host allows it.
3. The person gives the web server user write access to `DATA_DIR`
   (`setfacl`, and `semanage fcontext ... httpd_sys_rw_content_t` plus
   `restorecon` with SELinux) and sets the admin password with `htpasswd
   -B` at its prompt.
4. The person decides the approval policy: admin approval only (no token),
   or an `enrollment_token` with `auto_approve_with_token`. The token is a
   shared secret (rule 1); with auto-approval on, anyone who has it can
   register a host under an unused name.
5. RHEL 10 scans: `vex_sync.php` builds the CSAF/VEX index (first run
   about 400 MB, needs `zstd`); its daily cron line is the person's step.
6. Check: `https://<server>/<path>/upload/admin.php` asks for the login,
   and `register.php` answers a browser GET with `STATUS: error`.

## 5. Installing the agent

README "Install" and `docs/install.html`.

1. Download the RPM for the host's release and its `.sha256sum` from
   https://datareel.com/downloads/linux_reporting_agent/ and check it:
   `sha256sum -c <rpm>.sha256sum`. Stop if it does not match.
2. **RHEL 8 has two packages; the person picks one** (rule 9):
   `linux_reporting_agent-<version>.el8` (RHEL 8's FIPS OpenSSL 1.1.1: the
   one for hosts in FIPS mode, `/proc/sys/crypto/fips_enabled` = 1, and
   the safe default) or `linux_reporting_agent-openssl35-<version>.el8`
   (OpenSSL 3.5 built in, hybrid post-quantum key exchange, follows the
   crypto policy; it refuses to install in FIPS mode). Switch later with
   `dnf install --allowerasing ./<other package>.rpm`; settings and the
   key are kept. RHEL 9 and 10 have one package.
3. Install on **one test host** first: `dnf install ./<package>.rpm`, and
   `openscap-scanner` for OVAL scans on RHEL 8 and 9. The RPM does not
   start the service.
4. The person sets `[https] host` (and `port`, the paths) and, if the site
   uses one, `enrollment_token` in `/etc/drra/drra.ini`. Then `drra
   selftest https://<server>/` (read-only): `OK`, and the key exchange
   group the server gives.
5. With the person's OK: `systemctl enable --now drra`. Check
   `/var/log/drra/drra.log`: `Registration status from server`, the `TLS:`
   line, and `Upload successful` or pending. Approve the host (rule 4),
   then check that the next report arrives.
6. CIFS and SCP delivery: README and `docs/configuration.html`. The SCP key
   is made by the person (`ssh-keygen -t ed25519 -N ""` into
   `/etc/drra/id_ed25519`, mode 0600) and the server's host key goes into
   `/var/lib/drra/known_hosts`. CIFS and SCP deliveries are not signed:
   share permissions and the SSH account control who can write.
7. Only after the test host works: the site's own rollout (section 0).

## 6. AI-assisted upgrade to 1.1.3

### 6.1 What changes, and what does not

- **Kept by the RPM:** `/etc/drra/drra.ini` (`%config(noreplace)`), the
  agent key, the certificate and the registration state, so an upgraded
  host does not need to be approved again. New settings take their
  defaults.
- **1.1.3, RHEL 8:** `dnf upgrade` of `linux_reporting_agent` keeps
  RHEL 8's OpenSSL 1.1.1 (now checked at build time), the right package
  for FIPS mode. For OpenSSL 3.5 and post-quantum key exchange, upgrade to
  `linux_reporting_agent-openssl35` with `dnf install --allowerasing`
  instead (not in FIPS mode: its `%pre` refuses, and it exits 78 if FIPS
  mode is turned on later). It follows the crypto policy.
- **1.1.3, all:** TLS 1.2 is the oldest TLS version; a server that only
  offers TLS 1.0 or 1.1 now fails. New `[https] tls_groups`. Each upload
  logs a `TLS:` line. RHEL 9 and 10 RPMs need `openssl-libs` 3.5 or later
  (`dnf update openssl-libs` on older minor releases).
- **1.1.1 and 1.1.2:** scans by hand (`drra scan` sends a report); RHEL 10
  CSAF scans use Red Hat's advisory severity.
- **Report server pages:** 1.1.3 needs no change on the server.

### 6.2 Steps (confirm each)

1. **Back up** `/etc/drra` on the test host and keep the old RPM.
2. **One test host:** `dnf upgrade
   ./linux_reporting_agent-1.1.3-1.el<N>.x86_64.rpm`. Check `rpm -q`,
   `drra selftest https://<server>/` (the build, the crypto policy and the
   key exchange group), `drra.log` (`Upload successful`, no new registration, the
   `TLS:` line) and the `VERSION:` line of the next report.
3. **DRSM:** nothing to change for 1.1.3.
4. **Rollout** to the rest of the hosts with the site's deployment tool
   (section 0).

Roll back: `dnf downgrade` to the previous RPM (keep its file); the
settings and the key are kept. From the openssl35 package, `dnf install
--allowerasing` the 1.1.2 RPM.

## 7. Hook uploads, utils and DRSM

README "Report hooks" and "Hook uploads", `docs/hooks.html`,
`utils/README.md` and DRSM's PLUGINS.md.

- Report hooks are root-owned scripts in `/etc/drra/report.d`; their
  output goes into the HOOKS section of every report. A script there runs
  as root (or the `[hooks] user`): adding one is a changing step (rule 3).
- An upload hook is `/etc/drra/uploads.d/<id>.ini`; the report server only
  takes a hook ID with a manifest in `[hooks] manifest_dir`, from a
  registered host, about itself. `drra submit --hook <id> [--now] <file>`
  queues a file (rule 3). Check what the file holds before it is sent.
- Utils such as `auth_watch` report failed logins with user names and
  addresses: site data (rule 11).
- DRSM reads reports from `LRA_REPORTS_DIR`; a host file has
  `COLLECTOR=lra` and the `linux/*` plugins (`utils/lra_hosts.sh` makes
  them).

## 8. Forks and contributions

The Reporting Agent is free software under the GNU General Public License
version 3 (see `LICENSE`).

- Keep the license and copyright notices, and make the changed source
  available under the same license when you distribute a fork.
- Use your own product name, service name, folders and version numbers,
  so a fork is never taken for a DataReel release.
- Keep the signed request formats (`register`, `upload` and `hook`
  strings), the `STATUS:` replies and the report section format unless
  every report server, DRSM plugin and agent changes together.
- Do not remove a server-side check (signature, approval, nonce,
  timestamp, host name pattern, size limits, CSRF token, output escaping),
  the OpenSSL release check, or the systemd unit's protections (rule 8).
- Security issues: report them privately through
  https://datareel.com/contact.php, not in public issue trackers.

## 9. AI-assisted troubleshooting and support

Diagnose read-only first; change nothing until the person agrees on the
cause and the fix (rule 3).

### 9.1 Where to look

| What | Command or file |
| --- | --- |
| Service state | `systemctl status drra`, `journalctl -u drra` |
| Last delivery result | `/var/log/drra/drra.log` |
| Agent version and build | `drra version`, `drra selftest` (build, OpenSSL, FIPS mode, crypto policy), `rpm -q linux_reporting_agent linux_reporting_agent-openssl35` |
| TLS to the server | `drra selftest https://<server>/` (version, cipher, key exchange group) |
| Registration state | `drra fingerprint`, `admin.php` |
| Settings | `drra config` (the token shows as `(set)`) |
| FIPS mode | `cat /proc/sys/crypto/fips_enabled`, `fips-mode-setup --check` |
| Hook uploads | `drra uploads`, the UPLOADS section of the report |
| Vulnerability scan | `drra scan --no-send`, the VULNERABILITIES section |
| Report server | Apache error log, `ls -l`/`ls -Z` of `DATA_DIR`, `STATUS:` text in `drra.log` |
| DRSM | the host's DRSM report for `linux/checkin`, `LRA_REPORTS_DIR` |

### 9.2 Common problems

The full table is `docs/troubleshooting.html`.

- **`pending`:** approve it after the fingerprint check (rule 4), or the
  person sets the enrollment token.
- **`key_mismatch`:** the host was reinstalled, renamed, cloned or its key
  changed. The person finds out why, then deletes the old registration on
  `admin.php` and approves the new key (rule 4).
- **`bad_timestamp`:** fix the clock (chronyd on the host or the
  server's NTP); do not raise `max_clock_skew_seconds` (rule 8).
- **`bad_token`:** the token in `drra.ini` does not match `server.ini`; the
  person compares them without pasting either (rule 1).
- **`bad_signature` or `replay`:** something changed the request on the
  way (a proxy) or sent it twice. Stop and report (9.3) if it repeats.
- **`SSL certificate problem`:** the host does not trust the server's
  certificate: the CA goes into the system trust store or `ca_file`; never
  `verify_peer=0` (rule 8).
- **TLS fails after the upgrade to 1.1.3:** the server offers only TLS 1.0
  or 1.1; the fix is on the server.
- **The service stopped with status 78 (RHEL 8):** the openssl35 package
  on a host in FIPS mode. With the person's OK: `dnf install
  --allowerasing ./linux_reporting_agent-<version>.el8.x86_64.rpm`, then
  `systemctl restart drra`.
- **`NOT applied` in the crypto policy line (openssl35 package):** a
  policy setting OpenSSL 3.5 does not take; report it (9.4), do not edit
  the policy files.
- **`key exchange x25519` instead of `X25519MLKEM768`:** the server does
  not offer the hybrid group, or the build or crypto policy does not
  (security design, section 12). Not an error.
- **`unexpected eof while reading`:** the server or a proxy closed TLS
  without a close_notify. Fix the server or proxy.
- **Server `Could not save the registration` / reports missing:** the web
  server user cannot write `DATA_DIR` (owner, ACL, SELinux label).

### 9.3 Stop and escalate at once

Do not try to fix these yourself. Report to the person straight away, with
the summary in 9.4:

- A pending or `key_mismatch` host nobody can vouch for, a registration
  nobody made, or reports from a host the site does not own.
- Repeated `bad_signature` or `replay` replies, or a report that does not
  match its host.
- A report server whose `DATA_DIR`, `server.ini`, reports or
  `admin.htpasswd` can be read from the web, or an admin page without a
  login.
- An enrollment token, agent key, share login or SCP key that may have
  been seen by someone who should not have it (change it: the person
  does).
- `drra selftest` failing on a host that ran before, or a FIPS mode host
  running the openssl35 package.
- Anything that needs a secret to be shared, or a safeguard to be turned
  off (rules 1 and 8).

### 9.4 Support summary

When a problem is not solved, give the person a summary they can send to
their team or to DataReel (https://datareel.com/contact.php). AI-assisted
support ends here: the people take it from this summary.

1. Agent version, RHEL release, `drra selftest` output (build, OpenSSL,
   FIPS mode), and the delivery methods in use.
2. The `drra.log` lines and the `STATUS:` reply for the failing step, with
   host and server names replaced when the person asks.
3. Report server: PHP and Apache versions, shared hosting or not, the
   login type (`basic` or `drsm`), and the Apache error log lines.
4. DRSM version and the plugin output, if DRSM is involved.
5. What happened, when, what changed before it, and every command already
   tried with its result.

Never include the enrollment token, passwords, keys, `server.ini`,
`admin.htpasswd`, `cifs_credentials` or whole reports in the summary.
Remove host, user and server names when the person asks.

The Reporting Agent is free software, provided as is. Check every command
an agent proposes before it runs; the person who runs it is responsible
for the changes made.

## 10. Report back

End every task with: the hosts and servers touched (names only), each
command and its result (exit code and non-secret output), the backups made
and where, each approval, revoke or delete on `admin.php` and who checked
the fingerprint, every warning and what was decided, and the final
`drra version`, `drra selftest` and `drra.log` result.
