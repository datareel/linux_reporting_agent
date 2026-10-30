#!/usr/bin/env python3
# Generate the HTML documentation in docs/ (same style as the DRSM docs and the Windows agent docs).
# Edit the page content here, then run: python3 tools/gen_docs.py docs
import os, sys

OUT = sys.argv[1]
DL = "https://datareel.com/downloads/linux_reporting_agent/"
DEMO = ""
VERSION = "1.0 beta 2"

ICON_MENU = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"/></svg>'
ICON_DEMO = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="13" rx="2"/><path d="M8 21h8M12 17v4"/></svg>'
ICON_DL = '<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12M7 10l5 5 5-5M5 21h14"/></svg>'
ICON_THEME = '<svg class="icon sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg><svg class="icon moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'

NAV = [
    ("Get started", [("index.html", "Overview"), ("install.html", "Install the agent"), ("server.html", "Set up the report server")]),
    ("Using the agent", [("approve.html", "Approve hosts"), ("configuration.html", "Configuration"), ("reports.html", "Reports and DRSM"),
                         ("vulnerabilities.html", "Vulnerability scans"), ("hooks.html", "Hooks")]),
    ("Reference", [("security.html", "Security"), ("building.html", "Build from source"), ("troubleshooting.html", "Troubleshooting"), ("changelog.html", "What's new")]),
]
ORDER = [f for _, items in NAV for f, _ in items]
LABELS = {f: l for _, items in NAV for f, l in items}

def code(lines):
    """lines: list of (kind, text) kind in '', '#', '$', 'c'"""
    out = []
    for kind, text in lines:
        t = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        if kind == "#":
            out.append('<span class="r"># </span>' + t)
        elif kind == "$":
            out.append('<span class="p">$ </span>' + t)
        elif kind == "c":
            out.append('<span class="c">' + t + '</span>')
        else:
            out.append(t)
    return "<pre><code>" + "\n".join(out) + "</code></pre>"

def table(head, rows):
    h = "".join("<th>%s</th>" % c for c in head)
    b = "".join("<tr>" + "".join("<td>%s</td>" % c for c in r) + "</tr>" for r in rows)
    return '<div class="table-wrap"><table><thead><tr>%s</tr></thead><tbody>%s</tbody></table></div>' % (h, b)

def page(fname, title, desc, toc, body):
    side = []
    for group, items in NAV:
        side.append("<h4>%s</h4>" % group)
        for f, label in items:
            if f == fname:
                side.append('<a href="%s" class="active" aria-current="page">%s</a>' % (f, label))
                if toc:
                    side.append('<div class="toc">' + "".join('<a href="#%s">%s</a>' % t for t in toc) + "</div>")
            else:
                side.append('<a href="%s">%s</a>' % (f, label))
    side.append("<h4>Links</h4>")
    if DEMO:
        side.append('<a href="%s">Live demo</a>' % DEMO)
    side.append('<a href="%s">Downloads</a><a href="https://datareel.com/contact.php">Report an issue</a>' % DL)

    i = ORDER.index(fname)
    pager = []
    if i > 0:
        pager.append('<a class="card prev" href="%s"><small>Previous</small>%s</a>' % (ORDER[i - 1], LABELS[ORDER[i - 1]]))
    if i < len(ORDER) - 1:
        pager.append('<a class="card next" href="%s"><small>Next</small>%s</a>' % (ORDER[i + 1], LABELS[ORDER[i + 1]]))

    demo_btn = ('<a class="tool primary" href="%s">%s<span>Live demo</span></a>' % (DEMO, ICON_DEMO)) if DEMO else ""
    full_title = "DataReel Reporting Agent for Linux Documentation" if fname == "index.html" else "%s | DataReel Reporting Agent for Linux Documentation" % title
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%(full_title)s</title>
<meta name="description" content="%(desc)s">
<link rel="icon" href="images/logo.svg" type="image/svg+xml">
<link rel="stylesheet" href="docs.css">
<script src="docs.js"></script>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
  <div class="topbar-inner">
    <button class="tool icon-only menu-btn" type="button" data-action="menu" aria-label="Menu" aria-expanded="false">%(menu)s</button>
    <a class="brand" href="index.html"><img src="images/logo.svg" alt="">DataReel Reporting Agent for Linux <small>Documentation</small></a>
    <span class="spacer"></span>
    %(demo)s
    <a class="tool hide-sm" href="%(dl)s">%(dlicon)s<span>Downloads</span></a>
    <button class="tool icon-only" type="button" data-action="theme" aria-label="Switch light or dark theme">%(theme)s</button>
  </div>
</header>
<div class="layout">
  <nav class="sidebar" aria-label="Documentation">
    %(side)s
  </nav>
  <main class="content" id="main">
%(body)s
<nav class="pager" aria-label="Previous and next page">%(pager)s</nav>
  </main>
</div>
<footer class="foot">DataReel Reporting Agent for Linux %(version)s &middot; GNU General Public License v3 &middot; <a href="https://datareel.com/info_linux_reporting_agent.php">datareel.com</a></footer>
</body>
</html>
""" % dict(full_title=full_title, desc=desc, menu=ICON_MENU, demo=demo_btn, dl=DL, dlicon=ICON_DL,
           theme=ICON_THEME, version=VERSION, side="".join(side), body=body.strip(), pager="".join(pager))
    with open(os.path.join(OUT, fname), "w") as f:
        f.write(html)

DIAGRAM = """<svg class="diagram" viewBox="0 0 860 330" role="img" aria-labelledby="dg-t">
<title id="dg-t">How the DataReel Reporting Agent for Linux works: each Linux host runs the drra service, which registers its certificate and uploads signed reports over HTTPS to the PHP pages on a report server, or copies them to a file share or SSH server. DRSM reads the reports and shows the hosts, their alerts, trends and vulnerabilities on its dashboard.</title>
<defs>
  <marker id="a1" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="ah" d="M0 0L10 5L0 10z"/></marker>
  <marker id="a2" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="ah hi" d="M0 0L10 5L0 10z"/></marker>
  <marker id="a3" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="ah alt" d="M0 0L10 5L0 10z"/></marker>
</defs>
<rect class="box hi" x="20" y="20" width="250" height="150" rx="14"/>
<text class="t" x="40" y="50">Linux hosts</text>
<text class="s" x="40" y="70">RHEL 8, 9 and 10, cloud or on site</text>
<text class="m" x="40" y="98">drra.service (systemd)</text>
<text class="s" x="40" y="120">report every 15 minutes</text>
<text class="s" x="40" y="138">RSA key + certificate</text>

<rect class="box" x="370" y="20" width="250" height="150" rx="14"/>
<text class="t" x="390" y="50">Report server</text>
<text class="s" x="390" y="70">Apache + PHP, local or hosted</text>
<text class="m" x="390" y="98">register.php</text>
<text class="m" x="390" y="120">upload.php, hook.php</text>
<text class="m" x="390" y="142">admin.php, vex_index.php</text>

<rect class="box" x="370" y="230" width="250" height="80" rx="14"/>
<text class="t" x="390" y="260">Reports</text>
<text class="s" x="390" y="284">one text file per host + scan HTML</text>

<rect class="box alt" x="690" y="20" width="150" height="150" rx="14"/>
<text class="t" x="708" y="50">Admins</text>
<text class="s" x="708" y="74">approve or</text>
<text class="s" x="708" y="92">revoke hosts</text>

<rect class="box alt" x="690" y="230" width="150" height="80" rx="14"/>
<text class="t" x="708" y="260">DRSM</text>
<text class="s" x="708" y="284">alerts, trends, CVEs</text>

<rect class="box" x="20" y="230" width="250" height="80" rx="14"/>
<text class="t" x="40" y="260">Or a file share / SSH</text>
<text class="s" x="40" y="284">smbclient copy, scp</text>

<path class="ln hi" d="M270 95H368" marker-end="url(#a2)"/>
<text class="lbl" x="319" y="86" text-anchor="middle">signed</text>
<text class="lbl" x="319" y="112" text-anchor="middle">HTTPS</text>
<path class="ln" d="M495 170V228" marker-end="url(#a1)"/>
<path class="ln alt" d="M688 95H622" marker-end="url(#a3)"/>
<path class="ln alt" d="M620 270H688" marker-end="url(#a3)"/>
<path class="ln" d="M145 170V228" marker-end="url(#a1)"/>
</svg>"""

# ---------------------------------------------------------------- index
page("index.html", "Overview",
     "DataReel Reporting Agent for Linux documentation: host reports, updates and vulnerability scans for RHEL 8, 9 and 10, sent over HTTPS to a report server and the DataReel System Monitor.",
     [("what", "What it reports"), ("how", "How it works"), ("who", "Who it is for"), ("start", "Get started"), ("docs", "Other documentation")],
     """
<section class="hero">
  <span class="badge new">New October 2026</span>
  <h1 style="margin-top:14px">DataReel Reporting Agent for Linux</h1>
  <p class="lead">A small C++ service for RHEL 8, 9 and 10 that sends a report about its host every 15 minutes to a report server: system, usage, security settings, updates, the Red Hat security advisories that apply, and the installed packages. The host only makes outgoing HTTPS connections, so the DataReel System Monitor can watch it over the internet, from behind NAT or a firewall, with no SSH access.</p>
  <div class="actions">
    <a class="tool primary" href="install.html">Install the agent</a>
    <a class="tool" href="server.html">Set up the report server</a>
    <a class="tool" href="vulnerabilities.html">Vulnerability scans</a>
    <a class="tool" href="changelog.html">What's new</a>
  </div>
</section>

<h2 id="what">What it reports</h2>
<div class="grid">
  <div class="card"><h3>System</h3><p>Release, kernel, vendor, model, serial number, virtualization, time zone and IP addresses.</p></div>
  <div class="card"><h3>Usage</h3><p>CPU, iowait, steal, load, memory, swap, every local file system (space and inodes) and network traffic, with the same metric names as DRSM's SSH plugins, so the trend graphs work.</p></div>
  <div class="card"><h3>Security settings</h3><p>SELinux, firewalld or nftables, auditd, FIPS, sshd root and password login, automatic updates, logged in users, accounts with a login shell and failed systemd units.</p></div>
  <div class="card"><h3>Updates</h3><p>Pending package updates, the last package install, and whether a restart is needed for a new kernel.</p></div>
  <div class="card"><h3>Vulnerabilities</h3><p>The Red Hat security advisories the host still needs, with severity, CVEs and fixed packages, from OpenSCAP (RHEL 8 and 9) or Red Hat CSAF/VEX data (RHEL 10). Off by default.</p></div>
  <div class="card"><h3>Hooks</h3><p>Site checks in <code>/etc/drra/report.d</code> run with every report, and reports from other tools are sent with the agent's hook uploads.</p></div>
</div>

<h2 id="how">How it works</h2>
<p>The agent is the <code>drra</code> program, run by the <code>drra.service</code> systemd unit. Every 15 minutes (<code>report_interval_minutes</code>) it writes a plain text report and delivers it. On its first run it creates an RSA key and a certificate and registers the certificate with the report server. After an admin approves the host, or it sends the right enrollment token, every report it uploads is signed, and the server only accepts reports that are signed by the host they claim to be from.</p>
""" + DIAGRAM + """
<p>The report can also, or instead, be copied to a Windows file share (with <code>smbclient</code>) or to an SSH server. The reports are plain text files, one per host. The <a href="https://datareel.com/info_drsm.php">DataReel System Monitor</a> (DRSM) checks agent hosts from their last report with its <code>lra</code> collector and <code>linux/*</code> plugins, and shows every host's advisories on its Vulnerabilities page.</p>

<h2 id="who">Who it is for</h2>
<p>DRSM monitors Linux hosts it can reach over SSH without any agent. The agent is for the hosts it cannot reach:</p>
<ul>
  <li>Cloud servers and VPS hosts where you do not want SSH open to the monitor.</li>
  <li>Hosts behind NAT, a firewall or a VPN the monitor is not on.</li>
  <li>Hosts at other sites or customers, reporting to a hosted dashboard on shared hosting.</li>
  <li>Hosts where you want a daily list of the security advisories and CVEs that apply.</li>
</ul>
<p>It is the Linux counterpart of the <a href="https://datareel.com/info_windows_reporting_agent.php">DataReel Reporting Agent for Windows</a> and uses the same signed upload protocol, so one report server and one DRSM dashboard can take both.</p>

<h2 id="start">Get started</h2>
<div class="grid">
  <a class="card" href="server.html"><h3>1. Set up the report server</h3><p>Copy the PHP pages to an Apache and PHP host with <code>install_server.sh</code>. Shared hosting works.</p></a>
  <a class="card" href="install.html"><h3>2. Install the agent</h3><p>Install the RPM for RHEL 8, 9 or 10, set the server in <code>/etc/drra/drra.ini</code> and start the service.</p></a>
  <a class="card" href="approve.html"><h3>3. Approve the hosts</h3><p>Check each host's key fingerprint on the admin page, or use an enrollment token.</p></a>
  <a class="card" href="reports.html"><h3>4. Add the hosts to DRSM</h3><p>Point DRSM at the reports and make a host file for each agent with <code>lra_hosts.sh</code>.</p></a>
</div>

<h2 id="docs">Other documentation</h2>
<ul>
  <li><code>README.md</code> in the source code covers the same ground as plain text, and is installed in <code>/usr/share/doc/linux_reporting_agent</code>.</li>
  <li><code>/etc/drra/drra.ini</code> describes every agent setting, and <code>php/server.ini.example</code> every server setting.</li>
  <li><code>drra help</code> lists the commands.</li>
</ul>
""")

# ---------------------------------------------------------------- install
page("install.html", "Install the agent",
     "Install the DataReel Reporting Agent for Linux RPM on RHEL 8, 9 or 10, set the report server, and start the service.",
     [("needs", "What you need"), ("rpm", "Install the RPM"), ("settings", "Set the server"), ("start", "Start the service"), ("commands", "Commands"), ("files", "Installed files"), ("upgrade", "Upgrade and remove")],
     """
<h1>Install the agent</h1>
<p class="lead">The agent comes as an RPM for RHEL 8, 9 and 10 (and rebuilds such as Rocky Linux, AlmaLinux and Oracle Linux) for x86_64.</p>

<h2 id="needs">What you need</h2>
<ul>
  <li>RHEL 8, 9 or 10, x86_64, with systemd.</li>
  <li>A report server with the PHP pages, see <a href="server.html">Set up the report server</a>, and its enrollment token if you use one.</li>
  <li>Outgoing HTTPS (port 443) to the report server. Nothing needs to connect to the host.</li>
  <li>For vulnerability scans on RHEL 8 and 9: <code>openscap-scanner</code>. For compliance scans: <code>scap-security-guide</code>.</li>
  <li>For CIFS or SCP delivery: <code>samba-client</code> or <code>openssh-clients</code>.</li>
</ul>

<h2 id="rpm">Install the RPM</h2>
<p>Download the RPM for your release from the <a href="https://datareel.com/downloads/linux_reporting_agent/">downloads page</a> (<code>el8</code>, <code>el9</code> or <code>el10</code>) and check it against its <code>.sha256sum</code> file:</p>
""" + code([("$", "wget https://datareel.com/downloads/linux_reporting_agent/linux_reporting_agent-1.0-0.beta2.el9.x86_64.rpm"),
            ("$", "wget https://datareel.com/downloads/linux_reporting_agent/linux_reporting_agent-1.0-0.beta2.el9.x86_64.rpm.sha256sum"),
            ("$", "sha256sum -c linux_reporting_agent-1.0-0.beta2.el9.x86_64.rpm.sha256sum"),
            ("#", "dnf install ./linux_reporting_agent-1.0-0.beta2.el9.x86_64.rpm"),
            ("#", "dnf install openscap-scanner          # RHEL 8 and 9 vulnerability scans")]) + """
<p>The RPM installs the agent, its settings, the systemd unit and a logrotate file, and makes the <code>drra-upload</code> group. It does not start the service: set the server first.</p>

<h2 id="settings">Set the server</h2>
<p>All settings are in <code>/etc/drra/drra.ini</code> (root only, as it can hold the enrollment token). For a report server at <code>reports.example.com</code> with the pages in <code>/linux/upload/</code>:</p>
""" + code([("c", "[delivery]"), ("", "methods=https"), ("", ""),
            ("c", "[https]"), ("", "host=reports.example.com"), ("", "upload_path=/linux/upload/upload.php"),
            ("", "register_path=/linux/upload/register.php"), ("", "enrollment_token=     ; from server.ini, or empty to approve by hand"), ("", ""),
            ("c", "[scan]"), ("", "enabled=1             ; optional, see Vulnerability scans")]) + """
<p>See <a href="configuration.html">Configuration</a> for every setting.</p>

<h2 id="start">Start the service</h2>
""" + code([("#", "drra report | less                    # look at a report, nothing is sent"),
            ("#", "drra fingerprint                      # key fingerprint for the admin page"),
            ("#", "systemctl enable --now drra"),
            ("#", "tail /var/log/drra/drra.log")]) + """
<p>The first cycle registers the host. Without an enrollment token the log says the agent is pending: approve it on the admin page (<a href="approve.html">Approve hosts</a>), and the next report goes through. <code>systemctl reload drra</code> starts the next report now. Settings are read again before every report, so a changed <code>drra.ini</code> needs no restart.</p>

<h2 id="commands">Commands</h2>
""" + table(["Command", "What it does"], [
    ["<code>drra run</code>", "Runs as a service: a report every <code>report_interval_minutes</code> (systemd uses this)"],
    ["<code>drra once</code>", "Writes and sends one report, scanning first when a scan is due"],
    ["<code>drra report</code>", "Prints a report, nothing is sent"],
    ["<code>drra scan</code>", "Runs the vulnerability (and compliance) scan now"],
    ["<code>drra hooks</code>", "Runs the report hooks and prints their HOOKS section"],
    ["<code>drra submit --hook &lt;id&gt; [--now] &lt;file&gt;</code>", "Queues a report from another tool for upload hook &lt;id&gt;; <code>--now</code> asks the service to send it right away"],
    ["<code>drra send-uploads</code>", "Sends the queued upload files now, without a report"],
    ["<code>drra uploads</code>", "Lists the upload hooks and their state"],
    ["<code>drra register</code>", "Registers the agent certificate with the report server"],
    ["<code>drra fingerprint</code>", "Prints the agent key fingerprint to check on the admin page"],
    ["<code>drra config</code>", "Prints the settings in use"],
    ["<code>drra version</code>", "Prints the version"],
]) + """
<p><code>-c &lt;ini file&gt;</code> uses another settings file, for example to test against a development server.</p>

<h2 id="files">Installed files</h2>
""" + table(["Path", "Contents"], [
    ["<code>/usr/sbin/drra</code>", "The agent"],
    ["<code>/etc/drra/drra.ini</code>", "Settings, with comments (mode 0600)"],
    ["<code>/etc/drra/report.d/</code>", "Report hooks, see <a href=\"hooks.html\">Hooks</a>"],
    ["<code>/etc/drra/uploads.d/</code>", "Upload hook files"],
    ["<code>/usr/lib/systemd/system/drra.service</code>", "The systemd unit, hardened (read only <code>/usr</code>, <code>/boot</code> and <code>/etc</code>, private <code>/tmp</code>, no new privileges)"],
    ["<code>/var/lib/drra/</code>", "Agent key and certificate, registration state, last report, scan results and feed cache"],
    ["<code>/var/log/drra/drra.log</code>", "Log of every report and upload (rotated by logrotate)"],
    ["<code>/var/spool/drra/uploads/</code>", "Hook upload spool, writable by the <code>drra-upload</code> group"],
    ["<code>/usr/share/doc/linux_reporting_agent/</code>", "README, license, the report server pages (<code>php/</code>) and the DRSM files (<code>drsm/</code>)"],
]) + """

<h2 id="upgrade">Upgrade and remove</h2>
<p><code>dnf install</code> a newer RPM to upgrade: the service restarts and <code>drra.ini</code>, the key and the registration stay. <code>dnf remove linux_reporting_agent</code> stops and removes the service; <code>/var/lib/drra</code> and <code>/var/log/drra</code> stay until you delete them. Delete the host on the admin page too, or a reinstall with a new key gets <code>key_mismatch</code>.</p>
""")

# ---------------------------------------------------------------- server
page("server.html", "Set up the report server",
     "Install the DataReel Reporting Agent for Linux PHP report server pages: register, upload, hook uploads, admin page and the RHEL 10 CSAF/VEX index.",
     [("needs", "What you need"), ("pages", "The pages"), ("install", "Install"), ("settings", "server.ini"), ("login", "Admin login"), ("vex", "RHEL 10 CSAF/VEX index"), ("shared", "Shared hosting"), ("windows", "With the Windows agent")],
     """
<h1>Set up the report server</h1>
<p class="lead">The report server is a few PHP pages on any Apache and PHP host. It checks each upload's signature and keeps one report per host for DRSM to read.</p>

<h2 id="needs">What you need</h2>
<ul>
  <li>Apache with PHP 7.4 or later and the openssl extension. Shared hosting works.</li>
  <li>An HTTPS certificate the hosts trust (or a private CA, set with <code>ca_file</code> on the agents).</li>
  <li>A data folder the web server can write to, best outside the web root.</li>
  <li>For the RHEL 10 CSAF/VEX index: PHP on the command line, cron, <code>zstd</code> and outgoing HTTPS to security.access.redhat.com.</li>
</ul>

<h2 id="pages">The pages</h2>
""" + table(["Page", "What it does"], [
    ["<code>register.php</code>", "Registers an agent's certificate. With the enrollment token the agent is approved at once, otherwise it waits for an admin."],
    ["<code>upload.php</code>", "Takes a report only when it is signed with the key of an approved agent, and saves it as <code>&lt;host&gt;_linux_report_agent.txt</code>, with the OpenSCAP HTML reports, in <code>reports_dir</code>"],
    ["<code>hook.php</code>", "Takes hook uploads, signed the same way, for hook IDs with a manifest, and keeps them in <code>[hooks] dir</code>"],
    ["<code>admin.php</code>", "Approves, revokes and deletes agents, behind a login"],
    ["<code>vex_index.php</code>", "Serves the RHEL 10 CSAF/VEX index to the agents"],
    ["<code>vex_sync.php</code>", "Builds the CSAF/VEX index (cron, not a web page)"],
    ["<code>lra_lib.php</code>, <code>lra_auth.php</code>, <code>hook_lib.php</code>", "Shared code, blocked from the web"],
]) + """

<h2 id="install">Install</h2>
<p>The pages and <code>install_server.sh</code> are in the source code and in <code>/usr/share/doc/linux_reporting_agent/php</code> on any host with the RPM. The script shows what it would do first; run it again with <code>--apply</code>:</p>
""" + code([("$", "php/install_server.sh /var/www/html/linux /var/lib/linux_reporting_agent"),
            ("$", "sudo php/install_server.sh --apply --admin-user admin /var/www/html/linux /var/lib/linux_reporting_agent")]) + """
<p>It puts the pages in <code>/var/www/html/linux/upload/</code>, writes <code>server.ini</code> in the data folder (never over an existing one), adds the <code>.htaccess</code> files, and with <code>--admin-user</code> makes an <code>admin.htpasswd</code> login. At the end it prints the commands that let the web server user write to the data folder, including the SELinux label <code>httpd_sys_rw_content_t</code>. Point Apache at <code>server.ini</code> with <code>SetEnv LRA_SERVER_INI /var/lib/linux_reporting_agent/server.ini</code> if it is not in <code>/etc/linux_reporting_agent/</code>.</p>

<h2 id="settings">server.ini</h2>
""" + table(["Setting", "Default", "What it does"], [
    ["<code>[paths] reports_dir</code>", "<code>/var/www/html/linux/reports</code>", "Where reports are written, one file per host. DRSM reads it (<code>LRA_REPORTS_DIR</code>)."],
    ["<code>[paths] data_dir</code>", "<code>/var/lib/linux_reporting_agent</code>", "Agent registrations and replay protection data"],
    ["<code>[registration] enrollment_token</code>", "empty", "Shared secret agents send when they register. Empty: an admin approves every agent."],
    ["<code>[registration] auto_approve_with_token</code>", "1", "0 still checks the token, but an admin must approve"],
    ["<code>[upload] max_upload_bytes</code>", "2000000", "Largest report"],
    ["<code>[upload] max_html_bytes</code>", "20000000", "Largest OpenSCAP HTML report"],
    ["<code>[upload] max_clock_skew_seconds</code>", "300", "Largest clock difference between agent and server"],
    ["<code>[admin] require_remote_user</code>", "1", "<code>admin.php</code> only runs behind web server authentication"],
    ["<code>[admin] login</code>", "basic", "<code>basic</code> (web server login) or <code>drsm</code> (DRSM dashboard login)"],
    ["<code>[admin] drsm_config</code>", "empty", "With <code>login = drsm</code>: the dashboard's <code>config/drsm.php</code>"],
    ["<code>[hooks] enabled</code>", "1", "Take hook uploads"],
    ["<code>[hooks] manifest_dir</code>", "empty", "DRSM's <code>plugins/uploads</code> folder; only hook IDs with a manifest are taken"],
    ["<code>[hooks] dir</code>", "<code>&lt;data_dir&gt;/hooks</code>", "Where hook payloads are kept; DRSM reads it (<code>UPLOADS_DIR</code>)"],
    ["<code>[hooks] max_bytes</code>", "20000000", "Largest hook payload"],
]) + """

<h2 id="login">Admin login</h2>
<p>By default <code>admin.php</code> sits behind an Apache Basic login (<code>admin.htpasswd</code>). When the pages are inside the DRSM dashboard's web folder, for example <code>/dashboard/linux/upload/</code>, they can use the dashboard login instead:</p>
""" + code([("$", "sudo php/install_server.sh --apply --drsm-login ../../config/drsm.php /var/www/html/dashboard/linux /var/www/html/dashboard/linux/data")]) + """

<h2 id="vex">RHEL 10 CSAF/VEX index</h2>
<p>Red Hat publishes no OVAL feed for RHEL 10. <code>vex_sync.php</code> builds a small index (about 2 MB) from Red Hat's CSAF/VEX files, and agents fetch it from <code>vex_index.php</code> when it changes. The first run downloads Red Hat's full VEX archive (about 400 MB, needs <code>zstd</code>) and takes a while; later runs fetch only the files that changed, in seconds. Run it daily from cron as a user that can write the data folder:</p>
""" + code([("c", "# /etc/cron.d/lra_vex_sync"),
            ("", "30 5 * * * apache LRA_SERVER_INI=/var/lib/linux_reporting_agent/server.ini php /var/www/html/linux/upload/vex_sync.php --releases 10")]) + """
<p>Only needed when RHEL 10 hosts scan for vulnerabilities. See <a href="vulnerabilities.html">Vulnerability scans</a>.</p>

<h2 id="shared">Shared hosting</h2>
<p>On hosts with only Apache and PHP, such as HostGator, put the data folder inside the web folder: <code>install_server.sh</code> adds a <code>Require all denied</code> <code>.htaccess</code> to it. Copy <code>server.ini</code> next to it and set <code>SetEnv LRA_SERVER_INI</code> in the pages' <code>.htaccess</code>. Build the CSAF/VEX index on another machine if the host has no cron with PHP, and copy it into <code>data/vex/</code>.</p>

<h2 id="windows">With the Windows agent</h2>
<p>The <a href="https://datareel.com/info_windows_reporting_agent.php">Windows agent</a> uses the same protocol with its own pages. Install each in its own folder, for example <code>/dashboard/windows/upload/</code> and <code>/dashboard/linux/upload/</code>, so the Linux and Windows registrations stay apart.</p>
""")

# ---------------------------------------------------------------- approve
page("approve.html", "Approve hosts",
     "Approve, revoke and delete DataReel Reporting Agent for Linux hosts on the admin page.",
     [("states", "Host states"), ("fingerprint", "Check the fingerprint"), ("token", "Enrollment token"), ("reinstall", "Reinstalled hosts")],
     """
<h1>Approve hosts</h1>
<p class="lead">A host registers its certificate on its first run and sends nothing until it is approved, on the admin page or with the enrollment token.</p>

<h2 id="states">Host states</h2>
""" + table(["State", "Meaning"], [
    ["pending", "Registered, waiting for an admin. The agent tries again every cycle."],
    ["approved", "Reports are accepted"],
    ["revoked", "Reports are refused until an admin approves the host again"],
]) + """
<p><code>admin.php</code> lists each host with its state, key fingerprint, registration time and last report, with buttons to approve, revoke and delete it (with CSRF protection).</p>

<h2 id="fingerprint">Check the fingerprint</h2>
<p>Before you approve a pending host, check that the fingerprint on the admin page is the one on the host:</p>
""" + code([("#", "drra fingerprint")]) + """
<p>The fingerprint is also in <code>/var/log/drra/drra.log</code>.</p>

<h2 id="token">Enrollment token</h2>
<p>With <code>enrollment_token</code> set in <code>server.ini</code> and the same value in each agent's <code>drra.ini</code>, hosts are approved as they register. That suits large rollouts with Ansible or a kickstart file. Change the token after a rollout, or empty it, so new hosts need an admin again. Hosts already approved keep reporting.</p>

<h2 id="reinstall">Reinstalled hosts</h2>
<p>A host is registered by its host name, and the certificate's CN must match it. A reinstalled host makes a new key, and the server answers <code>key_mismatch</code> until an admin deletes the old registration. Then the host registers again on its next cycle. Two hosts with the same host name cannot both report.</p>
""")

# ---------------------------------------------------------------- configuration
def setting_rows(rows):
    return table(["Setting", "Default", "What it does"], [["<code>%s</code>" % r[0], r[1], r[2]] for r in rows])

page("configuration.html", "Configuration",
     "Every DataReel Reporting Agent for Linux setting in /etc/drra/drra.ini: delivery, HTTPS, CIFS, SCP, agent, scan, hooks and uploads.",
     [("file", "The settings file"), ("delivery", "[delivery]"), ("https", "[https]"), ("cifs", "[cifs]"), ("scp", "[scp]"), ("agent", "[agent]"), ("scan", "[scan]"), ("hooks", "[hooks] and [uploads]")],
     """
<h1>Configuration</h1>
<p class="lead">Every setting is in <code>/etc/drra/drra.ini</code>. The agent reads it again before every report, so changes need no restart; <code>systemctl reload drra</code> starts the next report now.</p>

<h2 id="file">The settings file</h2>
<p>A setting left out uses its default. <code>drra config</code> prints the settings in use. The file is root only (mode 0600) because it can hold the enrollment token.</p>

<h2 id="delivery">[delivery]</h2>
""" + setting_rows([
    ("methods", "https", "One or more of <code>https</code>, <code>cifs</code>, <code>scp</code>, separated by commas. Every listed method runs each cycle."),
]) + """

<h2 id="https">[https]</h2>
""" + setting_rows([
    ("host", "reports.example.com", "Report server"),
    ("port", "443", "443 for HTTPS, 80 for HTTP"),
    ("upload_path", "/linux/upload/upload.php", "Upload page"),
    ("register_path", "/linux/upload/register.php", "Registration page"),
    ("hook_path", "empty", "Hook upload page; empty uses <code>hook.php</code> next to <code>upload_path</code>"),
    ("enrollment_token", "empty", "The <code>enrollment_token</code> from <code>server.ini</code>; empty to have an admin approve the host"),
    ("use_https", "1", "0 = plain HTTP, only for a test server"),
    ("verify_peer", "1", "Check the server certificate and host name. 0 only for a test server; use <code>ca_file</code> for a private CA."),
    ("ca_file", "empty", "CA bundle (PEM) for a private CA; empty uses the system trust store"),
    ("timeout_seconds", "60", "Seconds before an upload is given up"),
]) + """

<h2 id="cifs">[cifs]</h2>
<p>Copies the report to a Windows (SMB/CIFS) file share with <code>smbclient</code> (package <code>samba-client</code>).</p>
""" + setting_rows([
    ("share", "empty", "Share, for example <code>//fileserver/reports</code>"),
    ("directory", "empty", "Folder inside the share"),
    ("credentials_file", "/etc/drra/cifs_credentials", "Share login in <code>smbclient -A</code> format (<code>username =</code>, <code>password =</code>, <code>domain =</code>), mode 0600; empty for a guest share"),
    ("smbclient_path", "/usr/bin/smbclient", ""),
    ("timeout_seconds", "120", ""),
]) + """

<h2 id="scp">[scp]</h2>
""" + setting_rows([
    ("host, port, user", "empty, 22, empty", "SSH server and account that receive the report"),
    ("key_file", "/etc/drra/id_ed25519", "Private key with no passphrase, mode 0600"),
    ("remote_dir", "empty", "Folder on the server, for example the report server's <code>reports_dir</code>"),
    ("known_hosts_file", "/var/lib/drra/known_hosts", "Host key of the server"),
    ("strict_host_key_checking", "yes", "<code>yes</code> (only a key already in known_hosts) or <code>accept-new</code> (save it on the first connection)"),
    ("scp_path", "/usr/bin/scp", ""),
    ("timeout_seconds", "120", "Seconds before a hung transfer is stopped"),
]) + """

<h2 id="agent">[agent]</h2>
""" + setting_rows([
    ("report_interval_minutes", "15", "Minutes between reports. 15 matches the DRSM check interval."),
    ("cpu_sample_seconds", "5", "Seconds the CPU use is sampled for"),
    ("report_dir", "/var/lib/drra", "Where the report is written before it is sent"),
    ("log_file", "/var/log/drra/drra.log", "Log of every report and upload"),
    ("data_dir", "/var/lib/drra", "Agent key, certificate, registration and scan results"),
    ("check_updates", "1", "List pending package updates (from the dnf metadata cache)"),
    ("updates_refresh_hours", "24", "Hours between <code>dnf makecache</code> runs; 0 leaves it to <code>dnf-makecache.timer</code>"),
    ("command_timeout_seconds", "300", "Seconds before a command the agent runs (rpm, dnf, systemctl) is stopped"),
]) + """

<h2 id="scan">[scan]</h2>
<p>See <a href="vulnerabilities.html">Vulnerability scans</a> for how the sources work.</p>
""" + setting_rows([
    ("enabled", "0", "1 turns the vulnerability scan on"),
    ("interval_hours", "24", "Hours between scans"),
    ("source", "auto", "<code>auto</code>, <code>oval</code>, <code>csaf</code> or <code>dnf</code>"),
    ("oval_feed_url", "empty", "OVAL feed (https URL or local file, .xml or .xml.bz2); empty picks Red Hat's feed for the release"),
    ("csaf_index_url", "empty", "CSAF/VEX index (https URL or local file, <code>{major}</code> is replaced with the release); empty uses <code>vex_index.php</code> next to <code>upload_path</code>"),
    ("unfixed_list_severity", "Important", "CVEs with no fix yet are counted, and listed at or above this severity (Critical, Important, Moderate, Low or none)"),
    ("oscap_path", "/usr/bin/oscap", ""),
    ("upload_html", "1", "Send the OpenSCAP HTML reports to the server"),
    ("compliance_profile", "empty", "SCAP Security Guide profile for a compliance scan, for example <code>cis_server_l1</code> or <code>stig</code>; empty = none"),
    ("compliance_datastream", "empty", "SCAP data stream; empty picks <code>ssg-rhel&lt;release&gt;-ds.xml</code>"),
    ("timeout_minutes", "60", "Minutes before a scan is stopped"),
]) + """

<h2 id="hooks">[hooks] and [uploads]</h2>
""" + setting_rows([
    ("[hooks] enabled", "1", "Run the report hooks"),
    ("[hooks] dir", "/etc/drra/report.d", "Folder of hook programs"),
    ("[hooks] timeout_seconds", "60", "Seconds before a hook is stopped"),
    ("[hooks] max_output_kb", "256", "Output kept from each hook"),
    ("[hooks] user", "empty", "Run the hooks as this user instead of root (then set <code>dir</code> to a folder that user can reach)"),
    ("[uploads] enabled", "1", "Send hook uploads"),
    ("[uploads] dir", "/etc/drra/uploads.d", "Upload hook files (<code>&lt;id&gt;.ini</code>)"),
    ("[uploads] spool_dir", "/var/spool/drra/uploads", "Files waiting to be sent, one folder per hook"),
    ("[uploads] max_bytes", "20000000", "Largest file an upload hook may send"),
]) + """
<p>See <a href="hooks.html">Hooks</a>.</p>
""")

# ---------------------------------------------------------------- reports
page("reports.html", "Reports and DRSM",
     "The DataReel Reporting Agent for Linux report format and how the DataReel System Monitor checks agent hosts.",
     [("format", "Report format"), ("sections", "Sections"), ("drsm", "DRSM"), ("setup", "Set up DRSM"), ("plugins", "The linux plugins")],
     """
<h1>Reports and DRSM</h1>
<p class="lead">Each report is a plain text file, one per host, that DRSM reads in place of an SSH check.</p>

<h2 id="format">Report format</h2>
<p>The server saves the report as <code>&lt;host&gt;_linux_report_agent.txt</code>. It starts with <code>KEY: value</code> headers (<code>VERSION</code>, <code>PLATFORM: linux</code>, <code>HOSTNAME</code>, <code>ETIME</code>, <code>DATETIME</code>), followed by sections of <code>name=value</code> lines. Values with spaces are quoted.</p>
""" + code([("", "VERSION: 1.0-beta2"), ("", "PLATFORM: linux"), ("", "HOSTNAME: web1.example.com"), ("", "..."),
            ("", "PERFORMANCE:"), ("", "cpu_used_pct=7.4"), ("", "load_15m=0.31"), ("", "mem_available_mb=5120"), ("", "END PERFORMANCE")]) + """
<p><code>drra report</code> prints one without sending it.</p>

<h2 id="sections">Sections</h2>
""" + table(["Section", "Contents"], [
    ["SYSTEM", "Release, kernel, vendor, model, serial number, virtualization, time zone"],
    ["IP ADDRESS", "IPv4 and IPv6 addresses of the interfaces that are up"],
    ["PERFORMANCE", "CPU use (5 second sample), iowait, steal, load, memory, swap, processes, uptime"],
    ["DISK USAGE", "Size, use and inode use of every local file system"],
    ["NETWORK", "Traffic, errors and drops of each interface"],
    ["USERS, ACCOUNTS", "Logged in sessions, accounts with a login shell"],
    ["SECURITY", "SELinux, firewalld or nftables, auditd, FIPS, sshd root and password login, automatic updates"],
    ["FAILED SERVICES", "Failed systemd units"],
    ["UPDATES", "Pending package updates, last package install, restart needed for a new kernel"],
    ["VULNERABILITIES", "Security advisories that apply, with severity, CVEs and fixed packages"],
    ["COMPLIANCE", "SCAP Security Guide profile score and failed rules (optional)"],
    ["HOOKS", "Output of the report hooks"],
    ["UPLOADS", "State of the hook uploads"],
    ["INSTALLED PACKAGES", "Every package with version and install time"],
]) + """
<p>With scans on, the OpenSCAP HTML reports are saved next to it as <code>&lt;host&gt;_linux_scap_report.html</code> and <code>&lt;host&gt;_linux_compliance_report.html</code>.</p>

<h2 id="drsm">DRSM</h2>
<p>The <a href="https://datareel.com/info_drsm.php">DataReel System Monitor</a> checks hosts with <code>COLLECTOR=lra</code> from their last report: DRSM never connects to them. They show on the dashboard next to the SSH monitored hosts, with the same alerts and trend graphs, and their advisories show on the Vulnerabilities page. DRSM releases after 1.33 include the Linux agent plugins; for DRSM 1.33 and earlier, <code>drsm/install.sh</code> in the agent source code copies them in (dry run, then <code>--apply</code>).</p>

<h2 id="setup">Set up DRSM</h2>
<ol>
  <li>Set <code>LRA_REPORTS_DIR</code> (the server's <code>reports_dir</code>) in DRSM's <code>etc/hosts/_defaults.conf</code>. If DRSM runs on another machine, sync the reports to it.</li>
  <li>Make a host file for every agent report: <code>utils/lra_hosts.sh</code> (dry run, then <code>--apply</code>).</li>
  <li>For the OpenSCAP HTML links on the Vulnerabilities page, set <code>$LRAreportsDir</code> in the dashboard's <code>config/drsm.php</code> where the uploads land.</li>
</ol>

<h2 id="plugins">The linux plugins</h2>
""" + table(["Plugin", "Checks"], [
    ["<code>linux/checkin</code>", "Report age, agent version, host facts"],
    ["<code>linux/resources</code>", "CPU, load, memory, swap, disks, inodes, network, with the same metrics as the SSH plugins so trends work"],
    ["<code>linux/updates</code>", "Pending updates, days since the last update, restart needed"],
    ["<code>linux/security</code>", "SELinux, firewall, auditd, sshd, failed units"],
    ["<code>linux/vulnerabilities</code>", "An error for critical advisories, a warning for important ones, critical CVEs with no fix yet, an old or failed scan, a low compliance score"],
    ["<code>linux/hooks</code>", "Every report hook; a plugin with <code>LRA_HOOK=&lt;name&gt;</code> shows one hook as its own check"],
]) + """
<p>Each plugin's settings can be changed per host in its host file, for example <code>linux_vulnerabilities_WARN_SEVERITY=Critical</code>.</p>
""")

# ---------------------------------------------------------------- vulnerabilities
page("vulnerabilities.html", "Vulnerability scans",
     "DataReel Reporting Agent for Linux vulnerability scans: OpenSCAP OVAL on RHEL 8 and 9, Red Hat CSAF/VEX on RHEL 10, dnf updateinfo, and SCAP compliance scans.",
     [("on", "Turn scans on"), ("sources", "Sources"), ("oval", "RHEL 8 and 9: OpenSCAP"), ("csaf", "RHEL 10: CSAF/VEX"), ("unfixed", "CVEs with no fix"), ("compliance", "Compliance scans"), ("offline", "Hosts with no internet"), ("page", "The Vulnerabilities page")],
     """
<h1>Vulnerability scans</h1>
<p class="lead">Once a day the agent lists the Red Hat security advisories (RHSA) the installed packages still need, with their severity, CVEs and fixed packages.</p>

<h2 id="on">Turn scans on</h2>
<p>The scans are off by default. Turn them on in <code>/etc/drra/drra.ini</code>:</p>
""" + code([("c", "[scan]"), ("", "enabled=1")]) + code([("#", "systemctl reload drra"), ("#", "drra scan                 # or run one now")]) + """
<p>An OpenSCAP scan can use about 800 MB of memory for a few minutes: keep that in mind on small cloud servers, or use <code>source=dnf</code> there.</p>

<h2 id="sources">Sources</h2>
""" + table(["source", "Used for", "How"], [
    ["<code>auto</code> (default)", "Every host", "OpenSCAP on RHEL 8 and 9; the CSAF/VEX index on RHEL 10 when the agent sends to a report server over https; dnf updateinfo otherwise"],
    ["<code>oval</code>", "Any release", "Always OpenSCAP: <code>oscap oval eval</code> against <code>oval_feed_url</code>"],
    ["<code>csaf</code>", "RHEL 10 (8 and 9 too)", "The report server's CSAF/VEX index, plus dnf errata newer than the VEX files"],
    ["<code>dnf</code>", "Any release", "<code>dnf updateinfo</code>: the repositories' security errata, plus EPEL"],
]) + """

<h2 id="oval">RHEL 8 and 9: OpenSCAP</h2>
<p>The agent runs <code>oscap oval eval</code> (package <code>openscap-scanner</code>) against Red Hat's OVAL feed for the release, for example <code>security.access.redhat.com/data/oval/v2/RHEL9/rhel-9.oval.xml.bz2</code>. The feed is downloaded only when it changes. The OpenSCAP HTML report goes to the server with the next report, and DRSM links it from the Vulnerabilities page.</p>

<h2 id="csaf">RHEL 10: CSAF/VEX</h2>
<p>Red Hat publishes no OVAL feed for RHEL 10, only CSAF/VEX files: one JSON file per CVE, about 400 MB in all. Rather than every host downloading them, <code>vex_sync.php</code> on the report server builds a small index (about 2 MB) of the RHEL 10 packages each CVE is fixed in, and of the packages Red Hat lists as affected with no fix yet (see <a href="server.html#vex">Set up the report server</a>). Agents download the index from <code>vex_index.php</code> when it changes and compare it with their packages using rpm's version rules. Red Hat's VEX files can lag the errata by a day or more, so the agent adds the dnf errata that are newer.</p>

<h2 id="unfixed">CVEs with no fix</h2>
<p>CSAF/VEX scans also count the CVEs that affect an installed package and have no update yet, which <code>dnf updateinfo</code> cannot do. RHEL lists thousands of moderate and low CVEs (most of them kernel) as affected while they are reviewed, so the agent counts them all by severity and lists only those at or above <code>unfixed_list_severity</code> (Important). DRSM warns about unfixed CVEs at or above <code>UNFIXED_WARN_SEVERITY</code> (Critical).</p>

<h2 id="compliance">Compliance scans</h2>
<p>Set <code>compliance_profile</code> to run a SCAP Security Guide profile (package <code>scap-security-guide</code>) with each scan, for example <code>cis_server_l1</code>, <code>stig</code> or <code>pci-dss</code>. The report gets the score and the failed rules, and the HTML report goes to the server. List the profiles with:</p>
""" + code([("$", "oscap info /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")]) + """
<p>A compliance scan can also be run by hand and sent as a <a href="hooks.html#uploads">hook upload</a>, so a host does not run it every day.</p>

<h2 id="offline">Hosts with no internet</h2>
<p><code>source=oval</code> with <code>oval_feed_url</code> set to a local file uses a feed you copy to the host. <code>csaf_index_url</code> can point at a local copy of the CSAF/VEX index too.</p>

<h2 id="page">The Vulnerabilities page</h2>
<p>DRSM's Vulnerabilities page shows every host's advisory counts by severity, the advisories that affect the most hosts, and per host its advisories, fixed packages, CVEs, unfixed CVEs and compliance results. The <code>linux/vulnerabilities</code> plugin raises an error for a critical advisory and a warning for an important one, an unfixed critical CVE, a scan older than 3 days, a failed scan or a low compliance score.</p>
""")

# ---------------------------------------------------------------- hooks
page("hooks.html", "Hooks",
     "DataReel Reporting Agent for Linux report hooks (site checks in every report) and hook uploads (reports from other tools).",
     [("report", "Report hooks"), ("rules", "Hook rules"), ("drsm", "Hooks in DRSM"), ("uploads", "Hook uploads"), ("server", "Server manifests"), ("which", "Which one to use")],
     """
<h1>Hooks</h1>
<p class="lead">Two kinds of hooks add what the agent does not know about: report hooks run a site check with every report, and hook uploads send a file some other tool makes.</p>

<h2 id="report">Report hooks</h2>
<p>Every executable file in <code>/etc/drra/report.d</code> runs once per report, one at a time, stopped after <code>[hooks] timeout_seconds</code> (60). A hook prints lines in the DRSM plugin format (<code>INFO - </code>, <code>WARNING - </code>, <code>ERROR - </code>, <code>METRIC</code>, <code>DETAIL</code> and free text) and exits 0 OK, 1 WARNING, 2 ERROR or 3 UNKNOWN. Its name is the file name without <code>.sh</code>. The report gets them in one section:</p>
""" + code([("", "HOOKS:"), ("", "hook=drcm exit=0 secs=1 timed_out=0 truncated=0"),
            ("", "| INFO - node1 cluster status is HEALTHY, 2 nodes up, 1 resources"),
            ("", "| METRIC drcm_nodes_up=2"), ("", "END HOOKS")]) + """
<p><code>drra hooks</code> runs them now and prints the section.</p>

<h2 id="rules">Hook rules</h2>
<ul>
  <li>The agent runs as root, so a hook only runs when <code>report.d</code> and the file are owned by root and not group or world writable. Others are listed as <code>skipped=</code> and logged.</li>
  <li>Names may use letters, digits, dot, dash and underscore. <code>.rpmnew</code>, <code>.bak</code>, <code>.swp</code>, <code>.disabled</code> and similar files are skipped.</li>
  <li><code>[hooks] user=</code> runs them as another user. Then point <code>dir</code> at a folder that user can reach, since <code>/etc/drra</code> is root only.</li>
</ul>

<h2 id="drsm">Hooks in DRSM</h2>
<p>A DRSM plugin with <code>LRA_HOOK=&lt;name&gt;</code> in its manifest shows that hook as its own check on agent hosts (the <code>cluster/drcm</code> plugin does this), and <code>linux/hooks</code> shows every hook. DRSM's <code>utils/lra_hook_bundle.sh</code> writes a DRSM plugin as one self-contained hook file:</p>
""" + code([("$", "~/drsm/utils/lra_hook_bundle.sh cluster/drcm > drcm"),
            ("#", "install -o root -g root -m 0755 drcm /etc/drra/report.d/drcm"),
            ("#", "drra hooks")]) + """

<h2 id="uploads">Hook uploads</h2>
<p>A hook upload sends a report from another source with the agent: a scan you run by hand (so a cloud server does not pay for a daily scan), a vendor tool's export, a backup job's result. Each upload hook is a file in <code>/etc/drra/uploads.d/</code> (root owned, not group or world writable):</p>
""" + code([("#", "cat /etc/drra/uploads.d/openscap_manual.ini"), ("", "[upload]"), ("", "id=openscap_manual"),
            ("", "title=Manual OpenSCAP scan"), ("", "format=xccdf-results"),
            ("#", "oscap xccdf eval --profile cis_server_l1 --results /tmp/results.xml \\"),
            ("", "    /usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml"),
            ("#", "drra submit --hook openscap_manual --now /tmp/results.xml")]) + """
<p>A tool can also write its file to <code>/var/spool/drra/uploads/&lt;id&gt;/</code> (write a dot or <code>.tmp</code> file, then rename it). Members of the <code>drra-upload</code> group may do both. Files go to <code>hook.php</code> on the report server after each report, or within seconds with <code>--now</code>. <code>drra send-uploads</code> sends them right away and <code>drra uploads</code> lists them. Sent files are kept in <code>&lt;spool&gt;/&lt;id&gt;/sent/</code>, and the report's UPLOADS section has each upload hook's state. Uploads use the https delivery method.</p>

<h2 id="server">Server manifests</h2>
<p>The report server only takes an upload hook that has a manifest: the DRSM plugin <code>plugins/uploads/&lt;id&gt;/plugin.conf</code>, in the folder named by <code>[hooks] manifest_dir</code> in <code>server.ini</code>. The manifest picks the format (<code>drsm-lines</code>, <code>kv-sections</code>, <code>json</code>, <code>csv</code>, <code>xccdf-results</code>, <code>text</code>, <code>html</code>), the alert rules and how DRSM shows the data. See "Hook uploads" in DRSM's PLUGINS.md.</p>

<h2 id="which">Which one to use</h2>
<p>Use a report hook for a check that must run on the host each time; use a hook upload for a file that some other tool makes now and then.</p>
""")

# ---------------------------------------------------------------- security
page("security.html", "Security",
     "DataReel Reporting Agent for Linux security: agent key and certificate, registration, signed uploads, TLS, the hardened service and their limits.",
     [("identity", "Agent identity"), ("registration", "Registration"), ("uploads", "Signed uploads"), ("tls", "TLS"), ("service", "The service"), ("server", "Server side"), ("limits", "Limits")],
     """
<h1>Security</h1>
<p class="lead">The host only makes outgoing connections, and the server only keeps reports signed by approved hosts.</p>

<h2 id="identity">Agent identity</h2>
<p>On its first run the agent makes an RSA 3072 key and a self-signed certificate (CN = the host name, valid 20 years) in <code>/var/lib/drra</code>, readable by root only. The key never leaves the host.</p>

<h2 id="registration">Registration</h2>
<p>The agent sends its certificate to <code>register.php</code> with a time stamp and a one time nonce, signed with its key, which proves it holds the key. The server checks that the certificate's CN is the host name, and saves the registration as pending, or approved when the enrollment token matches. A host name that is already registered with another key gets <code>key_mismatch</code>.</p>

<h2 id="uploads">Signed uploads</h2>
<p>Each upload carries the report's SHA-256 hash (and the hash of each HTML report or hook file), the host name, a time stamp and a nonce, signed with RSA PKCS#1 v1.5 and SHA-256. The server checks the signature against the registered certificate, refuses agents that are not approved, refuses a time stamp more than <code>max_clock_skew_seconds</code> (300) from its clock, and refuses a nonce it has seen, so a captured upload cannot be sent again.</p>

<h2 id="tls">TLS</h2>
<p>Uploads use HTTPS through libcurl and OpenSSL with certificate and host name checks against the system trust store, or <code>ca_file</code> for a private CA. <code>verify_peer=0</code> and <code>use_https=0</code> exist for test servers only.</p>

<h2 id="service">The service</h2>
<p>The agent runs as root to read the package database, SELinux, firewalld and sshd settings and the DMI serial number. The systemd unit makes <code>/usr</code>, <code>/boot</code> and <code>/etc</code> read only, home folders read only, <code>/tmp</code> private, and sets <code>NoNewPrivileges</code>, kernel tunable and module protection, at low CPU and I/O priority. Files the agent writes are private to root. Report hooks run only from root owned, not group or world writable files, and can run as another user.</p>

<h2 id="server">Server side</h2>
<ul>
  <li>Keep <code>server.ini</code> and the data folder outside the web root, or behind the <code>Require all denied</code> <code>.htaccess</code> that <code>install_server.sh</code> adds.</li>
  <li><code>admin.php</code> runs only behind a login (web server or DRSM dashboard) and uses CSRF tokens.</li>
  <li>The include files and <code>vex_sync.php</code> are blocked from the web.</li>
  <li>Hook uploads are taken only for hook IDs with a manifest, up to <code>max_bytes</code>.</li>
</ul>

<h2 id="limits">Limits</h2>
<ul>
  <li>Anyone with root on a host can read its key and send reports as that host. Revoke a host that was compromised.</li>
  <li>With an enrollment token, anyone who has the token can register a new host name. Keep the token secret and empty it after a rollout.</li>
  <li>Reports hold the host's package list, users and settings: protect the reports folder and the DRSM dashboard with a login.</li>
</ul>
""")

# ---------------------------------------------------------------- building
page("building.html", "Build from source",
     "Build the DataReel Reporting Agent for Linux with make, and its RPMs for RHEL 8, 9 and 10 with podman.",
     [("needs", "What you need"), ("make", "Build with make"), ("rpms", "Build the RPMs"), ("tests", "Tests"), ("files", "Source files")],
     """
<h1>Build from source</h1>
<p class="lead">The agent is plain C++17 with OpenSSL, libcurl, libxml2, bzip2 and zlib from the distribution, so it builds the same on RHEL 8, 9 and 10.</p>

<h2 id="needs">What you need</h2>
""" + code([("#", "dnf install gcc-c++ make openssl-devel libcurl-devel libxml2-devel bzip2-devel zlib-devel")]) + """

<h2 id="make">Build with make</h2>
""" + code([("$", "wget https://datareel.com/downloads/linux_reporting_agent/linux_reporting_agent-1.0-beta2.tar.gz"),
            ("$", "tar xzf linux_reporting_agent-1.0-beta2.tar.gz && cd linux_reporting_agent-1.0-beta2"),
            ("$", "make"),
            ("#", "make install            # /usr/sbin/drra, /etc/drra, the systemd unit"),
            ("#", "systemctl daemon-reload")]) + """
<p><code>make install</code> takes <code>DESTDIR</code>, <code>PREFIX</code>, <code>SYSCONFDIR</code> and <code>UNITDIR</code>. It overwrites <code>/etc/drra/drra.ini</code>: keep a copy of yours.</p>

<h2 id="rpms">Build the RPMs</h2>
""" + code([("$", "tools/build_rpms.sh")]) + """
<p>Builds the source tarball and the RHEL 8, 9 and 10 RPMs in UBI containers with podman, into <code>output/</code>, with a <code>.sha256sum</code> file. The spec file is <code>rpm/linux_reporting_agent.spec</code>.</p>

<h2 id="tests">Tests</h2>
""" + code([("$", "tests/drsm_test.sh           # DRSM plugins and pages against a DRSM checkout"),
            ("$", "tests/uploads_test.sh        # hook uploads end to end with php -S")]) + """

<h2 id="files">Source files</h2>
""" + table(["File", "Contents"], [
    ["<code>src/drra.cpp</code>", "Commands and the service loop"],
    ["<code>src/common.cpp</code>, <code>common.h</code>", "Settings, logging, helpers, version"],
    ["<code>src/collect.cpp</code>", "The report sections"],
    ["<code>src/scan.cpp</code>", "OpenSCAP, CSAF/VEX and dnf vulnerability scans, compliance scans"],
    ["<code>src/agent_auth.cpp</code>", "Key, certificate, signing, registration and uploads (OpenSSL, libcurl)"],
    ["<code>src/deliver.cpp</code>", "HTTPS, CIFS and SCP delivery"],
    ["<code>src/hooks.cpp</code>, <code>uploads.cpp</code>", "Report hooks and hook uploads"],
    ["<code>src/compat.h</code>", "RHEL 8 OpenSSL 1.1 and curl 7.61 support"],
    ["<code>drra.ini</code>, <code>systemd/</code>, <code>rpm/</code>", "Default settings, systemd unit and logrotate file, RPM spec"],
    ["<code>php/</code>", "Report server pages, <code>install_server.sh</code>, <code>server.ini.example</code>"],
    ["<code>drsm/</code>", "DRSM collector, linux plugins and Vulnerabilities page, with <code>install.sh</code>"],
    ["<code>tools/</code>", "<code>build_rpms.sh</code>, <code>gen_docs.py</code> for these pages"],
]) + """
""")

# ---------------------------------------------------------------- troubleshooting
page("troubleshooting.html", "Troubleshooting",
     "DataReel Reporting Agent for Linux log messages and what to do about them.",
     [("log", "The log file"), ("messages", "Messages"), ("server", "Server side")],
     """
<h1>Troubleshooting</h1>
<p class="lead">Start with the agent log. It has the result of the last report for each delivery method.</p>

<h2 id="log">The log file</h2>
<p><code>/var/log/drra/drra.log</code>, and <code>journalctl -u drra</code>. Run <code>drra once</code> as root to get a fresh result right away, and <code>drra config</code> to see the settings in use.</p>

<h2 id="messages">Messages</h2>
""" + table(["Message", "What to do"], [
    ["<code>Registration status from server: pending</code>", "Approve the host on the admin page (check <code>drra fingerprint</code>), or set the enrollment token"],
    ["<code>key_mismatch</code>", "The host was reinstalled or its key changed. Delete its old registration on the admin page."],
    ["<code>revoked</code>", "An admin revoked the host. Approve it again if that was a mistake."],
    ["<code>bad_timestamp</code>", "Fix the clock on the host or the server (chronyd); allowed difference: <code>max_clock_skew_seconds</code>"],
    ["<code>bad_token</code>", "The enrollment token in <code>drra.ini</code> does not match <code>server.ini</code>"],
    ["<code>bad_signature</code>", "The request was changed on the way, or the key does not match the registration"],
    ["<code>Request to ... failed: SSL certificate problem</code>", "The host does not trust the server's certificate: install the CA in the system trust store or set <code>ca_file</code>"],
    ["<code>Request to ... failed: Could not resolve host</code> or <code>Connection refused</code>", "Check <code>host</code> and <code>port</code>, DNS, and outgoing firewall rules"],
    ["<code>Unexpected answer from ... (HTTP 404)</code>", "<code>upload_path</code> or <code>register_path</code> is wrong"],
    ["<code>NT_STATUS_...</code>", "The CIFS copy failed: share name, <code>credentials_file</code>, or permissions on the share"],
    ["<code>Host key verification failed</code>", "Add the SCP server to <code>known_hosts_file</code>, or use <code>accept-new</code> once"],
    ["Scan status <code>failed</code>", "Run <code>drra scan</code> to see the error: <code>openscap-scanner</code> missing, the feed cannot be downloaded, or the CSAF/VEX index is missing on the server"],
    ["Hook <code>skipped=</code>", "The hook file or folder is not owned by root, or is group or world writable"],
]) + """

<h2 id="server">Server side</h2>
<ul>
  <li><code>STATUS: error</code> about saving a registration or a report: the web server user cannot write to the data folder or <code>reports_dir</code>. Check the owner, ACL and, with SELinux, the <code>httpd_sys_rw_content_t</code> label (<code>ls -Z</code>).</li>
  <li><code>admin.php</code> refuses to run: the <code>.htaccess</code> login is not active (check <code>AllowOverride</code>), or <code>drsm_config</code> is wrong with <code>login = drsm</code>.</li>
  <li><code>vex_index.php</code> answers 404: <code>vex_sync.php</code> has not built the index yet.</li>
  <li>Check the Apache error log for PHP errors.</li>
</ul>
""")

# ---------------------------------------------------------------- changelog
page("changelog.html", "What's new",
     "DataReel Reporting Agent for Linux release history.",
     [("v10b2", "Release 1.0 beta 2"), ("v10b1", "Release 1.0 beta 1")],
     """
<h1>What's new</h1>
<p class="lead">Release 1.0 beta 2 (1.0-beta2) adds report hooks and hook uploads. Release 1.0 beta 1 was the first release of the DataReel Reporting Agent for Linux. Both are betas: test them on a few hosts before a wide rollout.</p>

<h2 id="v10b2">Release 1.0 beta 2 <span class="badge new">October 2026</span></h2>
<ul>
  <li><strong>Report hooks:</strong> site checks in <code>/etc/drra/report.d</code> run with every report, in a HOOKS section DRSM shows as checks (<code>LRA_HOOK=</code>, <code>linux/hooks</code>). <code>drra hooks</code> runs them now. See <a href="hooks.html">Hooks</a>.</li>
  <li><strong>Hook uploads:</strong> send reports from other sources, such as a scan run by hand or a backup job's result, with <code>drra submit --hook &lt;id&gt; [--now] &lt;file&gt;</code> or the spool folders. The server's new <code>hook.php</code> checks the signature and a manifest per hook.</li>
  <li>New <code>[hooks]</code> and <code>[uploads]</code> settings, <code>[https] hook_path</code>, the UPLOADS report section and the <code>drra-upload</code> group.</li>
</ul>

<h2 id="v10b1">Release 1.0 beta 1 <span class="badge new">October 2026</span></h2>
<ul>
  <li><strong>Agent:</strong> C++ systemd service for RHEL 8, 9 and 10, reporting every 15 minutes: system, usage, security settings, failed services, updates and installed packages.</li>
  <li><strong>Signed uploads:</strong> the Windows agent's protocol: certificate registration, approval on an admin page or with an enrollment token, and signed, time stamped, one time uploads over HTTPS. CIFS and SCP delivery too.</li>
  <li><strong>Vulnerability scans:</strong> OpenSCAP OVAL on RHEL 8 and 9, Red Hat CSAF/VEX on RHEL 10 (server index built by <code>vex_sync.php</code>, with unfixed CVE counts), dnf updateinfo as fallback, optional SCAP compliance profiles. Off by default.</li>
  <li><strong>DRSM:</strong> the <code>lra</code> collector, <code>linux/*</code> plugins and the Vulnerabilities page.</li>
  <li><strong>Packages:</strong> RPMs for RHEL 8, 9 and 10 with a hardened systemd unit.</li>
</ul>
""")
print("wrote", len(ORDER), "pages to", OUT)
