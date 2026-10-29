#ifndef SCAN_H
#define SCAN_H

// Vulnerability and compliance scans
//
// Vulnerabilities come from one of two sources, both Red Hat errata:
//   oval - OpenSCAP (oscap oval eval) against an OVAL feed. Red Hat
//          publishes OVAL v2 feeds for RHEL 8 and 9.
//   dnf  - dnf updateinfo, the security advisories that apply to the
//          installed packages. Used on RHEL 10, which has no OVAL feed,
//          and on other dnf based systems.
// A compliance scan (oscap xccdf eval with a SCAP Security Guide profile,
// such as cis or stig) runs too when [scan] compliance_profile is set.
//
// Scans take minutes, so they run every interval_hours and the results
// are kept in data_dir. Every report carries the last results.

#include "common.h"
#include "agent_auth.h"

#define SCAN_VULN_FILE "scan_vulnerabilities.txt"
#define SCAN_COMPLIANCE_FILE "scan_compliance.txt"
#define SCAN_VULN_HTML "scan_vulnerabilities.html"
#define SCAN_COMPLIANCE_HTML "scan_compliance.html"
#define SCAN_HTML_PENDING ".pending"

bool ScanDue(const AgentConfig &cfg);
int RunScan(const AgentConfig &cfg, std::string &output);
std::string ScanReportSections(const AgentConfig &cfg);
// HTML reports from the last scan that the server has not received yet
std::vector<FormFile> PendingScanHtml(const AgentConfig &cfg, const std::string &hostname);
void ClearPendingScanHtml(const AgentConfig &cfg);

#endif
