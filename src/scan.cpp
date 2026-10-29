// C STD lib includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// C++ STD lib includes
#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <algorithm>

// Libraries
#include <bzlib.h>
#include <curl/curl.h>
#include <libxml/xmlreader.h>
#include <libxml/tree.h>

// APP includes
#include "common.h"
#include "collect.h"
#include "scan.h"
#include "compat.h"

// One security advisory that applies to this host
struct Advisory {
  std::string id;                    // RHSA-2026:1234
  std::string severity;              // Critical, Important, Moderate, Low, Unknown
  std::string title;
  std::string issued;                // YYYY-MM-DD
  std::set<std::string> cves;
  std::set<std::string> packages;    // name<fixed version, or the update NEVRA
};

static std::string NormalSeverity(const std::string &s)
{
  std::string l = ToLower(Trim(s));
  if(l == "critical") return "Critical";
  if(l == "important" || l == "high") return "Important";
  if(l == "moderate" || l == "medium") return "Moderate";
  if(l == "low") return "Low";
  return "Unknown";
}

static int SeverityRank(const std::string &s)
{
  if(s == "Critical") return 0;
  if(s == "Important") return 1;
  if(s == "Moderate") return 2;
  if(s == "Low") return 3;
  return 4;
}

// Red Hat's OVAL v2 feed for the host's release, empty when there is none
static std::string DefaultOvalFeed()
{
  std::map<std::string, std::string> os = ReadOsRelease();
  int major = atoi(os["VERSION_ID"].c_str());
  if(os["ID"] != "rhel" || major < 8 || major > 9) return std::string();
  return "https://security.access.redhat.com/data/oval/v2/RHEL" + std::to_string(major) +
    "/rhel-" + std::to_string(major) + ".oval.xml.bz2";
}

bool ScanDue(const AgentConfig &cfg)
{
  if(!cfg.scan_enabled) return false;
  long long last = FileMtime(JoinPath(cfg.data_dir, SCAN_VULN_FILE));
  return last == 0 || (long long)time(NULL) - last >= (long long)cfg.scan_interval_hours * 3600;
}

static size_t CurlToFile(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  return fwrite(ptr, size, nmemb, (FILE *)userdata);
}

//
// Purpose:
//   Downloads the OVAL feed when it changed on the server (If-Modified-Since)
//   and unpacks a .bz2 feed
//
// Return value:
//   0 when feed_xml holds a usable feed
//
static int FetchOvalFeed(const AgentConfig &cfg, const std::string &url, std::string &feed_xml, std::string &output)
{
  std::string dir = JoinPath(cfg.data_dir, "oval");
  CreateDirTree(dir, 0700);
  bool bz2 = url.length() > 4 && url.substr(url.length() - 4) == ".bz2";
  std::string name = url.substr(url.rfind('/') + 1);
  std::string download = JoinPath(dir, name);
  feed_xml = bz2 ? download.substr(0, download.length() - 4) : download;

  // A local feed file needs no download
  if(StartsWith(url, "/")) {
    download = url;
    feed_xml = bz2 ? JoinPath(dir, name.substr(0, name.length() - 4)) : url;
  }
  else if(StartsWith(url, "file://")) {
    download = url.substr(7);
    feed_xml = bz2 ? JoinPath(dir, name.substr(0, name.length() - 4)) : download;
  }
  else {
    std::string tmp = download + ".download";
    FILE *fp = fopen(tmp.c_str(), "wb");
    if(!fp) {
      output += "ERROR - Cannot write " + tmp + "\n";
      return -1;
    }
    CURL *curl = curl_easy_init();
    char errbuf[CURL_ERROR_SIZE] = "";
    long last = FileMtime(download);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlToFile);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    AgentCurlProtocols(curl, true);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DataReelReportAgentLinux/" AGENT_VERSION);
    if(last > 0 && FileExists(feed_xml)) {
      curl_easy_setopt(curl, CURLOPT_TIMECONDITION, (long)CURL_TIMECOND_IFMODSINCE);
      curl_easy_setopt(curl, CURLOPT_TIMEVALUE, last);
    }
    CURLcode rc = curl_easy_perform(curl);
    long http = 0, filetime = -1;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
    long unmet = 0;
    curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &unmet);
    curl_easy_cleanup(curl);
    fclose(fp);

    if(rc != CURLE_OK || (http != 200 && http != 304)) {
      unlink(tmp.c_str());
      std::string why = (rc != CURLE_OK) ? std::string(errbuf[0] ? errbuf : curl_easy_strerror(rc)) : "HTTP " + std::to_string(http);
      if(FileExists(feed_xml)) {
	output += "WARNING - Could not download " + url + " (" + why + "), using the copy from the last scan\n";
	return 0;
      }
      output += "ERROR - Could not download " + url + ": " + why + "\n";
      return -1;
    }
    if(http == 304 || unmet) {
      unlink(tmp.c_str());
      return 0;
    }
    if(rename(tmp.c_str(), download.c_str()) != 0) {
      output += "ERROR - Cannot save " + download + "\n";
      return -1;
    }
    // Keep the server's time on the file for the next If-Modified-Since
    if(filetime > 0) {
      std::string t = std::to_string(filetime);
      CommandResult r;
      RunCommand({ "touch", "-d", "@" + t, download }, 10, r);
    }
    output += "Downloaded " + url + "\n";
    if(bz2) unlink(feed_xml.c_str());
  }

  if(!bz2) return FileExists(feed_xml) ? 0 : -1;
  if(FileExists(feed_xml) && FileMtime(feed_xml) >= FileMtime(download)) return 0;

  // Unpack the .bz2 feed
  FILE *in = fopen(download.c_str(), "rb");
  if(!in) {
    output += "ERROR - Cannot read " + download + "\n";
    return -1;
  }
  std::string tmp = feed_xml + ".tmp";
  FILE *out = fopen(tmp.c_str(), "wb");
  if(!out) {
    fclose(in);
    output += "ERROR - Cannot write " + tmp + "\n";
    return -1;
  }
  int bzerr = BZ_OK;
  BZFILE *bz = BZ2_bzReadOpen(&bzerr, in, 0, 0, NULL, 0);
  char buf[65536];
  while(bzerr == BZ_OK) {
    int n = BZ2_bzRead(&bzerr, bz, buf, sizeof(buf));
    if((bzerr == BZ_OK || bzerr == BZ_STREAM_END) && n > 0) fwrite(buf, 1, (size_t)n, out);
  }
  BZ2_bzReadClose(NULL, bz);
  fclose(in);
  bool ok = (fclose(out) == 0) && bzerr == BZ_STREAM_END;
  if(!ok || rename(tmp.c_str(), feed_xml.c_str()) != 0) {
    unlink(tmp.c_str());
    output += "ERROR - Could not unpack " + download + "\n";
    return -1;
  }
  return 0;
}

static std::string NodeText(xmlNodePtr n)
{
  xmlChar *c = xmlNodeGetContent(n);
  std::string s = c ? Trim((const char *)c) : std::string();
  if(c) xmlFree(c);
  return s;
}

static std::string NodeAttr(xmlNodePtr n, const char *name)
{
  xmlChar *c = xmlGetProp(n, (const xmlChar *)name);
  std::string s = c ? (const char *)c : std::string();
  if(c) xmlFree(c);
  return s;
}

static void WalkDefinition(xmlNodePtr n, Advisory &a, const std::set<std::string> &installed)
{
  for(xmlNodePtr c = n; c; c = c->next) {
    if(c->type != XML_ELEMENT_NODE) continue;
    std::string name = (const char *)c->name;
    if(name == "title") {
      a.title = NodeText(c);
    }
    else if(name == "reference") {
      std::string src = NodeAttr(c, "source"), ref = NodeAttr(c, "ref_id");
      if(src == "RHSA" && a.id.empty()) a.id = ref;
      else if(src == "CVE") a.cves.insert(ref);
    }
    else if(name == "severity") {
      a.severity = NormalSeverity(NodeText(c));
    }
    else if(name == "issued") {
      a.issued = NodeAttr(c, "date");
    }
    else if(name == "cve") {
      a.cves.insert(NodeText(c));
    }
    else if(name == "criterion") {
      // "openssl is earlier than 1:3.0.7-27.el9": the fixed version
      std::string comment = NodeAttr(c, "comment");
      size_t p = comment.find(" is earlier than ");
      if(p != std::string::npos) {
	std::string pkg = comment.substr(0, p);
	if(installed.empty() || installed.count(pkg)) a.packages.insert(pkg + "<" + comment.substr(p + 17));
      }
    }
    if(name != "affected_cpe_list" && name != "description" && c->children) WalkDefinition(c->children, a, installed);
  }
}

// Reads the feed metadata (title, severity, CVEs, fixed versions) of the definitions in ids
static int ReadOvalDefinitions(const std::string &feed_xml, const std::set<std::string> &ids,
			       const std::set<std::string> &installed, std::vector<Advisory> &out, std::string &output)
{
  xmlTextReaderPtr reader = xmlReaderForFile(feed_xml.c_str(), NULL, XML_PARSE_NONET | XML_PARSE_HUGE);
  if(!reader) {
    output += "ERROR - Cannot open " + feed_xml + "\n";
    return -1;
  }
  int rc;
  while((rc = xmlTextReaderRead(reader)) == 1) {
    if(xmlTextReaderNodeType(reader) != XML_READER_TYPE_ELEMENT) continue;
    const xmlChar *lname = xmlTextReaderConstLocalName(reader);
    if(!lname || strcmp((const char *)lname, "definition") != 0) continue;
    xmlChar *idc = xmlTextReaderGetAttribute(reader, (const xmlChar *)"id");
    std::string id = idc ? (const char *)idc : "";
    if(idc) xmlFree(idc);
    if(!ids.count(id)) {
      xmlTextReaderNext(reader);
      continue;
    }
    xmlNodePtr node = xmlTextReaderExpand(reader);
    if(node) {
      Advisory a;
      WalkDefinition(node->children, a, installed);
      if(a.id.empty()) a.id = id;
      if(a.severity.empty()) a.severity = "Unknown";
      out.push_back(a);
    }
    xmlTextReaderNext(reader);
  }
  xmlFreeTextReader(reader);
  return rc < 0 ? -1 : 0;
}

static std::set<std::string> InstalledPackageNames(const AgentConfig &cfg)
{
  std::set<std::string> names;
  std::string list;
  long long newest = 0;
  get_installed_packages(cfg, list, newest);
  for(const std::string &line : Split(list, '\n')) {
    if(!StartsWith(line, "package=")) continue;
    names.insert(line.substr(8, line.find(' ') - 8));
  }
  return names;
}

static int ScanOval(const AgentConfig &cfg, const std::string &url, std::vector<Advisory> &advisories, std::string &output)
{
  if(access(cfg.oscap_path.c_str(), X_OK) != 0) {
    output += "ERROR - " + cfg.oscap_path + " not found, install openscap-scanner\n";
    return -1;
  }
  std::string feed_xml;
  if(FetchOvalFeed(cfg, url, feed_xml, output) != 0) return -1;

  std::string html = JoinPath(cfg.data_dir, SCAN_VULN_HTML);
  std::string results = JoinPath(cfg.data_dir, "oval/results.xml");
  std::vector<std::string> argv = { cfg.oscap_path, "oval", "eval", "--results", results };
  if(cfg.scan_upload_html) {
    argv.push_back("--report");
    argv.push_back(html + ".tmp");
  }
  argv.push_back(feed_xml);
  CommandResult r;
  RunCommand(argv, cfg.scan_timeout_minutes * 60, r);
  if(r.exit_code != 0) {
    output += "ERROR - oscap oval eval failed" + std::string(r.timed_out ? " (timed out)" : "") + ": " + Trim(r.err) + "\n";
    unlink((html + ".tmp").c_str());
    return -1;
  }
  if(cfg.scan_upload_html && rename((html + ".tmp").c_str(), html.c_str()) == 0) {
    WriteWholeFile(html + SCAN_HTML_PENDING, "1\n", 0600);
  }

  // "Definition oval:com.redhat.rhsa:def:20253456: true" for each patch
  // that is not installed
  std::set<std::string> ids;
  for(const std::string &line : Split(r.out, '\n')) {
    if(!StartsWith(line, "Definition ")) continue;
    size_t p = line.rfind(": ");
    if(p == std::string::npos || Trim(line.substr(p + 2)) != "true") continue;
    ids.insert(line.substr(11, p - 11));
  }
  if(ids.empty()) return 0;
  return ReadOvalDefinitions(feed_xml, ids, InstalledPackageNames(cfg), advisories, output);
}

static int ScanDnf(const AgentConfig &cfg, std::vector<Advisory> &advisories, std::string &output)
{
  std::string dnf = DnfProgram();
  if(dnf.empty()) {
    output += "ERROR - No dnf or yum to read security advisories from\n";
    return -1;
  }
  RefreshPackageMetadata(cfg, output);
  int timeout = cfg.scan_timeout_minutes * 60;

  // Advisory details: title, severity, CVEs
  CommandResult r;
  RunCommand({ dnf, "-q", "-C", "--setopt=skip_if_unavailable=True", "updateinfo", "info", "--security" }, timeout, r);
  if(r.exit_code != 0) {
    output += "ERROR - dnf updateinfo info failed: " + Trim(r.err) + "\n";
    return -1;
  }
  std::map<std::string, Advisory> by_id;
  std::string title, key;
  Advisory cur;
  auto flush = [&]() {
    if(!cur.id.empty()) {
      if(cur.severity.empty()) cur.severity = "Unknown";
      by_id[cur.id] = cur;
    }
    cur = Advisory();
  };
  std::vector<std::string> lines = Split(r.out, '\n');
  for(size_t i = 0; i < lines.size(); i++) {
    const std::string &line = lines[i];
    if(StartsWith(line, "=====")) {
      // A title between two rules starts the next advisory
      if(i + 2 < lines.size() && StartsWith(lines[i + 2], "=====")) {
	flush();
	cur.title = Trim(lines[i + 1]);
	i += 2;
      }
      continue;
    }
    size_t c = line.find(": ");
    if(c == std::string::npos) continue;
    std::string k = Trim(line.substr(0, c)), v = Trim(line.substr(c + 2));
    if(!k.empty()) key = k;
    if(key == "Update ID") cur.id = v;
    else if(key == "Severity") cur.severity = NormalSeverity(v);
    else if(key == "Updated" && cur.issued.empty()) cur.issued = v.substr(0, 10);
    else if(key == "Issued") cur.issued = v.substr(0, 10);
    else if(key == "CVEs") {
      for(const std::string &cve : Split(v, ' ')) if(StartsWith(Trim(cve), "CVE-")) cur.cves.insert(Trim(cve));
    }
    else if(key == "Bugs" && !v.empty()) {
      // EPEL advisories name the CVEs in the bug titles only
      size_t p = v.find("CVE-");
      if(p != std::string::npos) {
	size_t e = p + 4;
	while(e < v.length() && (isdigit((unsigned char)v[e]) || v[e] == '-')) e++;
	cur.cves.insert(v.substr(p, e - p));
      }
    }
  }
  flush();

  // Packages each advisory updates: "RHSA-2026:90328 Moderate/Sec. bind-libs-32:9.18.33-15.el10_2.13.x86_64"
  RunCommand({ dnf, "-q", "-C", "--setopt=skip_if_unavailable=True", "updateinfo", "list", "--security" }, timeout, r);
  if(r.exit_code != 0) {
    output += "ERROR - dnf updateinfo list failed: " + Trim(r.err) + "\n";
    return -1;
  }
  for(const std::string &line : Split(r.out, '\n')) {
    std::istringstream in(line);
    std::string id, sev, nevra;
    if(!(in >> id >> sev >> nevra)) continue;
    Advisory &a = by_id[id];
    if(a.id.empty()) {
      a.id = id;
      a.severity = NormalSeverity(sev.substr(0, sev.find('/')));
    }
    a.packages.insert(nevra);
  }
  for(auto &kv : by_id) advisories.push_back(kv.second);
  return 0;
}

static std::string JoinSet(const std::set<std::string> &s)
{
  std::string out;
  for(const std::string &v : s) {
    if(!out.empty()) out += ",";
    out += v;
  }
  return out;
}

static int ScanCompliance(const AgentConfig &cfg, std::string &section, std::string &output)
{
  section.clear();
  std::string ds = cfg.compliance_datastream;
  if(ds.empty()) {
    std::map<std::string, std::string> os = ReadOsRelease();
    std::string id = os["ID"];
    int major = atoi(os["VERSION_ID"].c_str());
    std::string base = "/usr/share/xml/scap/ssg/content/ssg-";
    if(id == "rhel" || id == "centos" || id == "almalinux" || id == "rocky") ds = base + "rhel" + std::to_string(major) + "-ds.xml";
    else if(id == "fedora") ds = base + "fedora-ds.xml";
    else ds = base + id + std::to_string(major) + "-ds.xml";
  }
  if(!FileExists(ds)) {
    output += "ERROR - SCAP data stream " + ds + " not found, install scap-security-guide\n";
    return -1;
  }
  std::string profile = cfg.compliance_profile;
  if(!StartsWith(profile, "xccdf_")) {
    profile = "xccdf_org.ssgproject.content_profile_" + profile;
  }
  std::string html = JoinPath(cfg.data_dir, SCAN_COMPLIANCE_HTML);
  std::string results = JoinPath(cfg.data_dir, "compliance_results.xml");
  std::vector<std::string> argv = { cfg.oscap_path, "xccdf", "eval", "--profile", profile, "--results", results };
  if(cfg.scan_upload_html) {
    argv.push_back("--report");
    argv.push_back(html + ".tmp");
  }
  argv.push_back(ds);
  CommandResult r;
  RunCommand(argv, cfg.scan_timeout_minutes * 60, r);
  // oscap xccdf eval exits 2 when a rule failed
  if(r.exit_code != 0 && r.exit_code != 2) {
    output += "ERROR - oscap xccdf eval failed" + std::string(r.timed_out ? " (timed out)" : "") + ": " + Trim(r.err) + "\n";
    unlink((html + ".tmp").c_str());
    return -1;
  }
  if(cfg.scan_upload_html && rename((html + ".tmp").c_str(), html.c_str()) == 0) {
    WriteWholeFile(html + SCAN_HTML_PENDING, "1\n", 0600);
  }

  xmlDocPtr doc = xmlReadFile(results.c_str(), NULL, XML_PARSE_NONET | XML_PARSE_HUGE);
  if(!doc) {
    output += "ERROR - Cannot read " + results + "\n";
    return -1;
  }
  std::map<std::string, int> counts;
  std::string score, failed;
  std::vector<xmlNodePtr> stack = { xmlDocGetRootElement(doc) };
  while(!stack.empty()) {
    xmlNodePtr n = stack.back();
    stack.pop_back();
    for(xmlNodePtr c = n ? n->children : NULL; c; c = c->next) {
      if(c->type != XML_ELEMENT_NODE) continue;
      std::string name = (const char *)c->name;
      if(name == "rule-result") {
	std::string result;
	for(xmlNodePtr k = c->children; k; k = k->next) {
	  if(k->type == XML_ELEMENT_NODE && strcmp((const char *)k->name, "result") == 0) result = NodeText(k);
	}
	counts[result]++;
	if(result == "fail") {
	  std::string rule = NodeAttr(c, "idref");
	  const std::string prefix = "xccdf_org.ssgproject.content_rule_";
	  if(StartsWith(rule, prefix)) rule = rule.substr(prefix.length());
	  failed += "fail rule=" + rule + " severity=" + NodeAttr(c, "severity") + "\n";
	}
      }
      else if(name == "score" && score.empty()) {
	score = NodeText(c);
      }
      else if(c->children) {
	stack.push_back(c);
      }
    }
  }
  xmlFreeDoc(doc);

  section += "profile=" + cfg.compliance_profile + "\n";
  section += "datastream=" + ds + "\n";
  section += "scan_etime=" + std::to_string((long long)time(NULL)) + "\n";
  if(!score.empty()) section += "score=" + FormatPct(atof(score.c_str())) + "\n";
  section += "pass=" + std::to_string(counts["pass"]) + " fail=" + std::to_string(counts["fail"]) +
    " notapplicable=" + std::to_string(counts["notapplicable"]) + " notchecked=" + std::to_string(counts["notchecked"]) +
    " error=" + std::to_string(counts["error"]) + "\n";
  section += failed;
  return 0;
}

//
// Purpose:
//   Runs the vulnerability scan, and the compliance scan when a profile
//   is set, and saves the results for the following reports
//
// Return value:
//   0 when the vulnerability scan worked
//
int RunScan(const AgentConfig &cfg, std::string &output)
{
  CreateDirTree(cfg.data_dir, 0700);
  std::string source = cfg.scan_source;
  std::string url = cfg.oval_feed_url.empty() ? DefaultOvalFeed() : cfg.oval_feed_url;
  if(source == "auto") source = url.empty() ? "dnf" : "oval";
  if(source == "oval" && url.empty()) {
    output += "ERROR - [scan] source=oval needs oval_feed_url, Red Hat has no OVAL feed for this release\n";
    source = "dnf";
  }

  time_t start = time(NULL);
  std::vector<Advisory> advisories;
  int rv = (source == "oval") ? ScanOval(cfg, url, advisories, output) : ScanDnf(cfg, advisories, output);

  std::string section = "source=" + source + "\n";
  section += "feed=" + (source == "oval" ? url : std::string("dnf updateinfo")) + "\n";
  section += "scan_etime=" + std::to_string((long long)start) + "\n";
  section += "scan_seconds=" + std::to_string((long long)(time(NULL) - start)) + "\n";
  if(rv != 0) {
    section += "status=failed\n";
    // The error line goes in the report so the dashboard can show it
    std::string last;
    for(const std::string &l : Split(output, '\n')) if(StartsWith(l, "ERROR - ")) last = l;
    section += last + "\n";
  }
  else {
    std::sort(advisories.begin(), advisories.end(), [](const Advisory &a, const Advisory &b) {
	if(SeverityRank(a.severity) != SeverityRank(b.severity)) return SeverityRank(a.severity) < SeverityRank(b.severity);
	return a.id > b.id;
      });
    std::map<std::string, int> counts;
    std::set<std::string> cves;
    for(const Advisory &a : advisories) {
      counts[a.severity]++;
      cves.insert(a.cves.begin(), a.cves.end());
    }
    section += "status=ok\n";
    section += "critical=" + std::to_string(counts["Critical"]) + " important=" + std::to_string(counts["Important"]) +
      " moderate=" + std::to_string(counts["Moderate"]) + " low=" + std::to_string(counts["Low"]) +
      " unknown=" + std::to_string(counts["Unknown"]) + " total=" + std::to_string(advisories.size()) +
      " cves=" + std::to_string(cves.size()) + "\n";
    for(const Advisory &a : advisories) {
      section += "advisory id=" + a.id + " severity=" + a.severity;
      if(!a.issued.empty()) section += " issued=" + a.issued;
      section += " cves=" + JoinSet(a.cves);
      section += " packages=" + JoinSet(a.packages);
      section += " title=" + QuoteValue(a.title) + "\n";
    }
  }
  WriteWholeFile(JoinPath(cfg.data_dir, SCAN_VULN_FILE), section, 0600);
  output += "Vulnerability scan (" + source + ") finished in " + std::to_string((long long)(time(NULL) - start)) +
    " seconds" + (rv == 0 ? ", " + std::to_string(advisories.size()) + " advisories apply" : ", failed") + "\n";

  std::string comp_file = JoinPath(cfg.data_dir, SCAN_COMPLIANCE_FILE);
  if(!cfg.compliance_profile.empty()) {
    std::string comp;
    if(ScanCompliance(cfg, comp, output) == 0) {
      WriteWholeFile(comp_file, comp, 0600);
      output += "Compliance scan (" + cfg.compliance_profile + ") finished\n";
    }
  }
  else {
    unlink(comp_file.c_str());
  }
  return rv;
}

std::string ScanReportSections(const AgentConfig &cfg)
{
  std::string out, data;
  if(!cfg.scan_enabled) {
    out += "VULNERABILITIES:\nstatus=disabled\nEND VULNERABILITIES\n\n";
  }
  else if(ReadWholeFile(JoinPath(cfg.data_dir, SCAN_VULN_FILE), data)) {
    out += "VULNERABILITIES:\n" + data + "END VULNERABILITIES\n\n";
  }
  else {
    out += "VULNERABILITIES:\nstatus=pending\nEND VULNERABILITIES\n\n";
  }
  if(!cfg.compliance_profile.empty() && ReadWholeFile(JoinPath(cfg.data_dir, SCAN_COMPLIANCE_FILE), data)) {
    out += "COMPLIANCE:\n" + data + "END COMPLIANCE\n\n";
  }
  return out;
}

std::vector<FormFile> PendingScanHtml(const AgentConfig &cfg, const std::string &hostname)
{
  std::vector<FormFile> files;
  if(!cfg.scan_upload_html) return files;
  const char *names[2][3] = {
    { SCAN_VULN_HTML, "scapReport", AGENT_SCAP_SUFFIX },
    { SCAN_COMPLIANCE_HTML, "complianceReport", "_linux_compliance_report.html" }
  };
  for(int i = 0; i < 2; i++) {
    std::string html = JoinPath(cfg.data_dir, names[i][0]);
    if(!FileExists(html + SCAN_HTML_PENDING)) continue;
    FormFile f;
    if(!ReadWholeFile(html, f.content) || f.content.empty()) continue;
    f.field = names[i][1];
    f.file_name = hostname + names[i][2];
    f.content_type = "text/html";
    files.push_back(f);
  }
  return files;
}

void ClearPendingScanHtml(const AgentConfig &cfg)
{
  unlink((JoinPath(cfg.data_dir, SCAN_VULN_HTML) + SCAN_HTML_PENDING).c_str());
  unlink((JoinPath(cfg.data_dir, SCAN_COMPLIANCE_HTML) + SCAN_HTML_PENDING).c_str());
}
