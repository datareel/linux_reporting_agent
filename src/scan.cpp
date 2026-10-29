// C STD lib includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

// C++ STD lib includes
#include <string>
#include <vector>
#include <map>
#include <set>
#include <sstream>
#include <algorithm>

// Libraries
#include <bzlib.h>
#include <zlib.h>
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

// A CVE Red Hat lists as affecting an installed package, with no fix yet
struct Unfixed {
  std::string cve;
  std::string severity;
  std::string state;                 // Affected, Fix deferred, Will not fix, Out of support scope
  std::set<std::string> packages;
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
//   Downloads url to download when the server has a newer copy
//   (If-Modified-Since against the file time of the last download)
//
// Parameters:
//   have_copy - a usable earlier copy exists, a failed download keeps it
//   report_server - the url is on the report server: use its
//                   verify_peer and ca_file settings
//   changed - set when a new copy was saved
//
// Return value:
//   0 when download holds a usable copy
//
static int DownloadIfChanged(const AgentConfig &cfg, const std::string &url, const std::string &download,
			     bool have_copy, bool report_server, bool &changed, std::string &output)
{
  changed = false;
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
  if(report_server) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, cfg.verify_peer ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, cfg.verify_peer ? 2L : 0L);
    if(!cfg.ca_file.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, cfg.ca_file.c_str());
  }
  if(last > 0 && have_copy) {
    curl_easy_setopt(curl, CURLOPT_TIMECONDITION, (long)CURL_TIMECOND_IFMODSINCE);
    curl_easy_setopt(curl, CURLOPT_TIMEVALUE, last);
  }
  CURLcode rc = curl_easy_perform(curl);
  long http = 0, filetime = -1, unmet = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
  curl_easy_getinfo(curl, CURLINFO_FILETIME, &filetime);
  curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &unmet);
  curl_easy_cleanup(curl);
  fclose(fp);

  if(rc != CURLE_OK || (http != 200 && http != 304)) {
    unlink(tmp.c_str());
    std::string why = (rc != CURLE_OK) ? std::string(errbuf[0] ? errbuf : curl_easy_strerror(rc)) : "HTTP " + std::to_string(http);
    if(have_copy) {
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
    struct timespec ts[2];
    ts[0].tv_sec = ts[1].tv_sec = (time_t)filetime;
    ts[0].tv_nsec = ts[1].tv_nsec = 0;
    utimensat(AT_FDCWD, download.c_str(), ts, 0);
  }
  output += "Downloaded " + url + "\n";
  changed = true;
  return 0;
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
    bool changed = false;
    if(DownloadIfChanged(cfg, url, download, FileExists(feed_xml), false, changed, output) != 0) return -1;
    if(changed && bz2) unlink(feed_xml.c_str());
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

//
// Purpose:
//   Compares two RPM version or release strings the way rpm does
//   (rpmvercmp): digit and letter runs in turn, ~ sorts before
//   anything, ^ after the end
//
// Return value:
//   -1, 0 or 1
//
static int RpmVerCmp(const std::string &a, const std::string &b)
{
  if(a == b) return 0;
  size_t i = 0, j = 0;
  while(i < a.length() || j < b.length()) {
    while(i < a.length() && !isalnum((unsigned char)a[i]) && a[i] != '~' && a[i] != '^') i++;
    while(j < b.length() && !isalnum((unsigned char)b[j]) && b[j] != '~' && b[j] != '^') j++;
    // Tilde: a pre-release, older than anything, even the end
    if((i < a.length() && a[i] == '~') || (j < b.length() && b[j] == '~')) {
      if(i >= a.length() || a[i] != '~') return 1;
      if(j >= b.length() || b[j] != '~') return -1;
      i++; j++;
      continue;
    }
    // Caret: a post-release, newer than the end, older than more segments
    if((i < a.length() && a[i] == '^') || (j < b.length() && b[j] == '^')) {
      if(i >= a.length()) return -1;
      if(j >= b.length()) return 1;
      if(a[i] != '^') return 1;
      if(b[j] != '^') return -1;
      i++; j++;
      continue;
    }
    if(i >= a.length() || j >= b.length()) break;
    size_t si = i, sj = j;
    bool num = isdigit((unsigned char)a[i]);
    if(num) {
      while(i < a.length() && isdigit((unsigned char)a[i])) i++;
      while(j < b.length() && isdigit((unsigned char)b[j])) j++;
    }
    else {
      while(i < a.length() && isalpha((unsigned char)a[i])) i++;
      while(j < b.length() && isalpha((unsigned char)b[j])) j++;
    }
    std::string x = a.substr(si, i - si), y = b.substr(sj, j - sj);
    // A number is newer than letters
    if(y.empty()) return num ? 1 : -1;
    if(num) {
      x.erase(0, std::min(x.find_first_not_of('0'), x.length()));
      y.erase(0, std::min(y.find_first_not_of('0'), y.length()));
      if(x.length() != y.length()) return x.length() > y.length() ? 1 : -1;
    }
    int c = x.compare(y);
    if(c != 0) return c > 0 ? 1 : -1;
  }
  if(i >= a.length() && j >= b.length()) return 0;
  return i >= a.length() ? -1 : 1;
}

// Compares epoch:version-release strings
int RpmEvrCmp(const std::string &a, const std::string &b)
{
  auto split = [](const std::string &evr, long &e, std::string &v, std::string &r) {
    size_t c = evr.find(':');
    e = (c == std::string::npos) ? 0 : atol(evr.substr(0, c).c_str());
    std::string vr = (c == std::string::npos) ? evr : evr.substr(c + 1);
    size_t d = vr.rfind('-');
    v = (d == std::string::npos) ? vr : vr.substr(0, d);
    r = (d == std::string::npos) ? "" : vr.substr(d + 1);
  };
  long ea, eb;
  std::string va, vb, ra, rb;
  split(a, ea, va, ra);
  split(b, eb, vb, rb);
  if(ea != eb) return ea > eb ? 1 : -1;
  int c = RpmVerCmp(va, vb);
  if(c != 0) return c;
  return RpmVerCmp(ra, rb);
}

// The index URL: csaf_index_url, else vex_index.php next to the upload page
static std::string CsafIndexUrl(const AgentConfig &cfg, int major)
{
  std::string url = cfg.csaf_index_url;
  if(url.empty()) {
    bool https = false;
    for(const std::string &m : cfg.delivery_methods) if(m == "https") https = true;
    if(!https || cfg.server_host.empty() || cfg.server_host == "reports.example.com") return std::string();
    std::string dir = cfg.upload_path.substr(0, cfg.upload_path.rfind('/') + 1);
    url = std::string(cfg.use_https ? "https://" : "http://") + cfg.server_host + ":" + std::to_string(cfg.server_port) +
      dir + "vex_index.php";
  }
  if(url.find("{major}") != std::string::npos) {
    url.replace(url.find("{major}"), 7, std::to_string(major));
  }
  else if(url.find(".php") != std::string::npos && url.find('?') == std::string::npos) {
    url += "?rhel=" + std::to_string(major);
  }
  return url;
}

struct InstalledPackage {
  std::string evr;                   // newest installed epoch:version-release
  std::string source;                // source package name
};

static std::map<std::string, InstalledPackage> InstalledPackages(const AgentConfig &cfg)
{
  std::map<std::string, InstalledPackage> pkgs;
  CommandResult r;
  RunCommand({ FindProgram("rpm"), "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\n" },
	     cfg.command_timeout_seconds, r);
  for(const std::string &line : Split(r.out, '\n')) {
    std::vector<std::string> f = Split(line, '\t');
    if(f.size() < 3 || f[0] == "gpg-pubkey") continue;
    // openssl-3.5.8-2.el10_2.src.rpm -> openssl
    std::string src = f[2];
    for(int k = 0; k < 3 && !src.empty(); k++) {
      size_t d = (k == 0) ? src.rfind(".src.rpm") : src.rfind('-');
      if(d == std::string::npos) break;
      src = src.substr(0, d);
    }
    InstalledPackage &p = pkgs[f[0]];
    // Two versions (kernels): the newest counts
    if(p.evr.empty() || RpmEvrCmp(f[1], p.evr) > 0) {
      p.evr = f[1];
      p.source = src;
    }
  }
  return pkgs;
}

//
// Purpose:
//   Checks the installed packages against the VEX index the report
//   server builds from Red Hat's CSAF/VEX files (php/vex_sync.php)
//
// Return value:
//   0 on success
//
static int ScanCsaf(const AgentConfig &cfg, std::vector<Advisory> &advisories, std::vector<Unfixed> &unfixed,
		    std::string &feed, std::string &output)
{
  std::map<std::string, std::string> os = ReadOsRelease();
  std::string ver = os["VERSION_ID"];
  int major = atoi(ver.c_str());
  int minor = (ver.find('.') != std::string::npos) ? atoi(ver.substr(ver.find('.') + 1).c_str()) : 0;
  feed = CsafIndexUrl(cfg, major);
  if(feed.empty()) {
    output += "ERROR - [scan] source=csaf needs csaf_index_url, or https delivery to a report server\n";
    return -1;
  }
  std::string dir = JoinPath(cfg.data_dir, "csaf");
  CreateDirTree(dir, 0700);
  std::string index = JoinPath(dir, "vex_rhel" + std::to_string(major) + ".tsv.gz");
  bool changed = false;
  if(StartsWith(feed, "/")) index = feed;
  else if(DownloadIfChanged(cfg, feed, index, FileExists(index), true, changed, output) != 0) return -1;

  std::map<std::string, InstalledPackage> pkgs = InstalledPackages(cfg);
  std::set<std::string> sources;
  for(const auto &kv : pkgs) sources.insert(kv.second.source);

  gzFile gz = gzopen(index.c_str(), "rb");
  if(!gz) {
    output += "ERROR - Cannot read " + index + "\n";
    return -1;
  }
  // Fixed lines per CVE and package: the stream to compare with is the
  // host's minor release, or the newest one before it
  struct Fix { int minor; std::string evr, rhsa, severity; };
  std::map<std::pair<std::string, std::string>, std::vector<Fix> > fixes;
  std::map<std::string, Unfixed> open;
  bool header = false;
  char buf[8192];
  while(gzgets(gz, buf, sizeof(buf))) {
    std::string line = buf;
    while(!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.pop_back();
    if(StartsWith(line, "# DataReel Reporting Agent VEX index")) header = true;
    if(line.empty() || line[0] == '#') continue;
    std::vector<std::string> f = Split(line, '\t');
    if(f[0] == "F" && f.size() >= 8 && atoi(f[4].c_str()) == major && pkgs.count(f[3])) {
      Fix x = { atoi(f[5].c_str()), f[6], f[7], f[2] };
      fixes[std::make_pair(f[1], f[3])].push_back(x);
    }
    else if(f[0] == "U" && f.size() >= 6 && atoi(f[4].c_str()) == major && (pkgs.count(f[3]) || sources.count(f[3]))) {
      Unfixed &u = open[f[1]];
      u.cve = f[1];
      u.severity = NormalSeverity(f[2]);
      u.state = f[5];
      u.packages.insert(f[3]);
    }
  }
  gzclose(gz);
  if(!header) {
    output += "ERROR - " + feed + " is not a VEX index from vex_sync.php\n";
    unlink(index.c_str());
    return -1;
  }

  std::map<std::string, Advisory> by_id;
  for(auto &kv : fixes) {
    const std::string &cve = kv.first.first, &name = kv.first.second;
    const Fix *use = NULL;
    for(const Fix &x : kv.second) {
      if(x.minor <= minor && (!use || x.minor > use->minor)) use = &x;
    }
    // A host older than every stream with a fix: the oldest fix
    if(!use) for(const Fix &x : kv.second) if(!use || x.minor < use->minor) use = &x;
    if(RpmEvrCmp(pkgs[name].evr, use->evr) >= 0) continue;
    std::string id = use->rhsa.empty() ? cve : use->rhsa;
    Advisory &a = by_id[id];
    a.id = id;
    if(a.severity.empty() || SeverityRank(NormalSeverity(use->severity)) < SeverityRank(a.severity)) {
      a.severity = NormalSeverity(use->severity);
    }
    a.cves.insert(cve);
    a.packages.insert(name + "<" + use->evr);
  }
  for(auto &kv : by_id) {
    Advisory &a = kv.second;
    // VEX names the RHSA, not its title; name the packages it fixes
    std::set<std::string> names;
    for(const std::string &p : a.packages) names.insert(p.substr(0, p.find('<')));
    std::string list;
    int n = 0;
    for(const std::string &nm : names) if(n++ < 3) list += (list.empty() ? "" : ", ") + nm;
    if(names.size() > 3) list += " and " + std::to_string(names.size() - 3) + " more";
    a.title = a.severity + ": " + list + " security update";
    advisories.push_back(a);
  }
  // A CVE with a pending fix for one package is not also "unfixed" for it
  for(auto &kv : open) {
    bool fixed_too = false;
    for(const Advisory &a : advisories) if(a.cves.count(kv.first)) fixed_too = true;
    if(!fixed_too) unfixed.push_back(kv.second);
  }
  std::sort(unfixed.begin(), unfixed.end(), [](const Unfixed &a, const Unfixed &b) {
      if(SeverityRank(a.severity) != SeverityRank(b.severity)) return SeverityRank(a.severity) < SeverityRank(b.severity);
      return a.cve > b.cve;
    });
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
  std::map<std::string, std::string> os = ReadOsRelease();
  int major = atoi(os["VERSION_ID"].c_str());
  if(source == "auto") {
    // RHEL 10 has no OVAL feed: the report server's CSAF/VEX index when
    // there is a report server, dnf otherwise
    if(!url.empty()) source = "oval";
    else if(os["ID"] == "rhel" && major >= 10 && !CsafIndexUrl(cfg, major).empty()) source = "csaf";
    else source = "dnf";
  }
  if(source == "oval" && url.empty()) {
    output += "ERROR - [scan] source=oval needs oval_feed_url, Red Hat has no OVAL feed for this release\n";
    source = "dnf";
  }

  time_t start = time(NULL);
  std::vector<Advisory> advisories;
  std::vector<Unfixed> unfixed;
  std::string feed = (source == "oval") ? url : std::string("dnf updateinfo");
  int rv;
  if(source == "oval") {
    rv = ScanOval(cfg, url, advisories, output);
  }
  else if(source == "csaf") {
    rv = ScanCsaf(cfg, advisories, unfixed, feed, output);
    // Without the index, dnf still lists the advisories with fixes
    if(rv != 0 && cfg.scan_source == "auto") {
      output += "WARNING - CSAF/VEX scan failed, using dnf updateinfo\n";
      advisories.clear();
      unfixed.clear();
      source = "dnf";
      feed = "dnf updateinfo";
      rv = ScanDnf(cfg, advisories, output);
    }
  }
  else {
    rv = ScanDnf(cfg, advisories, output);
  }

  std::string section = "source=" + source + "\n";
  section += "feed=" + feed + "\n";
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
      " cves=" + std::to_string(cves.size()) + " unfixed=" + std::to_string(unfixed.size()) + "\n";
    for(const Advisory &a : advisories) {
      section += "advisory id=" + a.id + " severity=" + a.severity;
      if(!a.issued.empty()) section += " issued=" + a.issued;
      section += " cves=" + JoinSet(a.cves);
      section += " packages=" + JoinSet(a.packages);
      section += " title=" + QuoteValue(a.title) + "\n";
    }
    // Known vulnerabilities with no update yet (CSAF/VEX only)
    for(const Unfixed &u : unfixed) {
      section += "unfixed cve=" + u.cve + " severity=" + u.severity + " packages=" + JoinSet(u.packages) +
	" state=" + QuoteValue(u.state) + "\n";
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
