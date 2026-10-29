// DataReel Reporting Agent for Linux
//
// Writes a report about this host (system, resource use, disks, network,
// users, security settings, pending updates, vulnerabilities and
// installed packages) every report_interval_minutes and sends it to the
// report server with the methods in /etc/drra/drra.ini. The server and
// DataReel System Monitor (DRSM) read the report. Nothing connects to
// the host, so it can be monitored over the internet from behind NAT.

// C STD lib includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

// C++ STD lib includes
#include <string>
#include <vector>

// Libraries
#include <curl/curl.h>
#include <libxml/parser.h>

// APP includes
#include "common.h"
#include "agent_auth.h"
#include "collect.h"
#include "deliver.h"
#include "scan.h"

static volatile sig_atomic_t g_stop = 0;
static volatile sig_atomic_t g_wake = 0;

static void OnSignal(int sig)
{
  if(sig == SIGHUP) g_wake = 1;
  else g_stop = 1;
}

static void Usage()
{
  printf("%s %s\n\n", AGENT_NAME, AGENT_VERSION);
  printf("Usage: drra [-c ini_file] command\n\n");
  printf("Commands:\n");
  printf("  run          run as a service: report every report_interval_minutes (systemd uses this)\n");
  printf("  once         write and send one report, scanning first when a scan is due\n");
  printf("  report       print a report to standard output, nothing is sent\n");
  printf("  scan         run the vulnerability (and compliance) scan now\n");
  printf("  register     register the agent certificate with the report server\n");
  printf("  fingerprint  print the agent key fingerprint to check on the admin page\n");
  printf("  config       print the settings in use\n");
  printf("  version      print the version\n\n");
  printf("Settings: %s\n", AGENT_INI_FILE);
}

//
// Purpose:
//   Writes the report to report_dir and delivers it
//
// Return value:
//   0 when the report was written and every delivery method worked
//
static int ReportCycle(const AgentConfig &cfg, std::string &output)
{
  std::string hostname = GetAgentHostname();
  std::string report = BuildReport(cfg, output);
  if(!CreateDirTree(cfg.report_dir, 0700)) {
    output += "ERROR - Cannot create report directory " + cfg.report_dir + "\n";
    return -1;
  }
  std::string report_file = JoinPath(cfg.report_dir, hostname + AGENT_REPORT_SUFFIX);
  if(!WriteWholeFile(report_file, report, 0600)) {
    output += "ERROR - Could not write " + report_file + "\n";
    return -1;
  }

  std::vector<FormFile> html_files = PendingScanHtml(cfg, hostname);
  int rv = DeliverReport(cfg, report_file, report, hostname, html_files, output);
  if(html_files.empty()) ClearPendingScanHtml(cfg);
  if(rv != 0) output += "ERROR - One or more report delivery methods failed\n";
  return rv;
}

static int RunOnce(const AgentConfig &cfg)
{
  std::string output;
  if(ScanDue(cfg)) RunScan(cfg, output);
  int rv = ReportCycle(cfg, output);
  LogMessage(cfg, output);
  return rv == 0 ? 0 : 1;
}

static int RunService(const std::string &ini_path)
{
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = OnSignal;
  sigaction(SIGTERM, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGHUP, &sa, NULL);

  AgentConfig cfg;
  std::string output;
  LoadAgentConfig(cfg, ini_path, output);
  LogMessage(cfg, output + AGENT_NAME " " AGENT_VERSION " started, reporting every " +
	     std::to_string(cfg.report_interval_minutes) + " minutes");

  while(!g_stop) {
    // Settings are read again every cycle, a changed INI file needs no restart
    output.clear();
    LoadAgentConfig(cfg, ini_path, output);
    time_t start = time(NULL);
    ReportCycle(cfg, output);
    LogMessage(cfg, output);

    // A scan runs after the report, so a long scan never delays the
    // check in, and its results go out right away in a second report
    if(!g_stop && ScanDue(cfg)) {
      output.clear();
      RunScan(cfg, output);
      if(!g_stop) ReportCycle(cfg, output);
      LogMessage(cfg, output);
    }

    time_t next = start + (time_t)cfg.report_interval_minutes * 60;
    g_wake = 0;
    while(!g_stop && !g_wake && time(NULL) < next) sleep(1);
  }
  LogMessage(cfg, AGENT_NAME " stopped");
  return 0;
}

int main(int argc, char **argv)
{
  std::string ini_path = AGENT_INI_FILE;
  int opt;
  while((opt = getopt(argc, argv, "c:hV")) != -1) {
    switch(opt) {
      case 'c': ini_path = optarg; break;
      case 'V': printf("%s\n", AGENT_VERSION); return 0;
      default: Usage(); return opt == 'h' ? 0 : 2;
    }
  }
  std::string command = (optind < argc) ? argv[optind] : "";
  if(command.empty() || command == "help") {
    Usage();
    return command.empty() ? 2 : 0;
  }
  if(command == "version") {
    printf("%s %s\n", AGENT_NAME, AGENT_VERSION);
    return 0;
  }

  // Files the agent writes are private to root
  umask(077);
  curl_global_init(CURL_GLOBAL_DEFAULT);
  xmlInitParser();

  AgentConfig cfg;
  std::string output;
  LoadAgentConfig(cfg, ini_path, output);
  int rv = 0;

  if(command == "run") {
    rv = RunService(ini_path);
  }
  else if(command == "once") {
    if(!output.empty()) fputs(output.c_str(), stderr);
    rv = RunOnce(cfg);
  }
  else if(command == "report") {
    std::string report = BuildReport(cfg, output);
    fputs(report.c_str(), stdout);
    if(!output.empty()) fputs(output.c_str(), stderr);
  }
  else if(command == "scan") {
    rv = RunScan(cfg, output) == 0 ? 0 : 1;
    fputs(output.c_str(), stdout);
    fputs(ScanReportSections(cfg).c_str(), stdout);
  }
  else if(command == "register") {
    AgentIdentity id;
    if(LoadOrCreateAgentIdentity(cfg, id, output) != 0) {
      rv = 1;
    }
    else {
      std::string status;
      std::string server_id = cfg.server_host + ":" + std::to_string(cfg.server_port) + cfg.register_path;
      if(RegisterAgent(cfg, id, status, output) == 0) {
	WriteRegistrationState(cfg, status + " " + id.key_fingerprint + " " + server_id);
	output += "Host " + id.hostname + ", key fingerprint " + id.key_fingerprint + "\n";
	rv = status == "approved" ? 0 : 1;
      }
      else {
	rv = 1;
      }
      FreeAgentIdentity(id);
    }
    fputs(output.c_str(), stdout);
  }
  else if(command == "fingerprint") {
    AgentIdentity id;
    if(LoadOrCreateAgentIdentity(cfg, id, output) == 0) {
      printf("%s", output.c_str());
      printf("Host: %s\nKey fingerprint: %s\nRegistration: %s\n", id.hostname.c_str(), id.key_fingerprint.c_str(),
	     ReadRegistrationState(cfg).c_str());
      FreeAgentIdentity(id);
    }
    else {
      fputs(output.c_str(), stderr);
      rv = 1;
    }
  }
  else if(command == "config") {
    if(!output.empty()) fputs(output.c_str(), stderr);
    std::string methods;
    for(const std::string &m : cfg.delivery_methods) methods += (methods.empty() ? "" : ",") + m;
    printf("ini_file=%s\n", cfg.ini_path.c_str());
    printf("[delivery] methods=%s\n", methods.c_str());
    printf("[https] host=%s port=%d upload_path=%s register_path=%s use_https=%d verify_peer=%d enrollment_token=%s\n",
	   cfg.server_host.c_str(), cfg.server_port, cfg.upload_path.c_str(), cfg.register_path.c_str(),
	   cfg.use_https, cfg.verify_peer, cfg.enrollment_token.empty() ? "(not set)" : "(set)");
    printf("[cifs] share=%s directory=%s credentials_file=%s\n", cfg.cifs_share.c_str(), cfg.cifs_directory.c_str(),
	   cfg.cifs_credentials.c_str());
    printf("[scp] host=%s port=%d user=%s remote_dir=%s\n", cfg.scp_host.c_str(), cfg.scp_port, cfg.scp_user.c_str(),
	   cfg.scp_remote_dir.c_str());
    printf("[agent] report_interval_minutes=%d report_dir=%s data_dir=%s log_file=%s check_updates=%d\n",
	   cfg.report_interval_minutes, cfg.report_dir.c_str(), cfg.data_dir.c_str(), cfg.log_file.c_str(), cfg.check_updates);
    printf("[scan] enabled=%d interval_hours=%d source=%s oval_feed_url=%s compliance_profile=%s\n",
	   cfg.scan_enabled, cfg.scan_interval_hours, cfg.scan_source.c_str(), cfg.oval_feed_url.c_str(),
	   cfg.compliance_profile.c_str());
  }
  else {
    Usage();
    rv = 2;
  }

  xmlCleanupParser();
  curl_global_cleanup();
  return rv;
}
