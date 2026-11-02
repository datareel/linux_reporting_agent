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
#include "hooks.h"
#include "uploads.h"

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
  printf("  scan [--no-send]\n");
  printf("               run the vulnerability (and compliance) scan now and send a report\n");
  printf("               with it; --no-send only prints the results\n");
  printf("  hooks        run the report hooks and print their HOOKS section\n");
  printf("  submit --hook <id> [--now] <file>\n");
  printf("               queue a report from another tool for upload hook <id> (%s/<id>.ini);\n", AGENT_UPLOADS_DIR_TEXT);
  printf("               --now asks the running service to send it right away\n");
  printf("  send-uploads send the queued upload files now, without a report\n");
  printf("  uploads      list the upload hooks and their state\n");
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
  // Reports from other sources (hook uploads) go out after the agent's own report
  if(SendPendingUploads(cfg, output) != 0) {
    output += "ERROR - One or more upload files could not be sent\n";
    if(rv == 0) rv = -1;
  }
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
    while(!g_stop && !g_wake && time(NULL) < next) {
      sleep(1);
      // "drra submit --now": send the queued upload files without a report
      if(UploadSendNowRequested(cfg)) {
	output.clear();
	SendPendingUploads(cfg, output);
	LogMessage(cfg, output);
      }
    }
  }
  LogMessage(cfg, AGENT_NAME " stopped");
  return 0;
}

int main(int argc, char **argv)
{
  std::string ini_path = AGENT_INI_FILE;
  int opt;
  while((opt = getopt(argc, argv, "+c:hV")) != -1) {
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
    // A scan by hand: run it, then send a report so the dashboard has it
    // now. --no-send only prints the results.
    bool send = !(optind + 1 < argc && strcmp(argv[optind + 1], "--no-send") == 0);
    rv = RunScan(cfg, output) == 0 ? 0 : 1;
    fputs(output.c_str(), stdout);
    fputs(ScanReportSections(cfg).c_str(), stdout);
    if(send) {
      output.clear();
      if(ReportCycle(cfg, output) != 0) rv = 1;
      // Logged, and shown on the terminal by LogMessage
      LogMessage(cfg, "Report sent after drra scan\n" + output);
    }
  }
  else if(command == "hooks") {
    fputs(HookReportSection(cfg, output).c_str(), stdout);
    if(!output.empty()) fputs(output.c_str(), stderr);
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
  else if(command == "submit") {
    // submit --hook <id> [--now] <file>, options in any order after the command
    std::string hook_id, file;
    bool now = false;
    for(int i = optind + 1; i < argc; i++) {
      std::string a = argv[i];
      if(a == "--hook" && i + 1 < argc) hook_id = argv[++i];
      else if(a.compare(0, 7, "--hook=") == 0) hook_id = a.substr(7);
      else if(a == "--now") now = true;
      else if(file.empty() && a.compare(0, 2, "--") != 0) file = a;
      else {
	fprintf(stderr, "Unknown option %s\n", a.c_str());
	return 2;
      }
    }
    if(hook_id.empty() || file.empty()) {
      fprintf(stderr, "Usage: drra submit --hook <id> [--now] <file>\n");
      return 2;
    }
    // Members of the drra-upload group may submit: their files are group readable
    umask(027);
    output.clear();
    rv = SubmitUploadFile(cfg, hook_id, file, now, output) == 0 ? 0 : 1;
    fputs(output.c_str(), rv == 0 ? stdout : stderr);
  }
  else if(command == "send-uploads") {
    output.clear();
    rv = SendPendingUploads(cfg, output) == 0 ? 0 : 1;
    // LogMessage prints it too
    LogMessage(cfg, output.empty() ? "No upload files waiting" : output);
  }
  else if(command == "uploads") {
    std::string section = UploadReportSection(cfg);
    output.clear();
    LoadUploadHooks(cfg, output);
    fputs(output.c_str(), stderr);
    if(section.empty()) printf("No upload hooks in %s\n", cfg.uploads_dir.c_str());
    else fputs(section.c_str(), stdout);
    printf("Hook page: %s\n", HookPagePath(cfg).c_str());
  }
  else if(command == "vercmp" && optind + 2 < argc) {
    // vercmp A B: how the CSAF scan compares package versions
    int c = RpmEvrCmp(argv[optind + 1], argv[optind + 2]);
    printf("%d\n", c);
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
    printf("[scan] enabled=%d interval_hours=%d source=%s oval_feed_url=%s csaf_index_url=%s compliance_profile=%s\n",
	   cfg.scan_enabled, cfg.scan_interval_hours, cfg.scan_source.c_str(), cfg.oval_feed_url.c_str(), cfg.csaf_index_url.c_str(),
	   cfg.compliance_profile.c_str());
    printf("[hooks] enabled=%d dir=%s timeout_seconds=%d max_output_kb=%d user=%s\n",
	   cfg.hooks_enabled, cfg.hooks_dir.c_str(), cfg.hooks_timeout_seconds, cfg.hooks_max_output_kb,
	   cfg.hooks_user.empty() ? "root" : cfg.hooks_user.c_str());
    printf("[uploads] enabled=%d dir=%s spool_dir=%s max_bytes=%lld hook_path=%s\n", cfg.uploads_enabled, cfg.uploads_dir.c_str(),
	   cfg.uploads_spool_dir.c_str(), cfg.uploads_max_bytes, HookPagePath(cfg).c_str());
  }
  else {
    Usage();
    rv = 2;
  }

  xmlCleanupParser();
  curl_global_cleanup();
  return rv;
}
