#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <vector>
#include <map>

#define AGENT_NAME "DataReel Reporting Agent for Linux"
#define AGENT_VERSION "1.0-beta1"
#define AGENT_INI_FILE "/etc/drra/drra.ini"
#define AGENT_REPORT_SUFFIX "_linux_report_agent.txt"
#define AGENT_SCAP_SUFFIX "_linux_scap_report.html"

// Agent settings, loaded from AGENT_INI_FILE, or the file given with -c.
// Any setting missing from the INI file keeps its default.
struct AgentConfig {
  // [delivery]
  std::vector<std::string> delivery_methods; // methods: https, cifs, scp
  // [https]
  std::string server_host;        // host
  int server_port;                // port
  std::string upload_path;        // upload_path
  std::string register_path;      // register_path
  std::string enrollment_token;   // enrollment_token
  bool use_https;                 // use_https
  bool verify_peer;               // verify_peer: check the server certificate
  std::string ca_file;            // ca_file: CA bundle for a private CA
  int https_timeout_seconds;      // timeout_seconds
  // [cifs]
  std::string cifs_share;         // share: //server/share
  std::string cifs_directory;     // directory inside the share
  std::string cifs_credentials;   // credentials_file (smbclient -A format)
  std::string smbclient_path;     // smbclient_path
  int cifs_timeout_seconds;       // timeout_seconds
  // [scp]
  std::string scp_host;           // host
  int scp_port;                   // port
  std::string scp_user;           // user
  std::string scp_key_file;       // key_file
  std::string scp_remote_dir;     // remote_dir
  std::string scp_path;           // scp_path
  std::string scp_known_hosts;    // known_hosts_file
  std::string scp_host_key_check; // strict_host_key_checking
  int scp_timeout_seconds;        // timeout_seconds
  // [agent]
  int report_interval_minutes;    // report_interval_minutes
  int cpu_sample_seconds;         // cpu_sample_seconds
  std::string report_dir;         // report_dir
  std::string log_file;           // log_file
  std::string data_dir;           // data_dir: agent key, certificate, registration and scan state
  bool check_updates;             // check_updates: pending dnf/yum updates
  int updates_refresh_hours;      // updates_refresh_hours: how often the package metadata is refreshed
  int command_timeout_seconds;    // command_timeout_seconds
  // [scan]
  bool scan_enabled;              // enabled
  int scan_interval_hours;        // interval_hours
  std::string scan_source;        // source: auto, oval, dnf
  std::string oval_feed_url;      // oval_feed_url, empty picks Red Hat's feed for the host's release
  std::string oscap_path;         // oscap_path
  bool scan_upload_html;          // upload_html
  std::string compliance_profile; // compliance_profile, empty = no compliance scan
  std::string compliance_datastream; // compliance_datastream, empty picks the SCAP Security Guide file
  int scan_timeout_minutes;       // timeout_minutes
  // Full path of the INI file that was read
  std::string ini_path;
};

// Result of a command run with RunCommand
struct CommandResult {
  int exit_code;      // exit status, -1 when it could not run or was killed
  bool timed_out;
  std::string out;    // standard output
  std::string err;    // standard error
};

void SetDefaultAgentConfig(AgentConfig &cfg);
int LoadAgentConfig(AgentConfig &cfg, const std::string &ini_path, std::string &output);

std::string JoinPath(const std::string &dir, const std::string &name);
std::string Trim(const std::string &s);
std::string ToLower(std::string s);
std::vector<std::string> Split(const std::string &s, char sep);
bool StartsWith(const std::string &s, const std::string &prefix);
bool ReadWholeFile(const std::string &fname, std::string &data);
bool WriteWholeFile(const std::string &fname, const std::string &data, int mode = 0644);
bool CreateDirTree(const std::string &dir, int mode = 0755);
bool FileExists(const std::string &fname);
long long FileMtime(const std::string &fname);
std::string FormatPct(double pct);
std::string QuoteValue(const std::string &s);
std::string NowText();
std::string GetAgentHostname();
std::map<std::string, std::string> ReadOsRelease();
int OsMajorVersion();

int RunCommand(const std::vector<std::string> &argv, int timeout_seconds, CommandResult &result,
               const std::vector<std::string> &extra_env = std::vector<std::string>());
std::string FindProgram(const std::string &name);

void LogMessage(const AgentConfig &cfg, const std::string &message);

#endif
