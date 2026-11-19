#ifndef COMMON_H
#define COMMON_H

#include <string>
#include <vector>
#include <map>

#define AGENT_NAME "DataReel Reporting Agent for Linux"
#define AGENT_VERSION "1.1.3"
#define AGENT_INI_FILE "/etc/drra/drra.ini"

// Build variants (set by the RPM spec on RHEL 8):
//   DRRA_BUNDLED_OPENSSL  linux_reporting_agent-openssl35: static OpenSSL 3.5
//                         and libcurl built in, follows the crypto policy
//                         (cryptopolicy.cpp), hybrid post-quantum key
//                         exchange, no FIPS mode
//   DRRA_FIPS_BUILD       linux_reporting_agent on RHEL 8: RHEL 8's own
//                         OpenSSL 1.1.1 and libcurl, so crypto-policies and
//                         FIPS mode apply
//   neither               the system OpenSSL and libcurl (RHEL 9 and 10)
#if defined(DRRA_BUNDLED_OPENSSL)
#define AGENT_BUILD_VARIANT "openssl35 (bundled OpenSSL 3.5, follows the crypto policy)"
// The crypto policy and OpenSSL 3.5 pick the groups (cryptopolicy.cpp):
// X25519MLKEM768 first unless the policy is FIPS
#define AGENT_TLS_GROUPS_DEFAULT ""
#elif defined(DRRA_FIPS_BUILD)
#define AGENT_BUILD_VARIANT "FIPS (system OpenSSL)"
#define AGENT_TLS_GROUPS_DEFAULT ""
#else
#define AGENT_BUILD_VARIANT "system OpenSSL"
#define AGENT_TLS_GROUPS_DEFAULT ""
#endif
// Exit status when the standard build refuses to run in FIPS mode; the
// systemd unit does not restart on it (RestartPreventExitStatus)
#define AGENT_EXIT_FIPS_REFUSED 78
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
  std::string hook_path;          // hook_path: hook uploads, empty = hook.php next to upload_path
  std::string register_path;      // register_path
  std::string enrollment_token;   // enrollment_token
  bool use_https;                 // use_https
  bool verify_peer;               // verify_peer: check the server certificate
  std::string ca_file;            // ca_file: CA bundle for a private CA
  std::string tls_groups;         // tls_groups: TLS key exchange groups, empty = OpenSSL/crypto policy
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
  std::string scan_source;        // source: auto, oval, csaf, dnf
  std::string oval_feed_url;      // oval_feed_url, empty picks Red Hat's feed for the host's release
  std::string csaf_index_url;     // csaf_index_url, empty = vex_index.php next to the upload page
  std::string unfixed_list_severity; // unfixed_list_severity: list unfixed CVEs at or above this
  std::string oscap_path;         // oscap_path
  bool scan_upload_html;          // upload_html
  std::string compliance_profile; // compliance_profile, empty = no compliance scan
  std::string compliance_datastream; // compliance_datastream, empty picks the SCAP Security Guide file
  int scan_timeout_minutes;       // timeout_minutes
  // [hooks]
  bool hooks_enabled;             // enabled
  std::string hooks_dir;          // dir: report hook scripts
  int hooks_timeout_seconds;      // timeout_seconds, for each hook
  int hooks_max_output_kb;        // max_output_kb, for each hook
  std::string hooks_user;         // user: run the hooks as this user, empty = root
  // [uploads] hook uploads
  bool uploads_enabled;           // enabled
  std::string uploads_dir;        // dir: one <id>.ini per upload hook
  std::string uploads_spool_dir;  // spool_dir: <spool_dir>/<id>/ takes the files
  long long uploads_max_bytes;    // max_bytes: largest file, an upload hook may set less
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

// User a command runs as, see RunCommand
struct RunAsUser {
  unsigned int uid;
  unsigned int gid;
  std::string name;
  std::string home;
};

int RunCommand(const std::vector<std::string> &argv, int timeout_seconds, CommandResult &result,
               const std::vector<std::string> &extra_env = std::vector<std::string>(),
               const RunAsUser *run_as = NULL);
std::string FindProgram(const std::string &name);

void LogMessage(const AgentConfig &cfg, const std::string &message);
bool HostFipsEnabled();

#endif
