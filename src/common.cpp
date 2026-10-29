// C STD lib includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <grp.h>

// C++ STD lib includes
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <cctype>

// APP includes
#include "common.h"

extern char **environ;

void SetDefaultAgentConfig(AgentConfig &cfg)
{
  cfg.delivery_methods.clear();
  cfg.delivery_methods.push_back("https");
  cfg.server_host = "reports.example.com";
  cfg.server_port = 443;
  cfg.upload_path = "/linux/upload/upload.php";
  cfg.register_path = "/linux/upload/register.php";
  cfg.enrollment_token.clear();
  cfg.use_https = true;
  cfg.verify_peer = true;
  cfg.ca_file.clear();
  cfg.https_timeout_seconds = 60;

  cfg.cifs_share.clear();
  cfg.cifs_directory.clear();
  cfg.cifs_credentials = "/etc/drra/cifs_credentials";
  cfg.smbclient_path = "/usr/bin/smbclient";
  cfg.cifs_timeout_seconds = 120;

  cfg.scp_host.clear();
  cfg.scp_port = 22;
  cfg.scp_user.clear();
  cfg.scp_key_file = "/etc/drra/id_ed25519";
  cfg.scp_remote_dir.clear();
  cfg.scp_path = "/usr/bin/scp";
  cfg.scp_known_hosts = "/var/lib/drra/known_hosts";
  cfg.scp_host_key_check = "yes";
  cfg.scp_timeout_seconds = 120;

  cfg.report_interval_minutes = 15;
  cfg.cpu_sample_seconds = 5;
  cfg.report_dir = "/var/lib/drra";
  cfg.log_file = "/var/log/drra/drra.log";
  cfg.data_dir = "/var/lib/drra";
  cfg.check_updates = true;
  cfg.updates_refresh_hours = 24;
  cfg.command_timeout_seconds = 300;

  cfg.scan_enabled = false;
  cfg.scan_interval_hours = 24;
  cfg.scan_source = "auto";
  cfg.oval_feed_url.clear();
  cfg.csaf_index_url.clear();
  cfg.unfixed_list_severity = "Important";
  cfg.oscap_path = "/usr/bin/oscap";
  cfg.scan_upload_html = true;
  cfg.compliance_profile.clear();
  cfg.compliance_datastream.clear();
  cfg.scan_timeout_minutes = 60;

  cfg.hooks_enabled = true;
  cfg.hooks_dir = "/etc/drra/report.d";
  cfg.hooks_timeout_seconds = 60;
  cfg.hooks_max_output_kb = 256;
  cfg.hooks_user.clear();

  cfg.ini_path = AGENT_INI_FILE;
}

static bool ParseBool(const std::string &v, bool def)
{
  std::string s = ToLower(Trim(v));
  if(s == "1" || s == "yes" || s == "true" || s == "on") return true;
  if(s == "0" || s == "no" || s == "false" || s == "off") return false;
  return def;
}

static int ParseInt(const std::string &v, int def, int min_value)
{
  std::string s = Trim(v);
  if(s.empty()) return def;
  char *end = NULL;
  long n = strtol(s.c_str(), &end, 10);
  if(end == s.c_str() || *end != '\0' || n < min_value) return def;
  return (int)n;
}

//
// Purpose:
//   Reads the agent INI file. A missing file keeps every default, so
//   the agent still writes a local report.
//
// Return value:
//   0 when the file was read, 1 when it is missing or unreadable
//
int LoadAgentConfig(AgentConfig &cfg, const std::string &ini_path, std::string &output)
{
  SetDefaultAgentConfig(cfg);
  if(!ini_path.empty()) cfg.ini_path = ini_path;

  std::ifstream in(cfg.ini_path.c_str());
  if(!in) {
    output += "WARNING - Cannot read " + cfg.ini_path + ", using the default settings\n";
    return 1;
  }

  std::string line, section;
  while(std::getline(in, line)) {
    line = Trim(line);
    if(line.empty() || line[0] == ';' || line[0] == '#') continue;
    if(line[0] == '[') {
      size_t e = line.find(']');
      section = ToLower(Trim(line.substr(1, e == std::string::npos ? std::string::npos : e - 1)));
      continue;
    }
    size_t eq = line.find('=');
    if(eq == std::string::npos) continue;
    std::string key = ToLower(Trim(line.substr(0, eq)));
    std::string val = Trim(line.substr(eq + 1));
    if(val.length() >= 2 && val[0] == '"' && val[val.length() - 1] == '"') {
      val = val.substr(1, val.length() - 2);
    }

    if(section == "delivery") {
      if(key == "methods") {
	cfg.delivery_methods.clear();
	for(const std::string &m : Split(val, ',')) {
	  std::string t = ToLower(Trim(m));
	  if(!t.empty()) cfg.delivery_methods.push_back(t);
	}
      }
    }
    else if(section == "https") {
      if(key == "host") cfg.server_host = val;
      else if(key == "port") cfg.server_port = ParseInt(val, cfg.server_port, 1);
      else if(key == "upload_path") cfg.upload_path = val;
      else if(key == "register_path") cfg.register_path = val;
      else if(key == "enrollment_token") cfg.enrollment_token = val;
      else if(key == "use_https") cfg.use_https = ParseBool(val, cfg.use_https);
      else if(key == "verify_peer") cfg.verify_peer = ParseBool(val, cfg.verify_peer);
      else if(key == "ca_file") cfg.ca_file = val;
      else if(key == "timeout_seconds") cfg.https_timeout_seconds = ParseInt(val, cfg.https_timeout_seconds, 5);
    }
    else if(section == "cifs") {
      if(key == "share") cfg.cifs_share = val;
      else if(key == "directory") cfg.cifs_directory = val;
      else if(key == "credentials_file") cfg.cifs_credentials = val;
      else if(key == "smbclient_path") cfg.smbclient_path = val;
      else if(key == "timeout_seconds") cfg.cifs_timeout_seconds = ParseInt(val, cfg.cifs_timeout_seconds, 5);
    }
    else if(section == "scp") {
      if(key == "host") cfg.scp_host = val;
      else if(key == "port") cfg.scp_port = ParseInt(val, cfg.scp_port, 1);
      else if(key == "user") cfg.scp_user = val;
      else if(key == "key_file") cfg.scp_key_file = val;
      else if(key == "remote_dir") cfg.scp_remote_dir = val;
      else if(key == "scp_path") cfg.scp_path = val;
      else if(key == "known_hosts_file") cfg.scp_known_hosts = val;
      else if(key == "strict_host_key_checking") cfg.scp_host_key_check = ToLower(val);
      else if(key == "timeout_seconds") cfg.scp_timeout_seconds = ParseInt(val, cfg.scp_timeout_seconds, 5);
    }
    else if(section == "agent") {
      if(key == "report_interval_minutes") cfg.report_interval_minutes = ParseInt(val, cfg.report_interval_minutes, 1);
      else if(key == "cpu_sample_seconds") cfg.cpu_sample_seconds = ParseInt(val, cfg.cpu_sample_seconds, 1);
      else if(key == "report_dir") cfg.report_dir = val;
      else if(key == "log_file") cfg.log_file = val;
      else if(key == "data_dir") cfg.data_dir = val;
      else if(key == "check_updates") cfg.check_updates = ParseBool(val, cfg.check_updates);
      else if(key == "updates_refresh_hours") cfg.updates_refresh_hours = ParseInt(val, cfg.updates_refresh_hours, 0);
      else if(key == "command_timeout_seconds") cfg.command_timeout_seconds = ParseInt(val, cfg.command_timeout_seconds, 10);
    }
    else if(section == "scan") {
      if(key == "enabled") cfg.scan_enabled = ParseBool(val, cfg.scan_enabled);
      else if(key == "interval_hours") cfg.scan_interval_hours = ParseInt(val, cfg.scan_interval_hours, 1);
      else if(key == "source") cfg.scan_source = ToLower(val);
      else if(key == "oval_feed_url") cfg.oval_feed_url = val;
      else if(key == "csaf_index_url") cfg.csaf_index_url = val;
      else if(key == "unfixed_list_severity") cfg.unfixed_list_severity = val;
      else if(key == "oscap_path") cfg.oscap_path = val;
      else if(key == "upload_html") cfg.scan_upload_html = ParseBool(val, cfg.scan_upload_html);
      else if(key == "compliance_profile") cfg.compliance_profile = val;
      else if(key == "compliance_datastream") cfg.compliance_datastream = val;
      else if(key == "timeout_minutes") cfg.scan_timeout_minutes = ParseInt(val, cfg.scan_timeout_minutes, 1);
    }
    else if(section == "hooks") {
      if(key == "enabled") cfg.hooks_enabled = ParseBool(val, cfg.hooks_enabled);
      else if(key == "dir") cfg.hooks_dir = val;
      else if(key == "timeout_seconds") cfg.hooks_timeout_seconds = ParseInt(val, cfg.hooks_timeout_seconds, 1);
      else if(key == "max_output_kb") cfg.hooks_max_output_kb = ParseInt(val, cfg.hooks_max_output_kb, 1);
      else if(key == "user") cfg.hooks_user = val;
    }
  }

  if(cfg.scan_source != "auto" && cfg.scan_source != "oval" && cfg.scan_source != "csaf" && cfg.scan_source != "dnf") {
    output += "WARNING - [scan] source=" + cfg.scan_source + " is not auto, oval, csaf or dnf, using auto\n";
    cfg.scan_source = "auto";
  }
  return 0;
}

std::string JoinPath(const std::string &dir, const std::string &name)
{
  if(dir.empty()) return name;
  if(dir[dir.length() - 1] == '/') return dir + name;
  return dir + "/" + name;
}

std::string Trim(const std::string &s)
{
  size_t b = 0, e = s.length();
  while(b < e && std::isspace((unsigned char)s[b])) b++;
  while(e > b && std::isspace((unsigned char)s[e - 1])) e--;
  return s.substr(b, e - b);
}

std::string ToLower(std::string s)
{
  for(char &c : s) c = (char)std::tolower((unsigned char)c);
  return s;
}

std::vector<std::string> Split(const std::string &s, char sep)
{
  std::vector<std::string> parts;
  std::string cur;
  for(char c : s) {
    if(c == sep) {
      parts.push_back(cur);
      cur.clear();
    }
    else {
      cur += c;
    }
  }
  parts.push_back(cur);
  return parts;
}

bool StartsWith(const std::string &s, const std::string &prefix)
{
  return s.compare(0, prefix.length(), prefix) == 0;
}

bool ReadWholeFile(const std::string &fname, std::string &data)
{
  data.clear();
  std::ifstream in(fname.c_str(), std::ios::binary);
  if(!in) return false;
  std::ostringstream ss;
  ss << in.rdbuf();
  data = ss.str();
  return true;
}

//
// Purpose:
//   Writes a file through a temporary file and a rename, so a reader
//   never sees half a file
//
bool WriteWholeFile(const std::string &fname, const std::string &data, int mode)
{
  std::string tmp = fname + ".tmp";
  int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if(fd < 0) return false;
  fchmod(fd, mode);
  size_t done = 0;
  while(done < data.length()) {
    ssize_t n = write(fd, data.data() + done, data.length() - done);
    if(n < 0) {
      if(errno == EINTR) continue;
      close(fd);
      unlink(tmp.c_str());
      return false;
    }
    done += (size_t)n;
  }
  if(fsync(fd) != 0 || close(fd) != 0) {
    unlink(tmp.c_str());
    return false;
  }
  if(rename(tmp.c_str(), fname.c_str()) != 0) {
    unlink(tmp.c_str());
    return false;
  }
  return true;
}

bool CreateDirTree(const std::string &dir, int mode)
{
  if(dir.empty()) return false;
  std::string path;
  for(const std::string &part : Split(dir, '/')) {
    if(part.empty()) {
      if(path.empty()) path = "/";
      continue;
    }
    path = JoinPath(path, part);
    if(mkdir(path.c_str(), mode) != 0 && errno != EEXIST) return false;
  }
  struct stat st;
  return stat(dir.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool FileExists(const std::string &fname)
{
  struct stat st;
  return stat(fname.c_str(), &st) == 0;
}

long long FileMtime(const std::string &fname)
{
  struct stat st;
  if(stat(fname.c_str(), &st) != 0) return 0;
  return (long long)st.st_mtime;
}

std::string FormatPct(double pct)
{
  char buf[32];
  snprintf(buf, sizeof(buf), "%.1f", pct);
  return buf;
}

// Quote a value for a name=value report line, with \" and \\ escapes
std::string QuoteValue(const std::string &s)
{
  std::string q = "\"";
  for(char c : s) {
    if(c == '"' || c == '\\') q += '\\';
    if(c == '\n' || c == '\r' || c == '\t') c = ' ';
    q += c;
  }
  return q + "\"";
}

std::string NowText()
{
  time_t now = time(NULL);
  struct tm tmv;
  localtime_r(&now, &tmv);
  char buf[64];
  strftime(buf, sizeof(buf), "%a %b %d %H:%M:%S %Y", &tmv);
  return buf;
}

// Lower case host name without the domain, the name the server files the report under
std::string GetAgentHostname()
{
  char buf[256];
  if(gethostname(buf, sizeof(buf)) != 0) return "localhost";
  buf[sizeof(buf) - 1] = '\0';
  std::string name = ToLower(buf);
  size_t dot = name.find('.');
  if(dot != std::string::npos) name = name.substr(0, dot);
  return name;
}

std::map<std::string, std::string> ReadOsRelease()
{
  std::map<std::string, std::string> os;
  std::string data;
  if(!ReadWholeFile("/etc/os-release", data)) ReadWholeFile("/usr/lib/os-release", data);
  for(const std::string &line : Split(data, '\n')) {
    size_t eq = line.find('=');
    if(eq == std::string::npos) continue;
    std::string v = Trim(line.substr(eq + 1));
    if(v.length() >= 2 && (v[0] == '"' || v[0] == '\'')) v = v.substr(1, v.length() - 2);
    os[Trim(line.substr(0, eq))] = v;
  }
  return os;
}

// Major release from VERSION_ID, for example 9 for 9.6, 0 when unknown
int OsMajorVersion()
{
  std::map<std::string, std::string> os = ReadOsRelease();
  return atoi(os["VERSION_ID"].c_str());
}

//
// Purpose:
//   Runs a program without a shell and collects its output
//
// Parameters:
//   argv - program and arguments, argv[0] is an absolute path or a name on PATH
//   timeout_seconds - the program is killed after this many seconds
//   result - exit code and output
//   extra_env - NAME=value entries added to the environment
//   run_as - user to run as (groups, then gid, then uid), NULL = this process's user
//
// Return value:
//   0 when the program ran and exited 0
//
int RunCommand(const std::vector<std::string> &argv, int timeout_seconds, CommandResult &result,
	       const std::vector<std::string> &extra_env, const RunAsUser *run_as)
{
  result.exit_code = -1;
  result.timed_out = false;
  result.out.clear();
  result.err.clear();
  if(argv.empty()) return -1;

  int out_pipe[2], err_pipe[2];
  if(pipe2(out_pipe, O_CLOEXEC) != 0) return -1;
  if(pipe2(err_pipe, O_CLOEXEC) != 0) {
    close(out_pipe[0]);
    close(out_pipe[1]);
    return -1;
  }

  std::vector<std::string> env;
  for(char **e = environ; e && *e; e++) env.push_back(*e);
  // Plain C locale output, the parsers expect English
  env.push_back("LC_ALL=C");
  for(const std::string &e : extra_env) {
    // An extra NAME=value replaces the inherited NAME
    std::string prefix = e.substr(0, e.find('=') + 1);
    for(size_t i = 0; i < env.size(); ) {
      if(!prefix.empty() && env[i].compare(0, prefix.length(), prefix) == 0) env.erase(env.begin() + i);
      else i++;
    }
    env.push_back(e);
  }

  pid_t pid = fork();
  if(pid < 0) {
    close(out_pipe[0]); close(out_pipe[1]);
    close(err_pipe[0]); close(err_pipe[1]);
    return -1;
  }
  if(pid == 0) {
    setpgid(0, 0);
    int devnull = open("/dev/null", O_RDONLY);
    if(devnull >= 0) dup2(devnull, 0);
    dup2(out_pipe[1], 1);
    dup2(err_pipe[1], 2);
    std::vector<char *> args, envp;
    for(const std::string &a : argv) args.push_back(const_cast<char *>(a.c_str()));
    args.push_back(NULL);
    for(const std::string &e : env) envp.push_back(const_cast<char *>(e.c_str()));
    envp.push_back(NULL);
    if(run_as) {
      // Never run as root by mistake when the switch fails
      if(initgroups(run_as->name.c_str(), (gid_t)run_as->gid) != 0) _exit(126);
      if(setgid((gid_t)run_as->gid) != 0) _exit(126);
      if(setuid((uid_t)run_as->uid) != 0) _exit(126);
      if(!run_as->home.empty() && chdir(run_as->home.c_str()) != 0 && chdir("/") != 0) _exit(126);
    }
    execvpe(args[0], args.data(), envp.data());
    _exit(127);
  }
  close(out_pipe[1]);
  close(err_pipe[1]);

  time_t deadline = time(NULL) + timeout_seconds;
  struct pollfd fds[2] = { { out_pipe[0], POLLIN, 0 }, { err_pipe[0], POLLIN, 0 } };
  int open_fds = 2;
  char buf[8192];
  while(open_fds > 0) {
    int wait_ms = (int)(deadline - time(NULL)) * 1000;
    if(wait_ms <= 0) {
      result.timed_out = true;
      break;
    }
    int rc = poll(fds, 2, wait_ms);
    if(rc < 0) {
      if(errno == EINTR) continue;
      break;
    }
    for(int i = 0; i < 2; i++) {
      if(fds[i].fd < 0 || !(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
      ssize_t n = read(fds[i].fd, buf, sizeof(buf));
      if(n > 0) {
	(i == 0 ? result.out : result.err).append(buf, (size_t)n);
      }
      else if(n == 0 || errno != EINTR) {
	close(fds[i].fd);
	fds[i].fd = -1;
	open_fds--;
      }
    }
  }
  for(int i = 0; i < 2; i++) if(fds[i].fd >= 0) close(fds[i].fd);

  if(result.timed_out) {
    kill(-pid, SIGTERM);
    sleep(2);
    kill(-pid, SIGKILL);
  }
  int status = 0;
  while(waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
  if(!result.timed_out && WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
  return (result.exit_code == 0) ? 0 : -1;
}

// Full path of a program in the usual system directories, empty when not found
std::string FindProgram(const std::string &name)
{
  static const char *dirs[] = { "/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin", NULL };
  for(int i = 0; dirs[i]; i++) {
    std::string p = JoinPath(dirs[i], name);
    if(access(p.c_str(), X_OK) == 0) return p;
  }
  return std::string();
}

// Appends a time stamped message to the log file, and to standard error
// when it is a terminal or the journal (systemd keeps stderr)
void LogMessage(const AgentConfig &cfg, const std::string &message)
{
  std::string text = message;
  while(!text.empty() && text[text.length() - 1] == '\n') text.erase(text.length() - 1);
  std::string line = "[" + NowText() + "] " + text + "\n";
  if(!cfg.log_file.empty()) {
    size_t slash = cfg.log_file.rfind('/');
    if(slash != std::string::npos && slash > 0) CreateDirTree(cfg.log_file.substr(0, slash), 0750);
    int fd = open(cfg.log_file.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
    if(fd >= 0) {
      ssize_t n = write(fd, line.data(), line.length());
      (void)n;
      close(fd);
    }
  }
  fputs(text.c_str(), stderr);
  fputc('\n', stderr);
}
