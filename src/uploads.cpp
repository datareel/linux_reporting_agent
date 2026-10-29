// C STD lib includes
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <grp.h>
#include <utime.h>
#include <sys/stat.h>

// C++ STD lib includes
#include <algorithm>
#include <fstream>
#include <string>
#include <vector>

// APP includes
#include "common.h"
#include "agent_auth.h"
#include "uploads.h"

// Group that may put files in the spool folders and run drra submit
#define UPLOAD_GROUP "drra-upload"

bool ValidUploadId(const std::string &id)
{
  if(id.empty() || id.length() > 32) return false;
  for(char c : id) {
    if(!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
  }
  return true;
}

std::string UploadSpoolDir(const AgentConfig &cfg, const std::string &id)
{
  return JoinPath(cfg.uploads_spool_dir, id);
}

static std::vector<std::string> ListDir(const std::string &dir)
{
  std::vector<std::string> names;
  DIR *d = opendir(dir.c_str());
  if(!d) return names;
  struct dirent *e;
  while((e = readdir(d)) != NULL) {
    std::string name = e->d_name;
    if(name != "." && name != "..") names.push_back(name);
  }
  closedir(d);
  std::sort(names.begin(), names.end());
  return names;
}

static bool EndsWith(const std::string &s, const std::string &suffix)
{
  return s.length() >= suffix.length() && s.compare(s.length() - suffix.length(), suffix.length(), suffix) == 0;
}

// File names sent to the server: letters, digits, . _ - only
static std::string SafeFileName(const std::string &name)
{
  std::string out;
  for(char c : name) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    out += ok ? c : '_';
  }
  if(out.length() > 100) out = out.substr(out.length() - 100);
  if(out.empty() || out[0] == '.') out = "payload" + out;
  return out;
}

static std::string ContentTypeFor(const std::string &name)
{
  std::string n = ToLower(name);
  if(EndsWith(n, ".xml") || EndsWith(n, ".nessus")) return "application/xml";
  if(EndsWith(n, ".json")) return "application/json";
  if(EndsWith(n, ".csv")) return "text/csv";
  if(EndsWith(n, ".html") || EndsWith(n, ".htm")) return "text/html";
  return "text/plain";
}

static std::string IsoTime(time_t t)
{
  char buf[32];
  struct tm tmv;
  gmtime_r(&t, &tmv);
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tmv);
  return buf;
}

// A hook file is trusted only when the agent's own user (root) owns it
// and nobody else can change it
static bool TrustedFile(const std::string &fname, std::string &why)
{
  struct stat st;
  if(stat(fname.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) {
    why = "is not a file";
    return false;
  }
  if(st.st_uid != 0 && st.st_uid != geteuid()) {
    why = "is not owned by root";
    return false;
  }
  if(st.st_mode & (S_IWGRP | S_IWOTH)) {
    why = "is writable by group or others";
    return false;
  }
  return true;
}

static bool ReadUploadFile(const AgentConfig &cfg, const std::string &fname, UploadHookConfig &hook, std::string &output)
{
  hook.id.clear();
  hook.title.clear();
  hook.format.clear();
  hook.max_bytes = cfg.uploads_max_bytes;
  hook.keep_sent = 3;
  hook.file = fname;

  std::ifstream in(fname.c_str());
  if(!in) {
    output += "ERROR - Cannot read upload hook file " + fname + "\n";
    return false;
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
    if(eq == std::string::npos || section != "upload") continue;
    std::string key = ToLower(Trim(line.substr(0, eq)));
    std::string val = Trim(line.substr(eq + 1));
    // Comments may follow a value
    size_t sc = val.find(" ;");
    if(sc != std::string::npos) val = Trim(val.substr(0, sc));
    if(val.length() >= 2 && val[0] == '"' && val[val.length() - 1] == '"') val = val.substr(1, val.length() - 2);
    if(key == "id") hook.id = val;
    else if(key == "title") hook.title = val;
    else if(key == "format") hook.format = ToLower(val);
    else if(key == "max_bytes") {
      long long n = atoll(val.c_str());
      if(n > 0 && n < hook.max_bytes) hook.max_bytes = n;
    }
    else if(key == "keep_sent") {
      int n = atoi(val.c_str());
      if(n >= 0) hook.keep_sent = n;
    }
    else if(key == "source" && ToLower(val) != "spool") {
      output += "WARNING - Upload hook file " + fname + ": source=" + val + " is not supported yet, using spool\n";
    }
  }
  if(!ValidUploadId(hook.id)) {
    output += "ERROR - Upload hook file " + fname + ": id must be 1 to 32 of a-z, 0-9 and _\n";
    return false;
  }
  if(hook.title.empty()) hook.title = hook.id;
  for(char &c : hook.format) if(!(isalnum((unsigned char)c) || c == '-')) c = '-';
  return true;
}

std::vector<UploadHookConfig> LoadUploadHooks(const AgentConfig &cfg, std::string &output)
{
  std::vector<UploadHookConfig> hooks;
  if(!cfg.uploads_enabled) return hooks;
  for(const std::string &name : ListDir(cfg.uploads_dir)) {
    if(!EndsWith(name, ".ini") || name[0] == '.') continue;
    std::string fname = JoinPath(cfg.uploads_dir, name);
    std::string why;
    if(!TrustedFile(fname, why)) {
      output += "ERROR - Upload hook file " + fname + " " + why + ", skipped\n";
      continue;
    }
    UploadHookConfig hook;
    if(!ReadUploadFile(cfg, fname, hook, output)) continue;
    bool dup = false;
    for(const UploadHookConfig &h : hooks) if(h.id == hook.id) dup = true;
    if(dup) {
      output += "ERROR - Upload hook " + hook.id + " is defined twice, " + fname + " skipped\n";
      continue;
    }
    hooks.push_back(hook);
  }
  return hooks;
}

static bool FindUploadHook(const AgentConfig &cfg, const std::string &id, UploadHookConfig &hook, std::string &output)
{
  for(const UploadHookConfig &h : LoadUploadHooks(cfg, output)) {
    if(h.id == id) {
      hook = h;
      return true;
    }
  }
  return false;
}

// Spool folders: owned by root, group drra-upload may add files (setgid)
static bool EnsureSpoolDir(const std::string &dir)
{
  if(!CreateDirTree(dir, 0750)) return false;
  if(geteuid() == 0) {
    struct group *g = getgrnam(UPLOAD_GROUP);
    if(g != NULL && chown(dir.c_str(), 0, g->gr_gid) == 0) chmod(dir.c_str(), 02770);
  }
  return true;
}

int SubmitUploadFile(const AgentConfig &cfg, const std::string &hook_id, const std::string &file, bool send_now,
		   std::string &output)
{
  UploadHookConfig hook;
  std::string dir = UploadSpoolDir(cfg, hook_id);
  if(!ValidUploadId(hook_id)) {
    output += "ERROR - " + hook_id + " is not a hook ID\n";
    return -1;
  }
  if(!FindUploadHook(cfg, hook_id, hook, output)) {
    // Only root reads /etc/drra: other drra-upload members may submit to a
    // hook whose spool folder exists, and the agent checks the size again
    struct stat st;
    if(geteuid() == 0 || access(cfg.uploads_dir.c_str(), R_OK) == 0 || stat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
      output += "ERROR - No upload hook " + hook_id + " in " + cfg.uploads_dir + "\n";
      return -1;
    }
    output.clear();
    hook.id = hook_id;
    hook.max_bytes = cfg.uploads_max_bytes;
  }
  std::string data;
  if(!ReadWholeFile(file, data)) {
    output += "ERROR - Cannot read " + file + "\n";
    return -1;
  }
  if((long long)data.length() > hook.max_bytes) {
    output += "ERROR - " + file + " is " + std::to_string(data.length()) + " bytes, hook " + hook_id +
      " takes at most " + std::to_string(hook.max_bytes) + "\n";
    return -1;
  }
  if(!EnsureSpoolDir(dir)) {
    output += "ERROR - Cannot create " + dir + "\n";
    return -1;
  }
  size_t slash = file.rfind('/');
  std::string base = SafeFileName(slash == std::string::npos ? file : file.substr(slash + 1));
  std::string name = std::to_string((long long)time(NULL)) + "_" + std::to_string((long long)getpid()) + "_" + base;
  std::string meta = "SOURCE: submit\nFILE_NAME: " + base + "\n";
  // The meta file first, then the payload by rename, so the agent never
  // sees a payload without its meta file or a partial payload
  std::string tmp = JoinPath(dir, "." + name + ".tmp");
  if(!WriteWholeFile(JoinPath(dir, "." + name + ".meta"), meta, 0640) || !WriteWholeFile(tmp, data, 0640) ||
     rename(tmp.c_str(), JoinPath(dir, name).c_str()) != 0) {
    unlink(tmp.c_str());
    output += "ERROR - Cannot write to " + dir + "\n";
    return -1;
  }
  output += "Queued " + file + " for hook " + hook_id + " as " + JoinPath(dir, name) + "\n";
  if(send_now) {
    std::string flag = JoinPath(cfg.uploads_spool_dir, UPLOAD_SEND_NOW_FILE);
    if(WriteWholeFile(flag, "", 0660)) output += "The agent sends it within a few seconds\n";
    else output += "It goes out with the next report (cannot write " + flag + ")\n";
  }
  else {
    output += "It goes out with the next report\n";
  }
  return 0;
}

bool UploadSendNowRequested(const AgentConfig &cfg)
{
  std::string flag = JoinPath(cfg.uploads_spool_dir, UPLOAD_SEND_NOW_FILE);
  if(!FileExists(flag)) return false;
  unlink(flag.c_str());
  return true;
}

// Payload files waiting in a spool folder, oldest first. Names starting
// with "." (meta and temporary files) are skipped. Files changed in the
// last two seconds may still be written and wait, except files from
// drra submit (they have a meta file and arrive complete by rename).
static std::vector<std::string> PendingFiles(const std::string &dir)
{
  std::vector<std::pair<long long, std::string> > files;
  time_t now = time(NULL);
  for(const std::string &name : ListDir(dir)) {
    if(name[0] == '.' || EndsWith(name, ".tmp")) continue;
    struct stat st;
    std::string path = JoinPath(dir, name);
    if(lstat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
    if(now - st.st_mtime < 2 && !FileExists(JoinPath(dir, "." + name + ".meta"))) continue;
    files.push_back(std::make_pair((long long)st.st_mtime, name));
  }
  std::sort(files.begin(), files.end());
  std::vector<std::string> names;
  for(const auto &f : files) names.push_back(f.second);
  return names;
}

static void MoveSpoolFile(const std::string &dir, const std::string &name, const std::string &to, int keep)
{
  std::string meta = JoinPath(dir, "." + name + ".meta");
  std::string from = JoinPath(dir, name);
  std::string tdir = JoinPath(dir, to);
  if(keep <= 0 || !CreateDirTree(tdir, 0750)) {
    unlink(from.c_str());
    unlink(meta.c_str());
    return;
  }
  std::string dest = JoinPath(tdir, name);
  if(rename(from.c_str(), dest.c_str()) != 0) unlink(from.c_str());
  else utime(dest.c_str(), NULL);
  unlink(meta.c_str());

  // Keep the newest "keep" files
  std::vector<std::pair<long long, std::string> > old;
  for(const std::string &n : ListDir(tdir)) {
    struct stat st;
    std::string p = JoinPath(tdir, n);
    if(lstat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode)) old.push_back(std::make_pair((long long)st.st_mtime, p));
  }
  std::sort(old.begin(), old.end());
  for(size_t i = 0; i + keep < old.size(); i++) unlink(old[i].second.c_str());
}

static std::string StateFile(const AgentConfig &cfg, const std::string &id)
{
  return JoinPath(JoinPath(cfg.data_dir, UPLOAD_STATE_DIR), id + ".state");
}

static void WriteUploadState(const AgentConfig &cfg, const std::string &id, const std::string &status,
			   long long bytes, const std::string &message)
{
  std::string old, last_sent = "0";
  ReadWholeFile(StateFile(cfg, id), old);
  for(const std::string &line : Split(old, '\n')) {
    if(StartsWith(line, "last_sent=")) last_sent = line.substr(10);
  }
  if(status == "ok") last_sent = std::to_string((long long)time(NULL));
  std::string state = "status=" + status + "\nlast_sent=" + last_sent + "\nlast_try=" + std::to_string((long long)time(NULL)) +
    "\nbytes=" + std::to_string(bytes) + "\nmessage=" + QuoteValue(message) + "\n";
  CreateDirTree(JoinPath(cfg.data_dir, UPLOAD_STATE_DIR), 0700);
  WriteWholeFile(StateFile(cfg, id), state, 0600);
}

static std::string MetaValue(const std::string &meta, const std::string &key)
{
  for(const std::string &line : Split(meta, '\n')) {
    if(StartsWith(line, key + ": ")) return Trim(line.substr(key.length() + 2));
  }
  return std::string();
}

int SendPendingUploads(const AgentConfig &cfg, std::string &output)
{
  if(!cfg.uploads_enabled) return 0;
  std::vector<UploadHookConfig> hooks = LoadUploadHooks(cfg, output);
  if(hooks.empty()) return 0;
  bool https = std::find(cfg.delivery_methods.begin(), cfg.delivery_methods.end(), "https") != cfg.delivery_methods.end();
  std::string hostname = GetAgentHostname();
  int error_level = 0;

  for(const UploadHookConfig &hook : hooks) {
    std::string dir = UploadSpoolDir(cfg, hook.id);
    EnsureSpoolDir(dir);
    std::vector<std::string> files = PendingFiles(dir);
    if(files.empty()) continue;
    if(!https) {
      output += "WARNING - Upload hook " + hook.id + " has " + std::to_string(files.size()) +
	" file(s) waiting: uploads are only sent with the https delivery method\n";
      WriteUploadState(cfg, hook.id, "waiting", 0, "uploads need https delivery");
      continue;
    }
    for(const std::string &name : files) {
      std::string path = JoinPath(dir, name);
      struct stat st;
      if(stat(path.c_str(), &st) != 0) continue;
      if((long long)st.st_size > hook.max_bytes) {
	output += "ERROR - " + path + " is " + std::to_string((long long)st.st_size) + " bytes, hook " + hook.id +
	  " takes at most " + std::to_string(hook.max_bytes) + ", moved to failed/\n";
	MoveSpoolFile(dir, name, "failed", 10);
	WriteUploadState(cfg, hook.id, "error", (long long)st.st_size, "file too large");
	error_level = -1;
	continue;
      }
      FormFile payload;
      if(!ReadWholeFile(path, payload.content)) {
	output += "ERROR - Cannot read " + path + "\n";
	error_level = -1;
	break;
      }
      std::string meta;
      ReadWholeFile(JoinPath(dir, "." + name + ".meta"), meta);
      std::string source = MetaValue(meta, "SOURCE") == "submit" ? "submit" : "spool";
      std::string file_name = SafeFileName(MetaValue(meta, "FILE_NAME").empty() ? name : MetaValue(meta, "FILE_NAME"));
      payload.field = "payload";
      payload.file_name = file_name;
      payload.content_type = ContentTypeFor(file_name);

      std::string envelope;
      envelope += "HOOK_ID: " + hook.id + "\n";
      envelope += "TITLE: " + hook.title + "\n";
      envelope += "SUBJECT: " + hostname + "\n";
      envelope += "FORMAT: " + hook.format + "\n";
      envelope += "CONTENT_TYPE: " + payload.content_type + "\n";
      envelope += "FILE_NAME: " + file_name + "\n";
      envelope += "COLLECTED: " + IsoTime(st.st_mtime) + "\n";
      envelope += "COLLECTED_ETIME: " + std::to_string((long long)st.st_mtime) + "\n";
      envelope += "SOURCE: " + source + "\n";
      envelope += "AGENT_VERSION: " AGENT_VERSION "\n";
      envelope += "SHA256: " + Sha256Hex(payload.content) + "\n";

      std::string status;
      int rv = UploadHook(cfg, hook.id, hostname, envelope, payload, status, output);
      if(rv == 0) {
	MoveSpoolFile(dir, name, "sent", hook.keep_sent);
	WriteUploadState(cfg, hook.id, "ok", (long long)payload.content.length(), file_name);
	continue;
      }
      WriteUploadState(cfg, hook.id, rv > 0 ? "waiting" : "error", (long long)payload.content.length(), status);
      if(rv < 0) error_level = -1;
      // The rest of this hook's files wait for the next cycle, in order
      break;
    }
  }
  return error_level;
}

std::string UploadReportSection(const AgentConfig &cfg)
{
  std::string ignore;
  std::vector<UploadHookConfig> hooks = LoadUploadHooks(cfg, ignore);
  if(hooks.empty()) return std::string();
  std::string body;
  for(const UploadHookConfig &hook : hooks) {
    std::string state, status = "none", last_sent = "0", message;
    ReadWholeFile(StateFile(cfg, hook.id), state);
    for(const std::string &line : Split(state, '\n')) {
      if(StartsWith(line, "status=")) status = line.substr(7);
      else if(StartsWith(line, "last_sent=")) last_sent = line.substr(10);
      else if(StartsWith(line, "message=")) message = line.substr(8);
    }
    body += hook.id + "_title=" + QuoteValue(hook.title) + "\n";
    body += hook.id + "_status=" + status + "\n";
    body += hook.id + "_last_sent=" + last_sent + "\n";
    body += hook.id + "_pending=" + std::to_string(PendingFiles(UploadSpoolDir(cfg, hook.id)).size()) + "\n";
    if(!message.empty() && status != "ok") body += hook.id + "_message=" + message + "\n";
  }
  return "UPLOADS:\n" + body + "END UPLOADS\n\n";
}
