// ----------------------------------------------------------- //
// C++ Source Code File
// Original Author(s): DataReel Software Development
// File Creation Date: 10/29/2026
// Date Last Modified: 10/29/2026
//
// ------------- Program Description and Details ------------- //
// ----------------------------------------------------------- //
/*
This file is part of the DataReel Reporting Agent for Linux.

Report hooks, see hooks.h.
*/
// ----------------------------------------------------------- //

// C STD lib includes
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/stat.h>

// C++ STD lib includes
#include <string>
#include <vector>
#include <algorithm>

// APP includes
#include "common.h"
#include "hooks.h"

// Hook names: letters, digits, dot, dash, underscore; no leading dot,
// and no editor or rpm leftovers
static bool HookNameOk(const std::string &name)
{
  if(name.empty() || name[0] == '.' || name.length() > 64) return false;
  for(char c : name) {
    if(!(isalnum((unsigned char)c) || c == '.' || c == '-' || c == '_')) return false;
  }
  static const char *skip[] = { ".rpmnew", ".rpmsave", ".rpmorig", ".bak", ".orig", ".swp", ".tmp", ".disabled", NULL };
  for(int i = 0; skip[i]; i++) {
    size_t n = strlen(skip[i]);
    if(name.length() > n && name.compare(name.length() - n, n, skip[i]) == 0) return false;
  }
  return true;
}

// Empty when root owns st and only root can write it
static std::string UnsafeReason(const struct stat &st)
{
  if(st.st_uid != 0) return "not owned by root";
  if(st.st_mode & (S_IWGRP | S_IWOTH)) return "group or world writable";
  return std::string();
}

static std::string Quote(const std::string &s)
{
  std::string q = "\"";
  for(char c : s) {
    if(c == '"' || c == '\\') q += '\\';
    q += c;
  }
  return q + "\"";
}

static std::string HookName(const std::string &file)
{
  // The name DRSM looks for: the file name without a .sh ending
  if(file.length() > 3 && file.compare(file.length() - 3, 3, ".sh") == 0) return file.substr(0, file.length() - 3);
  return file;
}

std::string HookReportSection(const AgentConfig &cfg, std::string &output)
{
  if(!cfg.hooks_enabled || cfg.hooks_dir.empty()) return std::string();
  struct stat dst;
  if(stat(cfg.hooks_dir.c_str(), &dst) != 0 || !S_ISDIR(dst.st_mode)) return std::string();

  std::string body;
  std::string why = UnsafeReason(dst);
  if(!why.empty()) {
    body += "skipped=" + Quote(cfg.hooks_dir) + " reason=" + Quote("directory " + why) + "\n";
    output += "WARNING - report hooks in " + cfg.hooks_dir + " skipped, the directory is " + why + "\n";
    return "HOOKS:\n" + body + "END HOOKS\n\n";
  }

  RunAsUser user;
  const RunAsUser *run_as = NULL;
  if(!cfg.hooks_user.empty() && cfg.hooks_user != "root") {
    struct passwd *pw = getpwnam(cfg.hooks_user.c_str());
    if(!pw) {
      body += "skipped=" + Quote(cfg.hooks_dir) + " reason=" + Quote("no user " + cfg.hooks_user) + "\n";
      output += "WARNING - report hooks skipped, [hooks] user " + cfg.hooks_user + " does not exist\n";
      return "HOOKS:\n" + body + "END HOOKS\n\n";
    }
    user.uid = pw->pw_uid;
    user.gid = pw->pw_gid;
    user.name = pw->pw_name;
    user.home = pw->pw_dir ? pw->pw_dir : "";
    run_as = &user;
  }

  std::vector<std::string> files;
  DIR *d = opendir(cfg.hooks_dir.c_str());
  if(!d) return std::string();
  struct dirent *de;
  while((de = readdir(d)) != NULL) {
    std::string n = de->d_name;
    if(n == "." || n == "..") continue;
    files.push_back(n);
  }
  closedir(d);
  std::sort(files.begin(), files.end());

  std::string hostname = GetAgentHostname();
  size_t max_bytes = (size_t)cfg.hooks_max_output_kb * 1024;
  for(const std::string &f : files) {
    std::string path = JoinPath(cfg.hooks_dir, f);
    struct stat st;
    if(lstat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
    if(!HookNameOk(f)) continue;
    if(!(st.st_mode & S_IXUSR)) continue;
    why = UnsafeReason(st);
    if(!why.empty()) {
      body += "skipped=" + Quote(f) + " reason=" + Quote(why) + "\n";
      output += "WARNING - report hook " + path + " skipped, it is " + why + "\n";
      continue;
    }
    std::string name = HookName(f);
    std::vector<std::string> env = {
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "DRRA_HOOK=" + name,
      "DRRA_HOSTNAME=" + hostname
    };
    if(run_as) {
      env.push_back("HOME=" + (run_as->home.empty() ? std::string("/") : run_as->home));
      env.push_back("USER=" + run_as->name);
      env.push_back("LOGNAME=" + run_as->name);
    }
    time_t t0 = time(NULL);
    CommandResult r;
    RunCommand({ path }, cfg.hooks_timeout_seconds, r, env, run_as);
    long secs = (long)(time(NULL) - t0);
    std::string out = r.out;
    if(!r.err.empty()) {
      if(!out.empty() && out[out.length() - 1] != '\n') out += "\n";
      out += r.err;
    }
    bool truncated = out.length() > max_bytes;
    if(truncated) out.resize(max_bytes);
    while(!out.empty() && out[out.length() - 1] == '\n') out.erase(out.length() - 1);
    body += "hook=" + name + " exit=" + std::to_string(r.exit_code) + " secs=" + std::to_string(secs)
      + " timed_out=" + (r.timed_out ? "1" : "0") + " truncated=" + (truncated ? "1" : "0") + "\n";
    if(!out.empty()) for(const std::string &line : Split(out, '\n')) {
      std::string l = line;
      if(!l.empty() && l[l.length() - 1] == '\r') l.erase(l.length() - 1);
      body += "| " + l + "\n";
    }
    if(r.timed_out) output += "WARNING - report hook " + path + " timed out after " + std::to_string(cfg.hooks_timeout_seconds) + " seconds\n";
  }
  if(body.empty()) return std::string();
  return "HOOKS:\n" + body + "END HOOKS\n\n";
}
