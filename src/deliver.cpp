// C STD lib includes
#include <stdio.h>
#include <unistd.h>

// C++ STD lib includes
#include <string>
#include <vector>

// APP includes
#include "common.h"
#include "agent_auth.h"
#include "deliver.h"

//
// Purpose:
//   Copies the report to a Windows (SMB/CIFS) share with smbclient. The
//   share login is in credentials_file, in smbclient -A format:
//     username = reports
//     password = secret
//     domain   = WORKGROUP
//
static int CopyToShare(const AgentConfig &cfg, const std::string &local_file, const std::string &remote_name,
		       std::string &output)
{
  if(cfg.cifs_share.empty()) {
    output += "ERROR - [cifs] share is not set\n";
    return -1;
  }
  if(access(cfg.smbclient_path.c_str(), X_OK) != 0) {
    output += "ERROR - " + cfg.smbclient_path + " not found, install samba-client\n";
    return -1;
  }
  std::string share = cfg.cifs_share;
  for(char &c : share) if(c == '\\') c = '/';
  // smbclient commands are parsed by smbclient, quote the names for it
  std::string cmd;
  if(!cfg.cifs_directory.empty()) cmd += "cd \"" + cfg.cifs_directory + "\"; ";
  cmd += "put \"" + local_file + "\" \"" + remote_name + ".tmp\"; ";
  cmd += "rename \"" + remote_name + ".tmp\" \"" + remote_name + "\" -f";
  std::vector<std::string> argv = { cfg.smbclient_path, share };
  if(!cfg.cifs_credentials.empty()) {
    argv.push_back("-A");
    argv.push_back(cfg.cifs_credentials);
  }
  else {
    argv.push_back("-N");
  }
  argv.push_back("-c");
  argv.push_back(cmd);
  CommandResult r;
  RunCommand(argv, cfg.cifs_timeout_seconds, r);
  std::string text = Trim(r.out + "\n" + r.err);
  if(r.exit_code != 0 || text.find("NT_STATUS_") != std::string::npos) {
    output += "ERROR - Copy to " + share + " failed" + std::string(r.timed_out ? " (timed out)" : "") + ": " + text + "\n";
    return -1;
  }
  output += "Copied " + remote_name + " to " + share + "\n";
  return 0;
}

static int ScpFile(const AgentConfig &cfg, const std::string &local_file, const std::string &remote_name,
		   std::string &output)
{
  if(cfg.scp_host.empty() || cfg.scp_user.empty() || cfg.scp_remote_dir.empty()) {
    output += "ERROR - [scp] host, user and remote_dir must be set\n";
    return -1;
  }
  if(access(cfg.scp_path.c_str(), X_OK) != 0) {
    output += "ERROR - " + cfg.scp_path + " not found, install openssh-clients\n";
    return -1;
  }
  std::string check = (cfg.scp_host_key_check == "accept-new") ? "accept-new" : "yes";
  std::vector<std::string> argv = {
    cfg.scp_path, "-q", "-B",
    "-P", std::to_string(cfg.scp_port),
    "-i", cfg.scp_key_file,
    "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=" + check,
    "-o", "UserKnownHostsFile=" + cfg.scp_known_hosts,
    "-o", "ConnectTimeout=30",
    local_file,
    cfg.scp_user + "@" + cfg.scp_host + ":" + JoinPath(cfg.scp_remote_dir, remote_name)
  };
  CommandResult r;
  RunCommand(argv, cfg.scp_timeout_seconds, r);
  if(r.exit_code != 0) {
    output += "ERROR - scp to " + cfg.scp_host + " failed" + std::string(r.timed_out ? " (timed out)" : "") + ": " + Trim(r.err) + "\n";
    return -1;
  }
  output += "Copied " + remote_name + " to " + cfg.scp_host + ":" + cfg.scp_remote_dir + "\n";
  return 0;
}

//
// Purpose:
//   Sends the report with every method in [delivery] methods
//
// Return value:
//   0 when every method worked
//
int DeliverReport(const AgentConfig &cfg, const std::string &report_file, const std::string &report,
		  const std::string &hostname, std::vector<FormFile> &html_files, std::string &output)
{
  int error_level = 0;
  bool html_sent = html_files.empty();
  std::string report_name = hostname + AGENT_REPORT_SUFFIX;
  for(const std::string &method : cfg.delivery_methods) {
    int rv = 0;
    if(method == "https") {
      rv = UploadReport(cfg, report, html_files, output);
      if(rv == 0) html_sent = true;
    }
    else if(method == "cifs" || method == "scp") {
      rv = (method == "cifs") ? CopyToShare(cfg, report_file, report_name, output) : ScpFile(cfg, report_file, report_name, output);
      // The HTML reports go next to the report, they are already in data_dir
      for(const FormFile &h : html_files) {
	if(rv != 0) break;
	std::string local = JoinPath(cfg.data_dir, h.field == "scapReport" ? "scan_vulnerabilities.html" : "scan_compliance.html");
	rv = (method == "cifs") ? CopyToShare(cfg, local, h.file_name, output) : ScpFile(cfg, local, h.file_name, output);
      }
      if(rv == 0) html_sent = true;
    }
    else {
      output += "ERROR - Unknown delivery method " + method + "\n";
      rv = -1;
    }
    if(rv != 0) error_level = -1;
  }
  if(html_sent) html_files.clear();
  return error_level;
}
