#ifndef UPLOADS_H
#define UPLOADS_H

// Hook uploads: reports from other sources
//
// An upload hook is one <id>.ini file in [uploads] dir
// (/etc/drra/uploads.d). Any tool puts a file in the hook's spool
// folder, <spool_dir>/<id>/, or runs "drra submit --hook <id> <file>",
// and the agent sends it to hook.php on the report server with a signed
// upload. The server side manifest for the same hook ID says how the
// data is read, alerted on and shown (DRSM plugins/uploads/<id>/).
// Report hooks (hooks.h, /etc/drra/report.d) are the other kind: scripts
// whose output goes in every report.
//
//   [upload]
//   id=openscap_manual      [a-z0-9_], 1 to 32 characters
//   title=Manual OpenSCAP scan
//   format=xccdf-results    a hint for the server, its manifest decides
//   max_bytes=20000000      at most [uploads] max_bytes
//   keep_sent=3             sent files kept in <spool>/<id>/sent/
//
// Upload hook files must be owned by the user the agent runs as (root) and not
// writable by group or others, or they are skipped.

#include "common.h"

#define AGENT_UPLOADS_DIR_TEXT "/etc/drra/uploads.d"
#define UPLOAD_STATE_DIR "uploads"
#define UPLOAD_SEND_NOW_FILE ".send_now"

struct UploadHookConfig {
  std::string id;
  std::string title;
  std::string format;
  long long max_bytes;
  int keep_sent;
  std::string file;        // the hook's INI file
};

bool ValidUploadId(const std::string &id);
std::vector<UploadHookConfig> LoadUploadHooks(const AgentConfig &cfg, std::string &output);
std::string UploadSpoolDir(const AgentConfig &cfg, const std::string &id);

// Copies file into the hook's spool folder; with send_now the running
// service sends it within a few seconds
int SubmitUploadFile(const AgentConfig &cfg, const std::string &hook_id, const std::string &file, bool send_now,
                   std::string &output);

// Sends every spooled file of every hook, oldest first. Returns 0 when
// nothing failed.
int SendPendingUploads(const AgentConfig &cfg, std::string &output);

// True (and clears the request) after "drra submit --now"
bool UploadSendNowRequested(const AgentConfig &cfg);

// UPLOADS report section: state of each upload hook, empty when there are none
std::string UploadReportSection(const AgentConfig &cfg);

#endif
