#ifndef HOOKS_H
#define HOOKS_H

// Report hooks: site scripts whose output goes in the report
//
// Every executable file in [hooks] dir (default /etc/drra/report.d) runs
// once per report, one at a time, each stopped after timeout_seconds.
// A hook prints what DRSM should show, in the DRSM plugin format
// (INFO -, WARNING -, ERROR -, METRIC and DETAIL lines and free text),
// and exits 0 OK, 1 WARNING, 2 ERROR or 3 UNKNOWN. The report gets one
// HOOKS section:
//
//   HOOKS:
//   hook=drcm exit=0 secs=1 timed_out=0 truncated=0
//   | INFO - node1 cluster status is HEALTHY
//   | ...
//   skipped=bad.sh reason="group or world writable"
//   END HOOKS
//
// Output lines are prefixed with "| ", so no hook output can end the
// section early. The agent runs as root, so a hook only runs when the
// directory and the file are owned by root and not writable by group
// or others, and its name is letters, digits, dot, dash or underscore
// (editor backups and rpm leftovers are skipped). [hooks] user= runs
// them as another user instead of root.

#include "common.h"

std::string HookReportSection(const AgentConfig &cfg, std::string &output);

#endif // HOOKS_H
