#ifndef DELIVER_H
#define DELIVER_H

#include "common.h"
#include "agent_auth.h"

// Sends the report with every method in [delivery] methods. html_files
// is cleared when at least one method delivered the HTML scan reports.
int DeliverReport(const AgentConfig &cfg, const std::string &report_file, const std::string &report,
                  const std::string &hostname, std::vector<FormFile> &html_files, std::string &output);

#endif
