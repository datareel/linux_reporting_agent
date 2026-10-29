#ifndef COLLECT_H
#define COLLECT_H

#include "common.h"

// Report sections. Each function fills output with the lines between
// "NAME:" and "END NAME" and returns 0, or 1 when part of the data
// could not be read (the lines then say why with "ERROR - ").
int get_system_info(std::string &output);
int get_ip_addresses(std::string &output);
int get_performance(std::string &output, int cpu_sample_seconds);
int get_disk_usage(std::string &output);
int get_network_stats(std::string &output);
int get_logged_in_users(std::string &output);
int get_local_accounts(std::string &output);
int get_installed_packages(const AgentConfig &cfg, std::string &output, long long &newest_install);
int get_pending_updates(const AgentConfig &cfg, std::string &output, long long newest_install);
int get_security_settings(const AgentConfig &cfg, std::string &output);
int get_failed_services(const AgentConfig &cfg, std::string &output);

// Package manager: "rpm", "dpkg" or empty
std::string PackageManager();
// dnf, or yum on older releases, empty when neither is installed
std::string DnfProgram();
// Refreshes the dnf metadata cache when it is older than updates_refresh_hours
void RefreshPackageMetadata(const AgentConfig &cfg, std::string &output);

std::string BuildReport(const AgentConfig &cfg, std::string &output);

#endif
