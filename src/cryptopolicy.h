// cryptopolicy.h
// The RHEL 8 openssl35 package follows the system crypto policy
// (cryptopolicy.cpp has the rules). Other builds use the system OpenSSL,
// which reads the policy itself, and these calls do nothing there.

#ifndef CRYPTOPOLICY_H
#define CRYPTOPOLICY_H

#include <string>
#include <vector>
#include <utility>
#include <curl/curl.h>
#include "common.h"

struct CryptoPolicy {
  bool found = false;                    // the policy's OpenSSL back-end was read
  std::string name;                      // DEFAULT, FUTURE, LEGACY, FIPS, ... (with sub-policies)
  std::string file;                      // the back-end file
  std::vector<std::pair<std::string, std::string> > settings;   // SSL_CONF commands applied
  std::vector<std::string> not_applied;  // settings OpenSSL 3.5 does not take
  std::vector<std::string> notes;        // changes, such as the TLS 1.2 floor
  std::string groups;                    // groups set from the policy, empty = OpenSSL or tls_groups
  std::string groups_rule;               // which rule picked them
};

// The policy, read once (NULL in builds that use the system OpenSSL)
const CryptoPolicy *SystemCryptoPolicy(const AgentConfig &cfg);

// Applies the policy to the TLS connections of curl
void AgentCurlCryptoPolicy(CURL *curl, const AgentConfig &cfg);

// One line for drra selftest and the log, empty in other builds
std::string CryptoPolicySummary(const AgentConfig &cfg);

#endif
