// tlscheck.h
// drra selftest: OpenSSL and libcurl versions, and a test connection

#ifndef TLSCHECK_H
#define TLSCHECK_H

#include <string>
#include <curl/curl.h>
#include "common.h"

// The RHEL 8 package for hosts in FIPS mode (the system OpenSSL 1.1.1);
// the openssl35 package refuses to run in FIPS mode
#define AGENT_FIPS_PACKAGE "linux_reporting_agent"

// Prints the build, OpenSSL and libcurl in use and, when url is set, the
// TLS version, cipher and key exchange group of a connection to it.
// Returns 0 when the OpenSSL fits the build (3.5 or later, or RHEL 8's
// 1.1.1 for the FIPS build), libcurl uses that same OpenSSL, the standard
// build is not in FIPS mode, and the connection (if any) worked.
int TlsSelfTest(const std::string &url, const AgentConfig &cfg);

// Puts "TLSv1.3, <cipher>, key exchange <group>" in *summary during the
// next transfer on curl (sets the header callback)
void AgentCurlTlsCapture(CURL *curl, std::string *summary);

#endif
