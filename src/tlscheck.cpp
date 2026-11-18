// tlscheck.cpp
// drra selftest: which OpenSSL and libcurl the agent runs with, and
// with a URL, the TLS version, cipher and key exchange group a real
// connection gets.
//
// Release builds need OpenSSL 3.5 (the LTS) or later, at build time and
// at run time, and libcurl must use that same OpenSSL. On RHEL 8 the
// system libcurl uses OpenSSL 1.1.1, so the RHEL 8 RPM links a static
// libcurl built against EPEL's openssl3 (see rpm/linux_reporting_agent.spec).

// C STD lib includes
#include <stdio.h>
#include <string.h>

// C++ STD lib includes
#include <string>

// 3pLibs includes
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <curl/curl.h>

// APP includes
#include "common.h"
#include "compat.h"
#include "tlscheck.h"

// The oldest OpenSSL a release build may use: 3.5.0, the 3.5 LTS
#define AGENT_MIN_OPENSSL 0x30500000L

struct TlsInfo {
  CURL *curl;
  bool have;
  std::string protocol, cipher, group;
};

static size_t TlsCheckHeader(char *data, size_t size, size_t nmemb, void *userp)
{
  // The TLS session is only sure to be there during the transfer
  TlsInfo *info = (TlsInfo *)userp;
  if(!info->have) {
    const struct curl_tlssessioninfo *ti = NULL;
    if(curl_easy_getinfo(info->curl, CURLINFO_TLS_SSL_PTR, &ti) == CURLE_OK && ti &&
       ti->backend == CURLSSLBACKEND_OPENSSL && ti->internals) {
      SSL *ssl = (SSL *)ti->internals;
      info->protocol = SSL_get_version(ssl);
      info->cipher = SSL_get_cipher_name(ssl);
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
      const char *g = SSL_get0_group_name(ssl);
      info->group = g ? g : "";
#endif
      info->have = true;
    }
  }
  return size * nmemb;
}

static size_t TlsCheckDiscard(char *data, size_t size, size_t nmemb, void *userp)
{
  return size * nmemb;
}

int TlsSelfTest(const std::string &url, const std::string &ca_file, bool verify_peer)
{
  int errors = 0;
  unsigned long run_num = OpenSSL_version_num();
  printf("%s %s\n", AGENT_NAME, AGENT_VERSION);
  printf("OpenSSL headers: %s\n", OPENSSL_VERSION_TEXT);
  printf("OpenSSL library: %s\n", OpenSSL_version(OPENSSL_VERSION));
  printf("OpenSSL dir:     %s\n", OpenSSL_version(OPENSSL_DIR));
  if(OPENSSL_VERSION_NUMBER < AGENT_MIN_OPENSSL) {
    printf("ERROR - built with OpenSSL headers older than 3.5\n");
    errors++;
  }
  if(run_num < (unsigned long)AGENT_MIN_OPENSSL) {
    printf("ERROR - running with an OpenSSL library older than 3.5\n");
    errors++;
  }

  curl_version_info_data *cv = curl_version_info(CURLVERSION_NOW);
  printf("libcurl:         %s (%s)\n", cv->version, cv->ssl_version ? cv->ssl_version : "no TLS");
  // libcurl says "OpenSSL/3.5.5": it must be the library this process runs
  std::string want = "OpenSSL/";
  const char *v = OpenSSL_version(OPENSSL_VERSION);   // "OpenSSL 3.5.5 27 Jan 2026"
  if(v && strncmp(v, "OpenSSL ", 8) == 0) {
    const char *e = strchr(v + 8, ' ');
    want += e ? std::string(v + 8, (size_t)(e - (v + 8))) : std::string(v + 8);
  }
  if(!cv->ssl_version || strncmp(cv->ssl_version, want.c_str(), want.length()) != 0) {
    printf("ERROR - libcurl does not use the same OpenSSL (%s)\n", want.c_str());
    errors++;
  }

  if(!url.empty()) {
    TlsInfo info;
    info.curl = curl_easy_init();
    info.have = false;
    char errbuf[CURL_ERROR_SIZE] = "";
    curl_easy_setopt(info.curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(info.curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(info.curl, CURLOPT_HEADERFUNCTION, TlsCheckHeader);
    curl_easy_setopt(info.curl, CURLOPT_HEADERDATA, &info);
    curl_easy_setopt(info.curl, CURLOPT_WRITEFUNCTION, TlsCheckDiscard);
    curl_easy_setopt(info.curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(info.curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(info.curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(info.curl, CURLOPT_USERAGENT, "DataReelReportAgentLinux/" AGENT_VERSION);
    curl_easy_setopt(info.curl, CURLOPT_SSL_VERIFYPEER, verify_peer ? 1L : 0L);
    curl_easy_setopt(info.curl, CURLOPT_SSL_VERIFYHOST, verify_peer ? 2L : 0L);
    if(!ca_file.empty()) curl_easy_setopt(info.curl, CURLOPT_CAINFO, ca_file.c_str());
    AgentCurlProtocols(info.curl, true);
    AgentCurlTlsMin(info.curl);
    CURLcode rc = curl_easy_perform(info.curl);
    long http = 0;
    curl_easy_getinfo(info.curl, CURLINFO_RESPONSE_CODE, &http);
    curl_easy_cleanup(info.curl);
    printf("Connect:         %s\n", url.c_str());
    if(rc != CURLE_OK) {
      printf("ERROR - %s\n", errbuf[0] ? errbuf : curl_easy_strerror(rc));
      errors++;
    }
    else if(!info.have) {
      printf("HTTP %ld, no TLS session (not https?)\n", http);
    }
    else {
      printf("HTTP %ld, %s, %s, key exchange %s\n", http, info.protocol.c_str(), info.cipher.c_str(),
	     info.group.empty() ? "(unknown)" : info.group.c_str());
    }
  }
  printf("%s\n", errors ? "FAILED" : "OK");
  return errors ? 1 : 0;
}
