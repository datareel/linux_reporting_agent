// tlscheck.cpp
// drra selftest: which OpenSSL and libcurl the agent runs with, and
// with a URL, the TLS version, cipher and key exchange group a real
// connection gets. Also the TLS line logged with every HTTPS request.
//
// Builds (common.h): the RHEL 8 standard build has OpenSSL 3.5 and
// libcurl built in (DRRA_BUNDLED_OPENSSL) and needs OpenSSL 3.5 or later;
// the RHEL 8 FIPS build (DRRA_FIPS_BUILD) uses RHEL 8's OpenSSL 1.1.1 and
// libcurl; RHEL 9 and 10 builds use the system OpenSSL, 3.5 or later.
// In every build libcurl must use the same OpenSSL as the agent.

// C STD lib includes
#include <stdio.h>
#include <string.h>

// C++ STD lib includes
#include <string>

// 3pLibs includes
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <curl/curl.h>

// APP includes
#include "common.h"
#include "compat.h"
#include "tlscheck.h"

// The oldest OpenSSL a standard (not FIPS) build may use: 3.5.0, the 3.5 LTS
#define AGENT_MIN_OPENSSL 0x30500000L

struct TlsCapture {
  CURL *curl;
  std::string *summary;
};

// Key exchange group of the session, such as X25519MLKEM768 or x25519
static std::string SessionGroup(SSL *ssl)
{
  std::string name;
#if OPENSSL_VERSION_NUMBER >= 0x30200000L
  const char *g = SSL_get0_group_name(ssl);
  if(g) name = g;
#else
  EVP_PKEY *key = NULL;
  if(SSL_get_server_tmp_key(ssl, &key) && key) {
    int id = EVP_PKEY_id(key);
    if(id == EVP_PKEY_EC) {
      const EC_KEY *ec = EVP_PKEY_get0_EC_KEY(key);
      int nid = ec ? EC_GROUP_get_curve_name(EC_KEY_get0_group(ec)) : NID_undef;
      if(nid != NID_undef) name = OBJ_nid2sn(nid);
    }
    else {
      name = OBJ_nid2sn(id);
    }
    EVP_PKEY_free(key);
  }
#endif
  return name;
}

static size_t TlsCaptureHeader(char *data, size_t size, size_t nmemb, void *userp)
{
  // The TLS session is only sure to be there during the transfer
  TlsCapture *cap = (TlsCapture *)userp;
  if(cap->summary->empty()) {
    const struct curl_tlssessioninfo *ti = NULL;
    if(curl_easy_getinfo(cap->curl, CURLINFO_TLS_SSL_PTR, &ti) == CURLE_OK && ti &&
       ti->backend == CURLSSLBACKEND_OPENSSL && ti->internals) {
      SSL *ssl = (SSL *)ti->internals;
      std::string group = SessionGroup(ssl);
      *cap->summary = std::string(SSL_get_version(ssl)) + ", " + SSL_get_cipher_name(ssl) +
	", key exchange " + (group.empty() ? "(unknown)" : group);
    }
  }
  return size * nmemb;
}

// One per thread of requests; the agent makes one request at a time
static TlsCapture g_capture;

void AgentCurlTlsCapture(CURL *curl, std::string *summary)
{
  summary->clear();
  g_capture.curl = curl;
  g_capture.summary = summary;
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, TlsCaptureHeader);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &g_capture);
}

static size_t TlsCheckDiscard(char *data, size_t size, size_t nmemb, void *userp)
{
  return size * nmemb;
}

int TlsSelfTest(const std::string &url, const AgentConfig &cfg)
{
  int errors = 0;
  unsigned long run_num = OpenSSL_version_num();
  printf("%s %s\n", AGENT_NAME, AGENT_VERSION);
  printf("Build:           %s\n", AGENT_BUILD_VARIANT);
  printf("OpenSSL headers: %s\n", OPENSSL_VERSION_TEXT);
  printf("OpenSSL library: %s\n", OpenSSL_version(OPENSSL_VERSION));
  printf("OpenSSL dir:     %s\n", OpenSSL_version(OPENSSL_DIR));
  bool fips = HostFipsEnabled();
  printf("FIPS mode:       %s\n", fips ? "on (/proc/sys/crypto/fips_enabled = 1)" : "off");
#if defined(DRRA_FIPS_BUILD)
  // RHEL 8's own OpenSSL 1.1.1 (its FIPS module), never a newer one
  if((OPENSSL_VERSION_NUMBER & 0xfffff000L) != 0x10101000L) {
    printf("ERROR - the FIPS build must use RHEL 8's OpenSSL 1.1.1 headers\n");
    errors++;
  }
  if((run_num & 0xfffff000UL) != 0x10101000UL) {
    printf("ERROR - the FIPS build must run with RHEL 8's OpenSSL 1.1.1 library\n");
    errors++;
  }
  printf("OpenSSL FIPS:    %s\n", FIPS_mode() ? "on" : "off");
  if(fips && !FIPS_mode()) {
    printf("ERROR - FIPS mode is on but OpenSSL is not in FIPS mode\n");
    errors++;
  }
#else
  if(OPENSSL_VERSION_NUMBER < AGENT_MIN_OPENSSL) {
    printf("ERROR - built with OpenSSL headers older than 3.5\n");
    errors++;
  }
  if(run_num < (unsigned long)AGENT_MIN_OPENSSL) {
    printf("ERROR - running with an OpenSSL library older than 3.5\n");
    errors++;
  }
#if defined(DRRA_BUNDLED_OPENSSL)
  if(fips) {
    printf("ERROR - this build's OpenSSL is not FIPS validated and does not run in FIPS mode:\n"
	   "        use the FIPS build (alternatives --set drra %s)\n", AGENT_FIPS_BINARY);
    errors++;
  }
#endif
#endif
  printf("TLS groups:      %s\n", cfg.tls_groups.empty() ? "(OpenSSL and crypto policy defaults)" : cfg.tls_groups.c_str());

  curl_version_info_data *cv = curl_version_info(CURLVERSION_NOW);
  printf("libcurl:         %s (%s)\n", cv->version, cv->ssl_version ? cv->ssl_version : "no TLS");
  // libcurl says "OpenSSL/3.5.9": it must be the library this process runs
  std::string want = "OpenSSL/";
  const char *v = OpenSSL_version(OPENSSL_VERSION);   // "OpenSSL 3.5.9 1 Nov 2026"
  if(v && strncmp(v, "OpenSSL ", 8) == 0) {
    const char *e = strchr(v + 8, ' ');
    want += e ? std::string(v + 8, (size_t)(e - (v + 8))) : std::string(v + 8);
  }
  if(!cv->ssl_version || strncmp(cv->ssl_version, want.c_str(), want.length()) != 0) {
    printf("ERROR - libcurl does not use the same OpenSSL (%s)\n", want.c_str());
    errors++;
  }

  if(!url.empty()) {
    CURL *curl = curl_easy_init();
    std::string summary;
    char errbuf[CURL_ERROR_SIZE] = "";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, TlsCheckDiscard);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "DataReelReportAgentLinux/" AGENT_VERSION);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, cfg.verify_peer ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, cfg.verify_peer ? 2L : 0L);
    if(!cfg.ca_file.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, cfg.ca_file.c_str());
    AgentCurlProtocols(curl, true);
    AgentCurlTls(curl, cfg.tls_groups);
    AgentCurlTlsCapture(curl, &summary);
    CURLcode rc = curl_easy_perform(curl);
    long http = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http);
    curl_easy_cleanup(curl);
    printf("Connect:         %s\n", url.c_str());
    if(rc != CURLE_OK) {
      printf("ERROR - %s\n", errbuf[0] ? errbuf : curl_easy_strerror(rc));
      errors++;
    }
    else if(summary.empty()) {
      printf("HTTP %ld, no TLS session (not https?)\n", http);
    }
    else {
      printf("HTTP %ld, %s\n", http, summary.c_str());
    }
  }
  printf("%s\n", errors ? "FAILED" : "OK");
  return errors ? 1 : 0;
}
