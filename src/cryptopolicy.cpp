// cryptopolicy.cpp
// The RHEL 8 openssl35 package has its own OpenSSL 3.5, which does not
// read RHEL's openssl.cnf. This file makes it follow the system crypto
// policy anyway: it reads the policy's OpenSSL back-end
// (/etc/crypto-policies/back-ends/opensslcnf.config) and applies each
// setting to every TLS connection with SSL_CONF, the same commands the
// system OpenSSL takes from that file.
//
// Rules:
//   CipherString, Ciphersuites, SignatureAlgorithms: as the policy says
//   TLS.MinProtocol, TLS.MaxProtocol: as the policy says, but never below
//     TLS 1.2, the agent's own floor (LEGACY allows TLS 1.0)
//   DTLS.*: not used, the agent speaks only TLS
//   Groups: [https] tls_groups when set; else the policy's Groups, with
//     X25519MLKEM768 put first when the policy is not FIPS and allows
//     X25519; else (RHEL 8's back-ends name no groups) OpenSSL 3.5's own
//     default list, which offers X25519MLKEM768 first, or with the FIPS
//     policy P-256:P-384:P-521
//   A setting OpenSSL 3.5 does not take is reported (drra selftest, the
//   log), never dropped silently.
// Other builds use the system OpenSSL, which reads the policy itself.

// C STD lib includes
#include <stdio.h>
#include <string.h>

// C++ STD lib includes
#include <string>
#include <vector>
#include <utility>

// 3pLibs includes
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <curl/curl.h>

// APP includes
#include "common.h"
#include "cryptopolicy.h"

#define POLICY_STATE_FILE "/etc/crypto-policies/state/current"
#define POLICY_OPENSSL_FILE "/etc/crypto-policies/back-ends/opensslcnf.config"

#if defined(DRRA_BUNDLED_OPENSSL)
static CryptoPolicy g_policy;
static bool g_loaded = false;

static std::string TrimStr(const std::string &s)
{
  size_t b = 0, e = s.length();
  while(b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r' || s[b] == '\n')) b++;
  while(e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r' || s[e - 1] == '\n')) e--;
  return s.substr(b, e - b);
}

static int ProtocolRank(const std::string &v)
{
  if(v == "TLSv1.3") return 4;
  if(v == "TLSv1.2") return 3;
  if(v == "TLSv1.1") return 2;
  if(v == "TLSv1") return 1;
  return 0;
}

// Try one SSL_CONF command on a scratch context
static bool CommandWorks(const std::string &cmd, const std::string &value)
{
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if(!ctx) return false;
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_CLIENT);
  SSL_CONF_CTX_set_ssl_ctx(cctx, ctx);
  int rv = SSL_CONF_cmd(cctx, cmd.c_str(), value.c_str());
  bool ok = rv > 0 && SSL_CONF_CTX_finish(cctx) == 1;
  SSL_CONF_CTX_free(cctx);
  SSL_CTX_free(ctx);
  ERR_clear_error();
  return ok;
}

static void LoadPolicy(const AgentConfig &cfg)
{
  CryptoPolicy &p = g_policy;
  p = CryptoPolicy();
  FILE *fp = fopen(POLICY_STATE_FILE, "r");
  if(fp) {
    char buf[256] = "";
    if(fgets(buf, sizeof(buf), fp)) p.name = TrimStr(buf);
    fclose(fp);
  }
  p.file = POLICY_OPENSSL_FILE;
  std::string base = p.name.substr(0, p.name.find(':'));
  bool fips_policy = (base == "FIPS");

  std::string policy_groups;
  fp = fopen(POLICY_OPENSSL_FILE, "r");
  if(fp) {
    p.found = true;
    char line[4096];
    while(fgets(line, sizeof(line), fp)) {
      std::string l = TrimStr(line);
      if(l.empty() || l[0] == '#' || l[0] == '[') continue;
      size_t eq = l.find('=');
      if(eq == std::string::npos) {
	p.not_applied.push_back(l + " (not a setting)");
	continue;
      }
      std::string key = TrimStr(l.substr(0, eq)), value = TrimStr(l.substr(eq + 1));
      if(key.compare(0, 5, "DTLS.") == 0) continue;   // not used
      if(key == "TLS.MinProtocol") key = "MinProtocol";
      else if(key == "TLS.MaxProtocol") key = "MaxProtocol";
      else if(key == "Curves") key = "Groups";
      if(key == "Groups") {
	policy_groups = value;
	continue;
      }
      if(key == "MinProtocol" && ProtocolRank(value) < 3) {
	p.notes.push_back("MinProtocol " + value + " raised to TLSv1.2, the agent's floor");
	value = "TLSv1.2";
      }
      if(CommandWorks(key, value)) p.settings.push_back(std::make_pair(key, value));
      else p.not_applied.push_back(key + " = " + value);
    }
    fclose(fp);
  }

  // The groups
  if(!cfg.tls_groups.empty()) {
    p.groups_rule = "[https] tls_groups";
    p.groups.clear();   // AgentCurlTls sets them
  }
  else if(!policy_groups.empty()) {
    std::string g = policy_groups;
    std::string lower = g;
    for(char &c : lower) c = (char)tolower((unsigned char)c);
    if(!fips_policy && lower.find("x25519") != std::string::npos && lower.find("mlkem") == std::string::npos) {
      g = "X25519MLKEM768:" + g;
      p.groups_rule = "the policy's groups, X25519MLKEM768 first";
    }
    else {
      p.groups_rule = "the policy's groups";
    }
    p.groups = g;
  }
  else if(fips_policy) {
    p.groups = "P-256:P-384:P-521";
    p.groups_rule = "FIPS policy: FIPS-approved groups only";
  }
  else {
    p.groups.clear();
    p.groups_rule = "OpenSSL 3.5 defaults, X25519MLKEM768 first (the policy names no groups)";
  }
  if(!p.groups.empty()) {
    if(CommandWorks("Groups", p.groups)) p.settings.push_back(std::make_pair("Groups", p.groups));
    else p.not_applied.push_back("Groups = " + p.groups);
  }
}

#endif

const CryptoPolicy *SystemCryptoPolicy(const AgentConfig &cfg)
{
#if defined(DRRA_BUNDLED_OPENSSL)
  if(!g_loaded) {
    LoadPolicy(cfg);
    g_loaded = true;
  }
  return &g_policy;
#else
  (void)cfg;
  return NULL;
#endif
}

#if defined(DRRA_BUNDLED_OPENSSL)
static CURLcode PolicySslCtx(CURL *curl, void *sslctx, void *userp)
{
  const CryptoPolicy *p = (const CryptoPolicy *)userp;
  SSL_CONF_CTX *cctx = SSL_CONF_CTX_new();
  SSL_CONF_CTX_set_flags(cctx, SSL_CONF_FLAG_FILE | SSL_CONF_FLAG_CLIENT);
  SSL_CONF_CTX_set_ssl_ctx(cctx, (SSL_CTX *)sslctx);
  for(const auto &kv : p->settings) SSL_CONF_cmd(cctx, kv.first.c_str(), kv.second.c_str());
  SSL_CONF_CTX_finish(cctx);
  SSL_CONF_CTX_free(cctx);
  // The agent's own floor, whatever the policy says
  if(SSL_CTX_get_min_proto_version((SSL_CTX *)sslctx) < TLS1_2_VERSION) {
    SSL_CTX_set_min_proto_version((SSL_CTX *)sslctx, TLS1_2_VERSION);
  }
  ERR_clear_error();
  return CURLE_OK;
}
#endif

void AgentCurlCryptoPolicy(CURL *curl, const AgentConfig &cfg)
{
#if defined(DRRA_BUNDLED_OPENSSL)
  const CryptoPolicy *p = SystemCryptoPolicy(cfg);
  if(p && p->found) {
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, PolicySslCtx);
    curl_easy_setopt(curl, CURLOPT_SSL_CTX_DATA, (void *)p);
  }
#else
  (void)curl;
  (void)cfg;
#endif
}

std::string CryptoPolicySummary(const AgentConfig &cfg)
{
  const CryptoPolicy *p = SystemCryptoPolicy(cfg);
  if(!p) return std::string();
  if(!p->found) return "Crypto policy: " + (p->name.empty() ? std::string("(none)") : p->name) + ", " + p->file +
		  " not found: OpenSSL 3.5 defaults with TLS 1.2 or later";
  std::string s = "Crypto policy: " + p->name + " (" + p->file + "), " + std::to_string(p->settings.size()) +
    " settings applied; groups: " + p->groups_rule;
  for(const std::string &n : p->notes) s += "; " + n;
  if(!p->not_applied.empty()) {
    s += "; NOT applied (OpenSSL 3.5 does not take them):";
    for(const std::string &n : p->not_applied) s += " [" + n + "]";
  }
  return s;
}
