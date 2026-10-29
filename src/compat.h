#ifndef COMPAT_H
#define COMPAT_H

// Builds on RHEL 8 (OpenSSL 1.1.1, libcurl 7.61), RHEL 9 (OpenSSL 3.0,
// libcurl 7.76) and RHEL 10 (OpenSSL 3.2 and later, libcurl 8)

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>

// Only http and https, for the request and any redirect
static inline void AgentCurlProtocols(CURL *curl, bool https_only_redirects)
{
#if LIBCURL_VERSION_NUM >= 0x075500
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
  curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, https_only_redirects ? "https" : "http,https");
#else
  curl_easy_setopt(curl, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS));
  curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, (long)(https_only_redirects ? CURLPROTO_HTTPS : (CURLPROTO_HTTP | CURLPROTO_HTTPS)));
#endif
}

static inline EVP_PKEY *AgentRsaGenerate(unsigned int bits)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  return EVP_RSA_gen(bits);
#else
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  if(ctx && EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, (int)bits) > 0) {
    EVP_PKEY_keygen(ctx, &pkey);
  }
  EVP_PKEY_CTX_free(ctx);
  return pkey;
#endif
}

static inline bool AgentKeysEqual(const EVP_PKEY *a, const EVP_PKEY *b)
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  return EVP_PKEY_eq(a, b) == 1;
#else
  return EVP_PKEY_cmp(a, b) == 1;
#endif
}

#endif
