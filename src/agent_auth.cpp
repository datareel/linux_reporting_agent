// C STD lib includes
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

// C++ STD lib includes
#include <string>
#include <vector>
#include <cctype>

// OpenSSL and libcurl
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <curl/curl.h>

// APP includes
#include "common.h"
#include "agent_auth.h"
#include "compat.h"

static std::string ToHex(const unsigned char *data, size_t len)
{
  static const char digits[] = "0123456789abcdef";
  std::string hex;
  hex.reserve(len * 2);
  for(size_t i = 0; i < len; i++) {
    hex += digits[data[i] >> 4];
    hex += digits[data[i] & 0x0f];
  }
  return hex;
}

static std::string OpenSslError()
{
  unsigned long e = ERR_get_error();
  if(e == 0) return "unknown OpenSSL error";
  char buf[256];
  ERR_error_string_n(e, buf, sizeof(buf));
  return buf;
}

std::string Sha256Hex(const std::string &data)
{
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  if(!EVP_Digest(data.data(), data.length(), md, &len, EVP_sha256(), NULL)) return std::string();
  return ToHex(md, len);
}

std::string RandomHex(int nbytes)
{
  std::vector<unsigned char> buf((size_t)nbytes);
  if(RAND_bytes(buf.data(), nbytes) != 1) return std::string();
  return ToHex(buf.data(), buf.size());
}

static std::string KeyFingerprint(EVP_PKEY *pkey)
{
  // SHA-256 of the DER SubjectPublicKeyInfo, the value admin.php shows
  unsigned char *der = NULL;
  int len = i2d_PUBKEY(pkey, &der);
  if(len <= 0) return std::string();
  std::string spki((const char *)der, (size_t)len);
  OPENSSL_free(der);
  return Sha256Hex(spki);
}

static int CreateSelfSignedCert(EVP_PKEY *pkey, const std::string &hostname, std::string &pem, std::string &output)
{
  X509 *x = X509_new();
  if(!x) {
    output += "ERROR - Could not create a certificate: " + OpenSslError() + "\n";
    return -1;
  }
  X509_set_version(x, 2);
  // Random positive serial number
  unsigned char serial[16];
  RAND_bytes(serial, sizeof(serial));
  serial[0] &= 0x7f;
  BIGNUM *bn = BN_bin2bn(serial, sizeof(serial), NULL);
  BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x));
  BN_free(bn);
  X509_gmtime_adj(X509_getm_notBefore(x), -3600);
  X509_gmtime_adj(X509_getm_notAfter(x), 20L * 365 * 24 * 3600);
  X509_set_pubkey(x, pkey);
  X509_NAME *name = X509_get_subject_name(x);
  // register.php requires the host name as the CN
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_UTF8, (const unsigned char *)"DataReel Reporting Agent", -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, (const unsigned char *)hostname.c_str(), -1, -1, 0);
  X509_set_issuer_name(x, name);
  if(!X509_sign(x, pkey, EVP_sha256())) {
    output += "ERROR - Could not sign the certificate: " + OpenSslError() + "\n";
    X509_free(x);
    return -1;
  }
  BIO *mem = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(mem, x);
  char *data = NULL;
  long len = BIO_get_mem_data(mem, &data);
  pem.assign(data, (size_t)len);
  BIO_free(mem);
  X509_free(x);
  return 0;
}

//
// Purpose:
//   Loads the agent key and certificate from data_dir, creating them on
//   the first run. The key file is readable by root only.
//
// Return value:
//   0 on success
//
int LoadOrCreateAgentIdentity(const AgentConfig &cfg, AgentIdentity &id, std::string &output)
{
  id.hostname = GetAgentHostname();
  id.pkey = NULL;
  id.cert_pem.clear();
  id.key_fingerprint.clear();

  if(!CreateDirTree(cfg.data_dir, 0700)) {
    output += "ERROR - Cannot create data directory " + cfg.data_dir + "\n";
    return -1;
  }
  chmod(cfg.data_dir.c_str(), 0700);

  std::string key_fname = JoinPath(cfg.data_dir, AGENT_KEY_FILE);
  std::string cert_fname = JoinPath(cfg.data_dir, AGENT_CERT_FILE);
  EVP_PKEY *pkey = NULL;

  FILE *fp = fopen(key_fname.c_str(), "r");
  if(fp) {
    pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if(!pkey) {
      output += "ERROR - Cannot read agent key " + key_fname + ": " + OpenSslError() + "\n";
      return -1;
    }
  }
  else {
    pkey = AgentRsaGenerate(AGENT_KEY_BITS);
    if(!pkey) {
      output += "ERROR - Could not create the agent key: " + OpenSslError() + "\n";
      return -1;
    }
    BIO *mem = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL);
    char *data = NULL;
    long len = BIO_get_mem_data(mem, &data);
    std::string key_pem(data, (size_t)len);
    BIO_free(mem);
    bool saved = WriteWholeFile(key_fname, key_pem, 0600);
    OPENSSL_cleanse(&key_pem[0], key_pem.length());
    if(!saved) {
      output += "ERROR - Cannot save agent key " + key_fname + "\n";
      EVP_PKEY_free(pkey);
      return -1;
    }
    output += "Created new agent key " + key_fname + "\n";
    // A new key needs a new certificate
    unlink(cert_fname.c_str());
  }

  // Reuse the certificate when it matches the key and the host name,
  // otherwise make a new one
  std::string pem;
  bool have_cert = false;
  if(ReadWholeFile(cert_fname, pem) && !pem.empty()) {
    BIO *mem = BIO_new_mem_buf(pem.data(), (int)pem.length());
    X509 *x = PEM_read_bio_X509(mem, NULL, NULL, NULL);
    BIO_free(mem);
    if(x) {
      EVP_PKEY *cert_key = X509_get0_pubkey(x);
      char cn[256] = "";
      X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, cn, sizeof(cn));
      have_cert = cert_key && AgentKeysEqual(cert_key, pkey) && id.hostname == cn;
      X509_free(x);
    }
  }
  if(!have_cert) {
    if(CreateSelfSignedCert(pkey, id.hostname, pem, output) != 0) {
      EVP_PKEY_free(pkey);
      return -1;
    }
    if(!WriteWholeFile(cert_fname, pem, 0644)) {
      output += "ERROR - Cannot save agent certificate " + cert_fname + "\n";
      EVP_PKEY_free(pkey);
      return -1;
    }
    output += "Created new agent certificate " + cert_fname + "\n";
  }

  id.cert_pem = pem;
  id.key_fingerprint = KeyFingerprint(pkey);
  id.pkey = pkey;
  return 0;
}

void FreeAgentIdentity(AgentIdentity &id)
{
  if(id.pkey) EVP_PKEY_free((EVP_PKEY *)id.pkey);
  id.pkey = NULL;
}

int SignString(const AgentIdentity &id, const std::string &data, std::string &sig_b64, std::string &output)
{
  sig_b64.clear();
  // RSA PKCS#1 v1.5 with SHA-256, checked in PHP with openssl_verify()
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  size_t len = 0;
  if(!ctx || EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, (EVP_PKEY *)id.pkey) != 1 ||
     EVP_DigestSign(ctx, NULL, &len, (const unsigned char *)data.data(), data.length()) != 1) {
    output += "ERROR - Could not sign data: " + OpenSslError() + "\n";
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  std::vector<unsigned char> sig(len);
  if(EVP_DigestSign(ctx, sig.data(), &len, (const unsigned char *)data.data(), data.length()) != 1) {
    output += "ERROR - Could not sign data: " + OpenSslError() + "\n";
    EVP_MD_CTX_free(ctx);
    return -1;
  }
  EVP_MD_CTX_free(ctx);

  std::vector<unsigned char> b64(4 * ((len + 2) / 3) + 1);
  int n = EVP_EncodeBlock(b64.data(), sig.data(), (int)len);
  sig_b64.assign((const char *)b64.data(), (size_t)n);
  return 0;
}

static size_t CurlWrite(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  std::string *s = (std::string *)userdata;
  s->append(ptr, size * nmemb);
  // Answers are a few lines, stop runaway responses
  if(s->length() > 65536) return 0;
  return size * nmemb;
}

int HttpPostMultipart(const AgentConfig &cfg, const std::string &path, const FormFields &fields,
		      const std::vector<FormFile> &files, long &http_status, std::string &response, std::string &error)
{
  http_status = 0;
  response.clear();
  error.clear();

  CURL *curl = curl_easy_init();
  if(!curl) {
    error = "ERROR - Could not initialize libcurl";
    return -1;
  }
  std::string url = std::string(cfg.use_https ? "https://" : "http://") + cfg.server_host + ":" +
    std::to_string(cfg.server_port) + path;

  curl_mime *mime = curl_mime_init(curl);
  for(const auto &field : fields) {
    curl_mimepart *part = curl_mime_addpart(mime);
    curl_mime_name(part, field.first.c_str());
    curl_mime_data(part, field.second.data(), field.second.length());
  }
  for(const FormFile &f : files) {
    curl_mimepart *part = curl_mime_addpart(mime);
    curl_mime_name(part, f.field.c_str());
    curl_mime_filename(part, f.file_name.c_str());
    curl_mime_type(part, f.content_type.c_str());
    curl_mime_data(part, f.content.data(), f.content.length());
  }

  std::string user_agent = "DataReelReportAgentLinux/" AGENT_VERSION;
  char errbuf[CURL_ERROR_SIZE] = "";
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)cfg.https_timeout_seconds);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, CurlWrite);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
  AgentCurlProtocols(curl, false);
  // Never follow redirects: a signed request goes only where it was meant to
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);
  if(cfg.use_https) {
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, cfg.verify_peer ? 1L : 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, cfg.verify_peer ? 2L : 0L);
    if(!cfg.ca_file.empty()) curl_easy_setopt(curl, CURLOPT_CAINFO, cfg.ca_file.c_str());
  }

  int error_level = 0;
  CURLcode rc = curl_easy_perform(curl);
  if(rc == CURLE_OK) {
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
  }
  else {
    error = "ERROR - Request to " + url + " failed: " + (errbuf[0] ? errbuf : curl_easy_strerror(rc));
    error_level = -1;
  }
  curl_mime_free(mime);
  curl_easy_cleanup(curl);
  return error_level;
}

// The server answers with a "STATUS: <word>" line, such as STATUS: approved
std::string ParseStatus(const std::string &response)
{
  size_t pos = response.find("STATUS: ");
  if(pos == std::string::npos) return std::string();
  pos += 8;
  std::string status;
  while(pos < response.length() && (std::isalnum((unsigned char)response[pos]) || response[pos] == '_')) {
    status += (char)std::tolower((unsigned char)response[pos]);
    pos++;
  }
  return status;
}

std::string ReadRegistrationState(const AgentConfig &cfg)
{
  std::string state;
  ReadWholeFile(JoinPath(cfg.data_dir, AGENT_STATE_FILE), state);
  return Trim(state);
}

void WriteRegistrationState(const AgentConfig &cfg, const std::string &state)
{
  WriteWholeFile(JoinPath(cfg.data_dir, AGENT_STATE_FILE), state + "\n", 0600);
}

int RegisterAgent(const AgentConfig &cfg, const AgentIdentity &id, std::string &status, std::string &output)
{
  status.clear();
  std::string timestamp = std::to_string((long long)time(NULL));
  std::string nonce = RandomHex(16);

  // Signing the request proves the agent holds the key for this certificate
  std::string to_sign = "register\n" + id.hostname + "\n" + timestamp + "\n" + nonce + "\n" + Sha256Hex(id.cert_pem);
  std::string signature;
  if(SignString(id, to_sign, signature, output) != 0) return -1;

  FormFields fields;
  fields.push_back(std::make_pair("hostname", id.hostname));
  fields.push_back(std::make_pair("timestamp", timestamp));
  fields.push_back(std::make_pair("nonce", nonce));
  fields.push_back(std::make_pair("cert", id.cert_pem));
  fields.push_back(std::make_pair("enrollment_token", cfg.enrollment_token));
  fields.push_back(std::make_pair("signature", signature));

  long http_status = 0;
  std::string response, error;
  if(HttpPostMultipart(cfg, cfg.register_path, fields, std::vector<FormFile>(), http_status, response, error) != 0) {
    output += error + "\n";
    return -1;
  }

  status = ParseStatus(response);
  if(status.empty()) {
    output += "ERROR - Unexpected answer from " + cfg.register_path + " (HTTP " + std::to_string(http_status) + "): " + response + "\n";
    return -1;
  }
  output += "Registration status from server: " + status + "\n";
  // Anything but approved or pending carries the reason on the next line
  if(status != "approved" && status != "pending") {
    output += "Server said (HTTP " + std::to_string(http_status) + "): " + Trim(response) + "\n";
  }
  return 0;
}

//
// Purpose:
//   Registers the agent when needed, then sends a signed report and,
//   after a new scan, the OpenSCAP HTML report
//
// Return value:
//   0 when the server saved the report
//
int UploadReport(const AgentConfig &cfg, const std::string &report, const std::vector<FormFile> &html_files, std::string &output)
{
  AgentIdentity id;
  if(LoadOrCreateAgentIdentity(cfg, id, output) != 0) return -1;

  // Register the agent certificate before sending anything. The server
  // must approve it, either by an admin or with the enrollment token.
  // The state names the key and the server, so a new key or a different
  // server (host, port or register page) means registering again
  std::string server_id = cfg.server_host + ":" + std::to_string(cfg.server_port) + cfg.register_path;
  std::string approved_state = "approved " + id.key_fingerprint + " " + server_id;
  if(ReadRegistrationState(cfg) != approved_state) {
    std::string status;
    if(RegisterAgent(cfg, id, status, output) != 0) {
      FreeAgentIdentity(id);
      return -1;
    }
    if(status != "approved") {
      WriteRegistrationState(cfg, status + " " + id.key_fingerprint + " " + server_id);
      output += "ERROR - Report not sent, this agent is " + status + " on the server. "
	"Approve host " + id.hostname + " with key fingerprint " + id.key_fingerprint + " on the admin page\n";
      FreeAgentIdentity(id);
      return -1;
    }
    WriteRegistrationState(cfg, approved_state);
  }

  // Sign the upload: hostname, time, a one time nonce, the report hash
  // and a "<field> <hash>" line for each OpenSCAP HTML report sent with it
  std::string timestamp = std::to_string((long long)time(NULL));
  std::string nonce = RandomHex(16);
  std::string to_sign = "upload\n" + id.hostname + "\n" + timestamp + "\n" + nonce + "\n" + Sha256Hex(report);
  for(const FormFile &h : html_files) to_sign += "\n" + h.field + " " + Sha256Hex(h.content);
  std::string signature;
  if(SignString(id, to_sign, signature, output) != 0) {
    FreeAgentIdentity(id);
    return -1;
  }
  std::string hostname = id.hostname;
  FreeAgentIdentity(id);

  FormFields fields;
  fields.push_back(std::make_pair("hostname", hostname));
  fields.push_back(std::make_pair("timestamp", timestamp));
  fields.push_back(std::make_pair("nonce", nonce));
  fields.push_back(std::make_pair("signature", signature));

  std::vector<FormFile> files;
  FormFile f;
  f.field = "uploadedFile";
  f.file_name = hostname + AGENT_REPORT_SUFFIX;
  f.content_type = "text/plain";
  f.content = report;
  files.push_back(f);
  for(const FormFile &h : html_files) files.push_back(h);

  long http_status = 0;
  std::string response, error;
  if(HttpPostMultipart(cfg, cfg.upload_path, fields, files, http_status, response, error) != 0) {
    output += error + "\n";
    return -1;
  }

  std::string status = ParseStatus(response);
  if(http_status == 200 && status == "ok") {
    output += "Upload successful: " + Trim(response) + "\n";
    return 0;
  }

  // The server no longer accepts this agent, so register again next cycle
  if(status == "not_registered" || status == "pending" || status == "revoked" || status == "key_mismatch") {
    WriteRegistrationState(cfg, "");
  }
  output += "ERROR - Upload rejected (HTTP " + std::to_string(http_status) + "): " + Trim(response) + "\n";
  return -1;
}
