#ifndef AGENT_AUTH_H
#define AGENT_AUTH_H

// Agent identity and signed uploads
//
// Each agent has an RSA key (agent_key.pem in data_dir, readable by root
// only) and a self-signed certificate for that key. The agent registers
// the certificate with register.php, and once the server approves it,
// every upload is signed with the key. upload.php checks the signature
// against the registered certificate. This is the same protocol as the
// DataReel Reporting Agent for Windows.

#include "common.h"
#include <utility>

#define AGENT_KEY_BITS 3072
#define AGENT_KEY_FILE "agent_key.pem"
#define AGENT_CERT_FILE "agent_cert.pem"
#define AGENT_STATE_FILE "registration_status.txt"

struct AgentIdentity {
  std::string hostname;           // lower case host name without the domain
  std::string cert_pem;           // self-signed certificate, PEM
  std::string key_fingerprint;    // SHA-256 of the public key (SPKI DER), hex
  void *pkey;                     // EVP_PKEY
};

typedef std::vector<std::pair<std::string, std::string> > FormFields;

// One file in a multipart upload
struct FormFile {
  std::string field;              // form field name
  std::string file_name;          // file name sent to the server
  std::string content_type;       // text/plain, text/html
  std::string content;
};

std::string Sha256Hex(const std::string &data);
std::string RandomHex(int nbytes);
int LoadOrCreateAgentIdentity(const AgentConfig &cfg, AgentIdentity &id, std::string &output);
void FreeAgentIdentity(AgentIdentity &id);
int SignString(const AgentIdentity &id, const std::string &data, std::string &sig_b64, std::string &output);
int HttpPostMultipart(const AgentConfig &cfg, const std::string &path, const FormFields &fields,
                      const std::vector<FormFile> &files, long &http_status, std::string &response, std::string &error);
std::string ParseStatus(const std::string &response);
std::string ReadRegistrationState(const AgentConfig &cfg);
void WriteRegistrationState(const AgentConfig &cfg, const std::string &state);
int RegisterAgent(const AgentConfig &cfg, const AgentIdentity &id, std::string &status, std::string &output);
std::string HookPagePath(const AgentConfig &cfg);
int UploadHook(const AgentConfig &cfg, const std::string &hook_id, const std::string &subject,
               const std::string &envelope, const FormFile &payload, std::string &status, std::string &output);
int UploadReport(const AgentConfig &cfg, const std::string &report, const std::vector<FormFile> &html_files, std::string &output);

#endif
