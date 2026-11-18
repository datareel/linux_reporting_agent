// tlscheck.h
// drra selftest: OpenSSL and libcurl versions, and a test connection

#ifndef TLSCHECK_H
#define TLSCHECK_H

#include <string>

// Prints the OpenSSL and libcurl in use and, when url is set, the TLS
// version, cipher and key exchange group of a connection to it.
// Returns 0 when OpenSSL is 3.5 or later at build and run time, libcurl
// uses that same OpenSSL, and the connection (if any) worked.
int TlsSelfTest(const std::string &url, const std::string &ca_file, bool verify_peer);

#endif
