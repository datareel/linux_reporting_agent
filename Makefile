# DataReel Reporting Agent for Linux
# Build with: make          Install with: make install DESTDIR=...
# Needs: gcc-c++ openssl-devel libcurl-devel libxml2-devel bzip2-devel zlib-devel
#
# Release builds need OpenSSL 3.5 or later. On RHEL 8 the RPM spec builds
# a static libcurl against EPEL's openssl3 and passes:
#   make SSL_CFLAGS="$(pkg-config --cflags openssl3)" SSL_LIBS="$(pkg-config --libs openssl3)" \
#        CURL_CFLAGS=-I<curl>/include CURL_LIBS="<curl>/lib/libcurl.a -lz -lpthread"
# "make check-openssl" fails unless drra and every library it loads use
# OpenSSL 3.5 or later (tools/check_openssl.sh).

CXX      ?= g++
CXXFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
# Kept apart from CXXFLAGS, so "make CXXFLAGS=..." (rpmbuild) keeps them
SSL_CFLAGS  ?=
SSL_LIBS    ?= -lssl -lcrypto
CURL_CFLAGS ?=
CURL_LIBS   ?= -lcurl
# CURL_CFLAGS and SSL_CFLAGS come first so their headers win over /usr/include
AGENT_CXXFLAGS = -std=c++17 $(CURL_CFLAGS) $(SSL_CFLAGS) $(shell pkg-config --cflags libxml-2.0)
LIBS      = $(CURL_LIBS) $(SSL_LIBS) -lbz2 -lz $(shell pkg-config --libs libxml-2.0)
MIN_OPENSSL ?= 3.5

PREFIX     ?= /usr
SBINDIR    ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc
UNITDIR    ?= /usr/lib/systemd/system
DOCDIR     ?= $(PREFIX)/share/doc/linux_reporting_agent

OBJS = src/drra.o src/common.o src/agent_auth.o src/collect.o src/deliver.o src/scan.o src/hooks.o src/uploads.o src/tlscheck.o

all: drra

drra: $(OBJS)
	$(CXX) $(CXXFLAGS) $(AGENT_CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

src/%.o: src/%.cpp src/*.h
	$(CXX) $(CXXFLAGS) $(AGENT_CXXFLAGS) -c -o $@ $<

install: drra
	install -D -m 0755 drra $(DESTDIR)$(SBINDIR)/drra
	install -D -m 0600 drra.ini $(DESTDIR)$(SYSCONFDIR)/drra/drra.ini
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/drra/report.d
	install -D -m 0644 systemd/drra.service $(DESTDIR)$(UNITDIR)/drra.service
	install -D -m 0644 systemd/drra.logrotate $(DESTDIR)$(SYSCONFDIR)/logrotate.d/drra
	install -d -m 0700 $(DESTDIR)/var/lib/drra
	install -d -m 0750 $(DESTDIR)/var/log/drra
	install -d -m 0700 $(DESTDIR)$(SYSCONFDIR)/drra/uploads.d
	install -d -m 0755 $(DESTDIR)/var/spool/drra
	install -d -m 2770 $(DESTDIR)/var/spool/drra/uploads

check-openssl: drra
	tools/check_openssl.sh ./drra $(MIN_OPENSSL)

clean:
	rm -f drra src/*.o

.PHONY: all install check-openssl clean
