# DataReel Reporting Agent for Linux
# Build with: make          Install with: make install DESTDIR=...
# Needs: gcc-c++ openssl-devel libcurl-devel libxml2-devel bzip2-devel

CXX      ?= g++
CXXFLAGS ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CXXFLAGS += -std=c++17 $(shell pkg-config --cflags libxml-2.0)
LIBS      = -lssl -lcrypto -lcurl -lbz2 $(shell pkg-config --libs libxml-2.0)

PREFIX     ?= /usr
SBINDIR    ?= $(PREFIX)/sbin
SYSCONFDIR ?= /etc
UNITDIR    ?= /usr/lib/systemd/system
DOCDIR     ?= $(PREFIX)/share/doc/linux_reporting_agent

OBJS = src/drra.o src/common.o src/agent_auth.o src/collect.o src/deliver.o src/scan.o

all: drra

drra: $(OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

src/%.o: src/%.cpp src/*.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

install: drra
	install -D -m 0755 drra $(DESTDIR)$(SBINDIR)/drra
	install -D -m 0600 drra.ini $(DESTDIR)$(SYSCONFDIR)/drra/drra.ini
	install -D -m 0644 systemd/drra.service $(DESTDIR)$(UNITDIR)/drra.service
	install -D -m 0644 systemd/drra.logrotate $(DESTDIR)$(SYSCONFDIR)/logrotate.d/drra
	install -d -m 0700 $(DESTDIR)/var/lib/drra
	install -d -m 0750 $(DESTDIR)/var/log/drra

clean:
	rm -f drra src/*.o

.PHONY: all install clean
