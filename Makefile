ifeq ($(origin CC),default)
CC = gcc
endif
PROXY_SRC ?= SAv6_proxy.c
PROXY_TLS_SRC ?= TLS_proxy.c
STATION_SRC ?= dummy_station.c

CFLAGS ?= -Wall -Wextra

ifeq ($(OS),Windows_NT)
EXEEXT ?= .exe
RM = cmd /C del /Q
OPENSSL_ROOT ?= C:/Program Files/OpenSSL-Win64
OPENSSL_INCLUDE_DIR ?= $(OPENSSL_ROOT)/include
OPENSSL_LIB_DIR ?= $(OPENSSL_ROOT)/lib/VC/x64/MD/
OPENSSL_CPPFLAGS ?= -I"$(OPENSSL_INCLUDE_DIR)"
OPENSSL_LDFLAGS ?= -L"$(OPENSSL_LIB_DIR)"
OPENSSL_LDLIBS ?= -l:libssl.lib -l:libcrypto.lib
SOCKET_LDLIBS ?= -lws2_32
else
EXEEXT ?=
RM = rm -f
PKG_CONFIG ?= pkg-config
OPENSSL_CPPFLAGS ?= $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LDFLAGS ?=
OPENSSL_LDLIBS ?= $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null)
ifeq ($(strip $(OPENSSL_LDLIBS)),)
OPENSSL_LDLIBS = -lssl -lcrypto
endif
SOCKET_LDLIBS ?=
endif

PROXY_TARGET ?= SAv6_proxy$(EXEEXT)
PROXY_TLS_TARGET ?= TLS_proxy$(EXEEXT)
STATION_TARGET ?= dummy_station$(EXEEXT)

PROXY_CPPFLAGS = $(OPENSSL_CPPFLAGS)
PROXY_LDFLAGS = $(OPENSSL_LDFLAGS)
PROXY_LDLIBS = $(OPENSSL_LDLIBS) $(SOCKET_LDLIBS) -lm
STATION_LDLIBS = $(SOCKET_LDLIBS)

.PHONY: all clean help proxy proxy-tls station run-help run-station-help

all: proxy proxy-tls station


proxy: $(PROXY_TARGET)

proxy-tls: $(PROXY_TLS_TARGET)

station: $(STATION_TARGET)

$(PROXY_TARGET): $(PROXY_SRC)
	$(CC) $(CFLAGS) $(PROXY_CPPFLAGS) $< $(PROXY_LDFLAGS) $(PROXY_LDLIBS) -o $@

$(PROXY_TLS_TARGET): $(PROXY_TLS_SRC)
	$(CC) $(CFLAGS) $(PROXY_CPPFLAGS) $< $(PROXY_LDFLAGS) $(PROXY_LDLIBS) -o $@

$(STATION_TARGET): $(STATION_SRC)
	$(CC) $(CFLAGS) $< $(STATION_LDLIBS) -o $@

run-help: $(PROXY_TARGET)
	-./$(PROXY_TARGET) --help

run-station-help: $(STATION_TARGET)
	-./$(STATION_TARGET) --help

help:
	@echo make
	@echo make proxy
	@echo make station
	@echo make run-help
	@echo make run-station-help
	@echo make clean
	@echo Override OpenSSL paths with OPENSSL_CPPFLAGS, OPENSSL_LDFLAGS, and OPENSSL_LDLIBS.
	@echo On Windows, OPENSSL_ROOT defaults to "$(OPENSSL_ROOT)".

clean:
	-$(RM) "$(PROXY_TARGET)"
	-$(RM) "$(PROXY_TLS_TARGET)"
	-$(RM) "$(STATION_TARGET)"
