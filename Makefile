CC = gcc
RM = cmd /C del /Q
TARGET ?= SAv6_proxy.exe
SRC ?= SAv6_proxy.c

OPENSSL_ROOT ?= C:/Program Files/OpenSSL-Win64
OPENSSL_INCLUDE ?= $(OPENSSL_ROOT)/include
OPENSSL_LIBDIR ?= $(OPENSSL_ROOT)/lib/VC/x64/MD

CFLAGS ?= -Wall -Wextra
CPPFLAGS += -I"$(OPENSSL_INCLUDE)"
LDFLAGS += -L"$(OPENSSL_LIBDIR)"
LDLIBS += -l:libssl.lib -l:libcrypto.lib -lws2_32

.PHONY: all clean help run-help

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(CPPFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

run-help: $(TARGET)
	-./$(TARGET) --help

help:
	@echo make
	@echo make run-help
	@echo make clean
	@echo OPENSSL_ROOT defaults to "$(OPENSSL_ROOT)"

clean:
	-$(RM) "$(TARGET)"
