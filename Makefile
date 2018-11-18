CC=gcc
CFLAGS=-g -O2 -Wall
CPPFLAGS= -I. -Ishared -I/usr/include/libnm
CPPFLAGS += $(shell pkg-config --cflags-only-I openssl)
CPPFLAGS += $(shell pkg-config --cflags-only-I nss)
CPPFLAGS += $(shell pkg-config --cflags-only-I libnm)

LDFLAGS := $(shell pkg-config --libs openssl)
LDFLAGS += $(shell pkg-config --libs nss)
LDFLAGS += $(shell pkg-config --libs libnm)

all: test-nm-l2tp-crypto

.c.o:
	$(CC) -g -c $(CPPFLAGS) $(CFLAGS) $<


nm-l2tp-openssl.o : nm-l2tp-crypto-openssl.c nm-l2tp-crypto-openssl.h

nm-l2tp-nss.o : nm-l2tp-crypto-nss.c nm-l2tp-crypto-nss.h

test-nm-l2tp-crypto.o : test-nm-l2tp-crypto.c nm-l2tp-crypto-openssl.h nm-l2tp-crypto-nss.h

test-nm-l2tp-crypto: nm-l2tp-crypto-openssl.o nm-l2tp-crypto-nss.o test-nm-l2tp-crypto.o
	$(CC) $^ -o $@ $(LDFLAGS)


.PHONY: clean
clean :
	rm -f *.o test-nm-l2tp-crypto
	rm -rf nss-db pem-output
