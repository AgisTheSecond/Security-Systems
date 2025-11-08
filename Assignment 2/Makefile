# === Assignment 2 Makefile ===
CC = gcc
CFLAGS = -Wall -O2
LIBS_RSA = -lcrypto -lgmp
LIBS_ECDH = -lsodium

# === Targets ===

.PHONY: all clean perf
all:
	$(MAKE) rsa_assign_2
	$(MAKE) ecdh_assign_2


# RSA Compilation
rsa_assign_2: rsa_assign_2.c
	$(CC) $(CFLAGS) -o rsa_assign_2 rsa_assign_2.c $(LIBS_RSA)

# ECDH Compilation
ecdh_assign_2: ecdh_assign_2.c
	$(CC) $(CFLAGS) -o ecdh_assign_2 ecdh_assign_2.c $(LIBS_ECDH)

# Run Performance Analysis
perf: rsa_assign_2
	./rsa_assign_2 -a performance.txt

# Clean binaries
clean:
	rm -f rsa_assign_2 ecdh_assign_2 *.o performance.txt
