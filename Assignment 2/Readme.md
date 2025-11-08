#  Assignment 2 — Security Systems

##  Authors
- **Charalampos Mylonakis** — 202030133  
- **Agisilaos Fotinakis** — 2022030190  

---

##  Overview
This project implements two major cryptographic mechanisms in C:

1. **Elliptic Curve Diffie–Hellman (ECDH)** with Key Derivation using **libsodium**
2. **RSA (Rivest–Shamir–Adleman)** with **Digital Signatures** and **Performance Analysis** using **GMP** and **OpenSSL**

Both tools are command-line programs built fully from scratch, following the specifications of the assignment.

---

##  Task 1 — ECDH Key Exchange with Key Derivation (KDF)

### **File:** `ecdh_assign_2.c`

Implements a complete **Elliptic Curve Diffie–Hellman key exchange** using Curve25519 and derives two symmetric keys via libsodium’s KDF.

### **Main Features**
- Uses **libsodium** built-in Curve25519 (`crypto_scalarmult_base`)
- Optional manual hex private keys for Alice and Bob
- Derives:
  - **Encryption Key** (32 bytes)
  - **MAC Key** (32 bytes)
- Outputs all values in hexadecimal format

---

### **Usage**
```bash
# Random key generation
./ecdh_assign_2 -o ecdh_output.txt

# With fixed private keys
./ecdh_assign_2 -o ecdh_output.txt -a 0x1a2b3c -b 0x1a2cb7

# With custom KDF context
./ecdh_assign_2 -o ecdh_output.txt -a 0x1a2b3c -b 0x1a2cb7 -c "koukou25"
```

### **Example Output**
```
Alice's Public Key:
9ffb17b364f12b40f335e802fe02983f295b679ce291785181f122764ea80370
Bob's Public Key:
cb4a27e877b8d5572fa4b9e92a8d8b5f892ac87f58ed053f116b0dc20fe80278
Shared Secret (Alice):
afc0b79e89270b54ac24e161434b7b99eedeeda2ee7907548b2502adf63ed40c
Shared Secret (Bob):
afc0b79e89270b54ac24e161434b7b99eedeeda2ee7907548b2502adf63ed40c
Shared secrets match!
Derived Encryption Key (Alice):
3b8f9c2e5a7d1f4e6b2c8a9e4d1f7c3a5b8e2f9c6d3a7e1f4b8c2e9a5d1f7c3a
Derived MAC Key (Alice):
7c3a5b8e2f9c6d3a7e1f4b8c2e9a5d1f3b8f9c2e5a7d1f4e6b2c8a9e4d1f7c3a
```

---

##  Task 2 — RSA Algorithm with Digital Signatures and Performance Analysis

### **File:** `rsa_assign_2.c`

Implements the **RSA cryptosystem** using GMP for big integer operations and OpenSSL for SHA-256 hashing.  
Includes key generation, encryption/decryption, digital signing & verification, and a performance benchmark.

---

### **Implemented Functions**

| Function | Description |
|-----------|--------------|
| **`rsa_generate_keys()`** | Generates RSA key pair (`n`, `e`, `d`) given key length (1024/2048/4096) |
| **`rsa_crypt()`** | Performs encryption/decryption of files via modular exponentiation |
| **`rsa_sign()`** | Computes SHA-256 hash of input and signs it (`hash^d mod n`) |
| **`rsa_verify()`** | Verifies signature (`sig^e mod n`) and compares with SHA-256 hash |
| **`rsa_performance()`** | Measures encryption, decryption, signing and verification times for three key lengths |

---

### **Command-Line Options**

| Option | Description |
|--------|--------------|
| `-g <bits>` | Generate RSA key pair (1024, 2048, 4096) |
| `-i <path>` | Input file path |
| `-o <path>` | Output file path |
| `-k <path>` | Key file (public/private) |
| `-e` | Encrypt input using key |
| `-d` | Decrypt input using key |
| `-s` | Sign input file (private key) |
| `-v <sigfile>` | Verify signature (public key) |
| `-a <file>` | Run performance analysis and save to file |
| `-h` | Show help message |

---

### **Usage Examples**

####  Key Generation
```bash
./rsa_assign_2 -g 2048
```
Creates: `public_2048.key`, `private_2048.key`

####  Encryption
```bash
./rsa_assign_2 -i plaintext.txt -o ciphertext.bin -k public_2048.key -e
```

####  Decryption
```bash
./rsa_assign_2 -i ciphertext.bin -o decrypted.txt -k private_2048.key -d
```

####  Sign a file
```bash
./rsa_assign_2 -i input.txt -o signature.sig -k private_2048.key -s
```

####  Verify a signature
```bash
./rsa_assign_2 -i input.txt -k public_2048.key -v signature.sig
```

#### Performance Analysis
```bash
./rsa_assign_2 -a performance.txt
```

---

### **Performance Output Example**
```
Key Length: 1024 bits
Encryption Time: 0.0000s
Decryption Time: 0.0015s
Signing Time: 0.0008s
Verification Time: 0.0000s
Peak Memory Usage (Encryption): 12 KB
Peak Memory Usage (Decryption): 10 KB
Peak Memory Usage (Signing): 11 KB
Peak Memory Usage (Verification): 9 KB

Key Length: 2048 bits
Encryption Time: 0.0000s
Decryption Time: 0.0054s
Signing Time: 0.0063s
Verification Time: 0.0000s
Peak Memory Usage (Encryption): 25 KB
Peak Memory Usage (Decryption): 23 KB
Peak Memory Usage (Signing): 24 KB
Peak Memory Usage (Verification): 22 KB

Key Length: 4096 bits
Encryption Time: 0.0003s
Decryption Time: 0.0856s
Signing Time: 0.0259s
Verification Time: 0.0002s
Peak Memory Usage (Encryption): 50 KB
Peak Memory Usage (Decryption): 47 KB
Peak Memory Usage (Signing): 48 KB
Peak Memory Usage (Verification): 45 KB
```

---

##   Compilation
### Manual Compilation
```bash
gcc -Wall -O2 -o ecdh_assign_2 ecdh_assign_2.c -lsodium
gcc -Wall -O2 -o rsa_assign_2 rsa_assign_2.c -lcrypto -lgmp
```

---



##  Libraries Used

| Library | Purpose |
|----------|----------|
| **libsodium** | Curve25519 ECDH and Key Derivation |
| **GMP** | Arbitrary-precision integer arithmetic for RSA |
| **OpenSSL** | SHA-256 hashing for digital signatures |

---

## Authors 

| Name | Student ID |  |
|------|-------------|--------------|
| **Charalampos Mylonakis** | 202030133 | 
| **Agisilaos Fotinakis** | 2022030190 | 

---

