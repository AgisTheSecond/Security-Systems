#include <gmp.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>  // getrusage
#include <unistd.h>

// ------------------------------------------------------
// Utilities
void die(const char *msg) { fprintf(stderr, "Error: %s\n", msg); exit(1); }



// RSA Key Generation
void rsa_generate_keys(mpz_t n, mpz_t e, mpz_t d, unsigned int key_bits) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));

    mpz_t p, q, lambda, p1, q1, gcd;
    mpz_inits(p, q, lambda, p1, q1, gcd, NULL);

    unsigned int half_bits = key_bits / 2;
    mpz_urandomb(p, state, half_bits);
    mpz_nextprime(p, p);
    mpz_urandomb(q, state, half_bits);
    mpz_nextprime(q, q);

    mpz_mul(n, p, q);
    mpz_sub_ui(p1, p, 1);
    mpz_sub_ui(q1, q, 1);
    mpz_mul(lambda, p1, q1);

    mpz_set_ui(e, 65537);
    mpz_gcd(gcd, e, lambda);
    if (mpz_cmp_ui(gcd, 1) != 0)
        die("e and λ(n) not coprime");
    if (mpz_invert(d, e, lambda) == 0)
        die("No modular inverse found");

    mpz_clears(p, q, lambda, p1, q1, gcd, NULL);
    gmp_randclear(state);
}


// Save keys
void save_key(const char *filename, mpz_t n, mpz_t exp) {
    FILE *f = fopen(filename, "w");
    if (!f) die("Cannot write key file");
    gmp_fprintf(f, "%Zx\n%Zx\n", n, exp);
    fclose(f);
}

//Load keys
void load_key(const char *filename, mpz_t n, mpz_t exp) {
    FILE *f = fopen(filename, "r");
    if (!f) die("Cannot read key file");
    gmp_fscanf(f, "%Zx\n%Zx\n", n, exp);
    fclose(f);
}


// Encrypt / Decrypt
void rsa_crypt(const char *infile, const char *outfile, mpz_t n, mpz_t exp) {
    FILE *in = fopen(infile, "rb");
    if (!in) die("Cannot open input file");

    fseek(in, 0, SEEK_END);
    long len = ftell(in);
    rewind(in);
    unsigned char *buf = malloc(len);
    if (fread(buf, 1, len, in) != (size_t)len)
        die("File read error");
    fclose(in);

    mpz_t msg, res;
    mpz_inits(msg, res, NULL);
    mpz_import(msg, len, 1, 1, 0, 0, buf);
    mpz_powm(res, msg, exp, n);

    size_t out_len;
    unsigned char *out_buf = (unsigned char *)mpz_export(NULL, &out_len, 1, 1, 0, 0, res);

    FILE *out = fopen(outfile, "wb");
    if (!out) die("Cannot open output file");
    fwrite(out_buf, 1, out_len, out);
    fclose(out);

    free(buf);
    free(out_buf);
    mpz_clears(msg, res, NULL);
}


// SHA256 hash helper (EVP API for OpenSSL 3)
void compute_sha256(const char *filename, unsigned char hash[SHA256_DIGEST_LENGTH]) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        // Creates a new one if it doesn't exist
        printf("File '%s' not found. Creating a new one...\n", filename);
        FILE *newf = fopen(filename, "w");
        if (!newf) die("Cannot create input file");
        fprintf(newf, "Auto-generated test file for RSA signing.\n");
        fclose(newf);
        // Open file again for hashing
        f = fopen(filename, "rb");
        if (!f) die("Still cannot open input after creation!");
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) die("EVP_MD_CTX_new failed");
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1)
        die("EVP_DigestInit_ex failed");

    unsigned char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), f)) != 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1)
            die("EVP_DigestUpdate failed");
    }

    unsigned int outlen;
    if (EVP_DigestFinal_ex(mdctx, hash, &outlen) != 1)
        die("EVP_DigestFinal_ex failed");

    EVP_MD_CTX_free(mdctx);
    fclose(f);
}


// RSA Sign (SHA256 + private key)
void rsa_sign(const char *infile, const char *sigfile, mpz_t n, mpz_t d) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    compute_sha256(infile, hash);

    mpz_t h, sig;
    mpz_inits(h, sig, NULL);
    mpz_import(h, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);
    mpz_powm(sig, h, d, n);

    FILE *out = fopen(sigfile, "w");
    if (!out) die("Cannot open signature file");
    gmp_fprintf(out, "%Zx\n", sig);
    fclose(out);

    mpz_clears(h, sig, NULL);
}


// RSA Verify
void rsa_verify(const char *infile, const char *sigfile, mpz_t n, mpz_t e) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    compute_sha256(infile, hash);

    mpz_t h, sig, h_check;
    mpz_inits(h, sig, h_check, NULL);
    mpz_import(h, SHA256_DIGEST_LENGTH, 1, 1, 0, 0, hash);

    FILE *sf = fopen(sigfile, "r");
    if (!sf) die("Cannot open signature file");
    gmp_fscanf(sf, "%Zx", sig);
    fclose(sf);

    mpz_powm(h_check, sig, e, n);

    if (mpz_cmp(h, h_check) == 0)
        printf("Signature is VALID \n");
    else
        printf("Signature is INVALID \n");

    mpz_clears(h, sig, h_check, NULL);
}


// Performance Test
void rsa_performance(const char *outfile) {

    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    //Key generation for 1024,2048,4096 bits
    rsa_generate_keys(n ,e ,d ,1024);
    char pub1[64], priv1[64];
    sprintf(pub1, "public_%d.key", 1024);
    sprintf(priv1, "private_%d.key", 1024);
    save_key(pub1, n, e);
    save_key(priv1, n, d);
    printf("Generated %d-bit key pair.\n", 1024);

    rsa_generate_keys(n ,e ,d ,2048);
    char pub2[64], priv2[64];
    sprintf(pub2, "public_%d.key", 2048);
    sprintf(priv2, "private_%d.key", 2048);
    save_key(pub2, n, e);
    save_key(priv2, n, d);
    printf("Generated %d-bit key pair.\n", 2048);

    rsa_generate_keys(n ,e ,d ,4096);
    char pub3[64], priv3[64];
    sprintf(pub3, "public_%d.key", 4096);
    sprintf(priv3, "private_%d.key", 4096);
    save_key(pub3, n, e);
    save_key(priv3, n, d);
    printf("Generated %d-bit key pair.\n", 4096);


    FILE *f = fopen(outfile, "w");
    if (!f) die("Cannot open performance file");

    clock_t start_time, end_time;
    struct rusage usage_before, usage_after;
    double cpu_time_used;
    long enc_mem, dec_mem, sign_mem, verf_mem;
    int bits[3] = {1024 ,2048 ,4096};
    char buf[64];
    char bufo[64];

    fprintf(f, "\n-------------- Performance Analysis File --------------\n\n");

    for(int i = 0; i < 3; i++){
        
        //get ram usage before and start time
        getrusage(RUSAGE_SELF, &usage_before);
        
        start_time = clock();
        //call the encryption function
        sprintf(buf, "public_%d.key", bits[i]);
        load_key(buf ,n ,e);
        sprintf(buf, "ciphertext_%d.txt", bits[i]);
        rsa_crypt("plaintext.txt" ,buf ,n ,e);
        // get finish time and ram usage
        end_time = clock();
        getrusage(RUSAGE_SELF, &usage_after);
        
    
        // Calculate CPU time used
        cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

        // Calculate memory usage
        enc_mem = usage_after.ru_maxrss - usage_before.ru_maxrss ;
        
    
        // Write the execution time to the output file
        fprintf(f,"Key Length: %d bits\n",bits[i]);
        fprintf(f, "Encryption Time: %f s\n", cpu_time_used);

        
        getrusage(RUSAGE_SELF, &usage_before);
        start_time = clock();
        //call the decryption function
        sprintf(buf, "private_%d.key", bits[i]);
        load_key(buf, n, d); 
        sprintf(buf, "ciphertext_%d.txt", bits[i]);
        sprintf(bufo, "decryptedtext_%d.txt", bits[i]);
        rsa_crypt(buf, bufo, n, d);
        
        
        end_time = clock();
        getrusage(RUSAGE_SELF, &usage_after);
        
    
        
        cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

        
        dec_mem = usage_after.ru_maxrss - usage_before.ru_maxrss;
        
    
        
        fprintf(f, "Decryption Time: %f s\n", cpu_time_used);

        getrusage(RUSAGE_SELF, &usage_before);
        start_time = clock();

        sprintf(buf, "private_%d.key", bits[i]);
        load_key(buf, n, d); 
        sprintf(buf, "signature_output_%d.txt", bits[i]);
        rsa_sign("input.txt", buf, n, d);
        
        
        end_time = clock();
        getrusage(RUSAGE_SELF, &usage_after);
        
    
        
        cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

        
        sign_mem = usage_after.ru_maxrss - usage_before.ru_maxrss;
        
    
        
        fprintf(f, "Signing time %f s\n", cpu_time_used);

        
        getrusage(RUSAGE_SELF, &usage_before);
        start_time = clock();

        sprintf(buf, "public_%d.key", bits[i]);
        load_key(buf, n, d); 
        sprintf(buf, "signature_output_%d.txt", bits[i]);
        rsa_verify("input.txt", buf, n, d);
      
        
        end_time = clock();
        getrusage(RUSAGE_SELF, &usage_after);
        
    
    
        
        cpu_time_used = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;

        
        verf_mem = usage_after.ru_maxrss - usage_before.ru_maxrss;
        
    
        
        fprintf(f, "Verification time %f s\n", cpu_time_used);
        // Write the peak memory usage in output file
        fprintf(f, "Peak Memory Usage (Encryption): %ld KBytes\n", enc_mem);
        fprintf(f, "Peak Memory Usage (Decryption): %ld KBytes\n", dec_mem);
        fprintf(f, "Peak Memory Usage (Signing): %ld KBytes\n", sign_mem);
        fprintf(f, "Peak Memory Usage (Verification): %ld KBytes\n", verf_mem);



    }

    fclose(f);
    printf("Performance written to %s \n", outfile);
}



// MAIN
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [options]\n", argv[0]);
        printf("  -g <bits>        Generate keys\n");
        printf("  -i <file>        Input file\n");
        printf("  -o <file>        Output file\n");
        printf("  -k <keyfile>     Key file\n");
        printf("  -e               Encrypt\n");
        printf("  -d               Decrypt\n");
        printf("  -s               Sign\n");
        printf("  -v <sigfile>     Verify\n");
        printf("  -a <outfile>     Performance\n");
        printf("  -h               Help\n");
        return 0;
    }

    mpz_t n, e, d;
    mpz_inits(n, e, d, NULL);

    const char *in = NULL, *out = NULL, *key = NULL, *sig = NULL;
    int bits = 0;
    int mode = 0; // 1=g,2=e,3=d,4=s,5=v,6=a

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-g") && i + 1 < argc) { bits = atoi(argv[++i]); mode = 1; }
        else if (!strcmp(argv[i], "-i") && i + 1 < argc) in = argv[++i];
        else if (!strcmp(argv[i], "-o") && i + 1 < argc) out = argv[++i];
        else if (!strcmp(argv[i], "-k") && i + 1 < argc) key = argv[++i];
        else if (!strcmp(argv[i], "-e")) mode = 2;
        else if (!strcmp(argv[i], "-d")) mode = 3;
        else if (!strcmp(argv[i], "-s")) mode = 4;
        else if (!strcmp(argv[i], "-v") && i + 1 < argc) { sig = argv[++i]; mode = 5; }
        else if (!strcmp(argv[i], "-a") && i + 1 < argc) { out = argv[++i]; mode = 6; }
        else if (!strcmp(argv[i], "-h")) { printf("Use -g/-e/-d/-s/-v/-a as per assignment.\n"); return 0; }
    }

    switch (mode) {
        case 1: { // Keygen
            rsa_generate_keys(n, e, d, bits);
            char pub[64], priv[64];
            sprintf(pub, "public_%d.key", bits);
            sprintf(priv, "private_%d.key", bits);
            save_key(pub, n, e);
            save_key(priv, n, d);
            printf("Generated %d-bit key pair.\n", bits);
            break;
        }
        case 2: { // Encrypt
            if (!in || !out || !key) die("Usage: -e -i <file> -o <file> -k <public.key>");
            load_key(key, n, e);
            rsa_crypt(in, out, n, e);
            printf("Encryption done -> %s\n", out);
            break;
        }
        case 3: { // Decrypt
            if (!in || !out || !key) die("Usage: -d -i <file> -o <file> -k <private.key>");
            load_key(key, n, d);
            rsa_crypt(in, out, n, d);
            printf("Decryption done -> %s\n", out);
            break;
        }
        case 4: { // Sign
            if (!in || !out || !key) die("Usage: -s -i <file> -o <sig> -k <private.key>");
            load_key(key, n, d);
            rsa_sign(in, out, n, d);
            printf("Signature saved to %s\n", out);
            break;
        }
        case 5: { // Verify
            if (!in || !sig || !key) die("Usage: -v <sigfile> -i <file> -k <public.key>");
            load_key(key, n, e);
            rsa_verify(in, sig, n, e);
            break;
        }
        case 6: { // Performance
            if (!out) die("Usage: -a <outfile>");
            rsa_performance(out);
            break;
        }
        default:
            printf("Invalid or missing arguments. Use -h for help.\n");
            break;
    }

    mpz_clears(n, e, d, NULL);
    return 0;
}
