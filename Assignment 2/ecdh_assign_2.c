
#include <sodium.h>
#include <stdio.h>
#include <string.h>


void kill_machine(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}
void confirm_hex(FILE *f,char *title,char *buf, size_t len) {
    char *hex = malloc(len*2 + 1);
    if (!hex) 
    {
        kill_machine("malloc failed");
    }
    
    sodium_bin2hex(hex, len*2 + 1, buf, len);
    fprintf(f, "%s\n%s\n", title, hex);
    free(hex);
}


int main(int argumentc,char *argumentv[]) {
    if (sodium_init() < 0) {
        printf("libsodium initialization failed\n");
        return 1;
    }

    //  Alice generates key pair
    unsigned char alice_private[crypto_box_SECRETKEYBYTES]={0};
    unsigned char alice_public[crypto_box_PUBLICKEYBYTES]={0};
    crypto_box_keypair(alice_public, alice_private); // same as crypto_scalarmult_base()

    //  Bob generates key pair
    unsigned char bob_private[crypto_box_SECRETKEYBYTES]={0};
    unsigned char bob_public[crypto_box_PUBLICKEYBYTES]={0};
    crypto_box_keypair(bob_public, bob_private);

    //  computes shared secret+
    unsigned char S_A[crypto_scalarmult_BYTES];
    unsigned char S_B[crypto_scalarmult_BYTES];

    int alice_is_produced=0,bob_is_produced = 0;
    char *_file_ = NULL;
    char context[crypto_kdf_CONTEXTBYTES+1];
    memset(context,0,crypto_kdf_CONTEXTBYTES+1);
    memcpy(context,"ECDH_KDF",8);

    for (int i = 1; i < argumentc; ++i)
    {
        if (strcmp(argumentv[i],"-o")==0 && i+1<argumentc)
        {
            i++;
            _file_ = argumentv[i];
        }
        else if(strcmp(argumentv[i],"-a")==0 && i+1<argumentc)
        {
            i++;
            char *hex=argumentv[i];
            size_t bin_len = 0;
            if (sodium_hex2bin(alice_private, sizeof(alice_private), hex, strlen(hex), NULL, &bin_len, NULL) != 0 || bin_len != sizeof(alice_private)) {
                kill_machine("Invalid hex input for Alice's private key");}
            alice_is_produced=1;
            
        }
        else if(strcmp(argumentv[i],"-b")==0 && i+1<argumentc)
        {
            i++;
            char *hex=argumentv[i];
            size_t bin_len = 0;
            if (sodium_hex2bin(bob_private, sizeof(bob_private), hex, strlen(hex), NULL, &bin_len, NULL) != 0 || bin_len != sizeof(bob_private)) {
                kill_machine("Invalid hex input for Alice's private key");
            }
                bob_is_produced=1; 
        }
        else if (strcmp(argumentv[i],"-c")==0 && i+1<argumentc)
        {
            i++;
            char *ctx = argumentv[i];
            size_t L = strlen(ctx);
            if (L != crypto_kdf_CONTEXTBYTES) kill_machine("Invalid context length");
            memcpy(context, ctx, crypto_kdf_CONTEXTBYTES);
        }
        
        else if(strcmp(argumentv[i],"-h")==0)
            {
            printf("Operations:\n-o path Path to output file : '_file_'\n"
                   "(Optional in hexadecimal format) -a number Alice's private key\n"
                    "(Optional in hexadecimal format) -b number Bob's private key\n"
                    "-h Help");

            }
        else
            {
            printf("Unknown argument: %s\n", argumentv[i]);
            }
        
    }
    
        if (!_file_) kill_machine("Missing -o <output file>");

        if(alice_is_produced){
            crypto_scalarmult_base(alice_public,alice_private);
        }
        else{
            crypto_box_keypair(alice_public,alice_private);
        }
        
        if(bob_is_produced){
            crypto_scalarmult_base(bob_public,bob_private);
        }
        else{
            crypto_box_keypair(bob_public,bob_private);
        }

        if(crypto_scalarmult(S_A,alice_private,bob_public)!=0){
            fprintf(stderr,"ERROR COMPUTE SHARED ALICE'S SECRET");
            return 1;
        }

        if(crypto_scalarmult(S_B,bob_private,alice_public)!=0){
            fprintf(stderr,"ERROR COMPUTE SHARED BOB'S SECRET");
            return 1;
        }

        // derive keys
        unsigned char enc_a[32], mac_a[32], enc_b[32], mac_b[32];
        crypto_kdf_derive_from_key(enc_a, 32, 1, context, S_A);
        crypto_kdf_derive_from_key(mac_a, 32, 2, context, S_A);
        crypto_kdf_derive_from_key(enc_b, 32, 1, context, S_B);
        crypto_kdf_derive_from_key(mac_b, 32, 2, context, S_B);

        // write output
        FILE *f = fopen(_file_, "w");
        if (!f) kill_machine("Cannot open output file");

        confirm_hex(f, "Alice's Public Key:", alice_public, sizeof(alice_public));
        confirm_hex(f, "Bob's Public Key:", bob_public, sizeof(bob_public));
        confirm_hex(f, "Shared Secret (Alice):", S_A, sizeof(S_A));
        confirm_hex(f, "Shared Secret (Bob):", S_B, sizeof(S_B));

        if (sodium_memcmp(S_A, S_B, sizeof(S_A)) == 0)
            fprintf(f, "Shared secrets match!\n");

        confirm_hex(f, "Derived Encryption Key (Alice):", enc_a, sizeof(enc_a));
        confirm_hex(f, "Derived Encryption Key (Bob):", enc_b, sizeof(enc_b));

        confirm_hex(f, "Derived MAC Key (Alice):", mac_a, sizeof(mac_a));
        confirm_hex(f, "Derived MAC Key (Bob):", mac_b, sizeof(mac_b));

        fclose(f);

        printf("Output file %s \n",_file_);
        return 0;

    
}
