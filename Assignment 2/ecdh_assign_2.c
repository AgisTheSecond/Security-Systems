
#include <sodium.h>
#include <stdio.h>
#include <string.h>

int main(int argumentc,char *argumentv[]) {
    if (sodium_init() < 0) {
        printf("libsodium initialization failed\n");
        return 1;
    }

    //  Alice generates key pair
    unsigned char alice_private[crypto_box_SECRETKEYBYTES];
    unsigned char alice_public[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(alice_public, alice_private); // same as crypto_scalarmult_base()

    //  Bob generates key pair
    unsigned char bob_private[crypto_box_SECRETKEYBYTES];
    unsigned char bob_public[crypto_box_PUBLICKEYBYTES];
    crypto_box_keypair(bob_public, bob_private);

    //  computes shared secret
    unsigned char S_A[crypto_scalarmult_BYTES];
    unsigned char B_A[crypto_scalarmult_BYTES];

    bool alice_is_produced,bob_is_produced = FALSE;
    char *_file_ = NULL;

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
            alice_is_produced=TRUE;
            unsigned long long temp_alice_private = strtoull(argumentv[i],NULL,10);
            memcpy(alice_private,&temp_alice_private,sizeof(temp_alice_private));
        }
        else if(strcmp(argumentv[i],"-b")==0 && i+1<argumentc)
        {
            i++;
            alice_is_produced=TRUE;
            unsigned long long temp_bob_private = strtoull(argumentv[i],NULL,10);
            memcpy(bob_private,&temp_bob_private,sizeof(temp_bob_private));
        }
        else
            {
                printf("Operations:\n-o path Path to output file : '_file_'\n
                    (Optional in hexadecimal format) -a number Alice's private key\n
                    (Optional in hexadecimal format) -b number Bob's private key\n
                    -h Help
                    ");

            }
        }

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

        printf("Output file %s \n",_file_);
        return 0;

    
}