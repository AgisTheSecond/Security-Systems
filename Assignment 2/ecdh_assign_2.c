
#include <sodium.h>
#include <stdio.h>
#include <string.h>

int main(void) {
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

    

    
}