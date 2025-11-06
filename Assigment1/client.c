#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port)
{
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL)
    {
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        close(sd);
        perror("Connection failed");
        abort();
    }

    return sd;
}

SSL_CTX* InitCTX(void)
{
    /* TODO:
     * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
*/
     SSL_library_init();
     OpenSSL_add_all_algorithms();
     SSL_load_error_strings();

/*
     * 2. Create a new TLS client context (TLS_client_method)	
     * 3. Load CA certificate to verify server
     * 4. Configure SSL_CTX to verify server certificate
     */
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
    ERR_print_errors_fp(stderr);
    abort();
}


   //SSL_CTX_use_certificate_file(ctx,"ca.crt",SSL_FILETYPE_PEM); // SSL_CTX_load_verify_locations(ctx,ca.crt,NULL); DK  YET
   //SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL);
//// ARXIKOPOIW SSL_LYBRARY,OPENSSLALGORITHM....
////DIMIURGW CONTEX (TEMPLATE POU KRATAEI PROTOKOLA PISTOPOIITIKA ALGORITHOI KA EPALITHEYSH
//LOAD VERIFY CERTF
//SET  VERIFY  OT O CLIENT EPALITHEYEI TO CRTFC TOY SERVER
   return ctx;
}



void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* TODO:
     * 1. Load client certificat using SSL_CTX_use_certificate_file
*/
	if(SSL_CTX_use_certificate_file(ctx,CertFile,SSL_FILETYPE_PEM)<=0){
	ERR_print_errors_fp(stderr);
	abort();
}
/* 2. Load client private key using SSL_CTX_use_PrivateKey_file
 */
	if(SSL_CTX_use_PrivateKey_file(ctx,KeyFile,SSL_FILETYPE_PEM)<=0){
	ERR_print_errors_fp(stderr);
	abort();
}
/* 3. Verify that private key matches certificate using SSL_CTX_check_private_key
     */
	if(SSL_CTX_check_private_key(ctx) != 1){
	ERR_print_errors_fp(stderr);
	abort();

}
}

int main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("Usage: %s <hostname> <port>\n", argv[0]);
        exit(0);
    }

    char *hostname = argv[1];
    int port = atoi(argv[2]);
    SSL_CTX *ctx;
    SSL *ssl;
    int server;

    /* TODO:
     * 1. Initialize SSL context using InitCTX
*/
	ctx=InitCTX();
    /* 2. Load client certificate and key using LoadCertificates
     */
	LoadCertificates(ctx,"client.crt","client.key");

    server = OpenConnection(hostname, port);
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server);

    /* TODO:
     * 1. Establish SSL connection using SSL_connect*/
	if(SSL_connect(ssl) ==-1)
{
	ERR_print_errors_fp(stderr);

} else {

/*Ask user to enter username and password
     * 3. Build XML message dynamically
     * 4. Send XML message over SSL
    */ 
	char username[64], password[64];
        printf("Enter username: ");
        scanf("%63s", username);
        printf("Enter password: ");
        scanf("%63s", password);

        char msg[256];
        snprintf(msg, sizeof(msg),
                 "<Body><UserName>%s</UserName><Password>%s</Password></Body>",
                 username, password);

        SSL_write(ssl, msg, strlen(msg));
     /* 5. Read server response and print it
     */
	char buf[256];
	int responded_bytes = SSL_read(ssl,buf,sizeof(buf));
	if(responded_bytes<0){
	ERR_print_errors_fp(stderr);
	}
	printf("Server response: %s",buf);
}
    SSL_free(ssl);
    close(server);
    SSL_CTX_free(ctx);
    return 0;
}
