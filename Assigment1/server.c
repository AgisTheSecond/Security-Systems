#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

const char allowedUsername[64] = "Sousi";
const char allowedPassword[64] = "123";
const char allowedName[64] = "sousi.com"; 
const char allowedYear[64] = "1.5";
const char allowedBlogType[64] = "Embedede and c c++";
const char allowedAuthor[64] = "John Johny"; 

int OpenListener(int port) {
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        perror("Can't bind port");
        abort();
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        abort();
    }

    return sd;
}

int verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
    SSL *ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
    if (preverify_ok==0) {
        //Send invalid message to client if certificate is invalid
        const char *msg = "peer did not return a certificate or returned an invalid one\n" ;
        SSL_write(ssl, msg, strlen(msg));
    }
    return preverify_ok;
}


SSL_CTX* InitServerCTX(void) {
    /* TODO:
        * 1. Initialize SSL library (SSL_library_init, OpenSSL_add_all_algorithms, SSL_load_error_strings)
     */
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();

/* 2. Create a new TLS server context (TLS_server_method)
    */
	const SSL_METHOD *method=TLS_server_method();
	SSL_CTX* ctx = SSL_CTX_new(method);
	
	if(ctx == NULL){
	ERR_print_errors_fp(stderr);
        abort();
	}

 /* 3. Load CA certificate for client verification
    */
	if(SSL_CTX_load_verify_locations(ctx,"ca.crt",NULL)<=0){
	ERR_print_errors_fp(stderr);
	abort();
}

 /* 4. Configure SSL_CTX to require client certificate (mutual TLS)
     */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_PEER, verify_callback);
	return ctx;  

 }

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
  /* TODO:
     * 1. Load server certificate using SSL_CTX_use_certificate_file
*/
    if(SSL_CTX_use_certificate_file(ctx,CertFile,SSL_FILETYPE_PEM)<=0){
    ERR_print_errors_fp(stderr);
    abort();
}
/* 2. Load server private key using SSL_CTX_use_PrivateKey_file
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

void ShowCerts(SSL* ssl) {
    /* TODO:
     * 1. Get client certificate (if any) using SSL_get_peer_certificate
     * 2. Print Subject and Issuer names
     */
	X509 *clientCerts;
    clientCerts = SSL_get1_peer_certificate(ssl);
    
    if(!clientCerts){
        ERR_print_errors_fp(stderr);
    }
    else{        
        X509_NAME *issuer = X509_get_issuer_name(clientCerts);
        X509_NAME *subject = X509_get_subject_name(clientCerts);

        char issuerBuf[256];
        char subjectBuf[256];

        X509_NAME_oneline(subject, subjectBuf, sizeof(subjectBuf));
        printf("Subject: %s\n", subjectBuf);
    
        X509_NAME_oneline(issuer, issuerBuf, sizeof(issuerBuf));
        printf("Issuer: %s\n", issuerBuf);	
}

}

void Servlet(SSL* ssl) {
    char buf[1024] = {0};

    if (SSL_accept(ssl) == FAIL) {
        ERR_print_errors_fp(stderr);
        return;
    }

    ShowCerts(ssl);

    int bytes = SSL_read(ssl, buf, sizeof(buf));
    if (bytes <= 0) {
        SSL_free(ssl);
        return;
    }
    buf[bytes] = '\0';
    printf("Client message: %s\n", buf);

    /* TODO:
     * 1. Parse XML from client message to extract username and password
     * 2. Compare credentials to predefined values (e.g., "sousi"/"123")
     * 3. Send appropriate XML response back to client
     */
    int ctrl = -1;
    char msg[512];
    char username[64] = {0};
    char password[64] = {0};
    char *username_start = strstr(buf, "<UserName>");
    char *username_end   = strstr(buf, "</UserName>");
    char *password_start = strstr(buf, "<Password>");
    char *password_end   = strstr(buf, "</Password>");
    if (username_start && username_end && password_start && password_end) {
        username_start += strlen("<UserName>");
        password_start += strlen("<Password>");

    size_t username_len = username_end - username_start;
    size_t password_len = password_end - password_start;

        if (username_len < sizeof(username) && password_len < sizeof(password)) {
            strncpy(username, username_start, username_len);
            username[username_len] = '\0';
            strncpy(password, password_start, password_len);
            password[password_len] = '\0';

            
        } else {
            printf("Error: username or password too long.\n");
        }
    } else {
        printf("Error: Invalid XML format.\n");
    }

    if (strcmp(username,allowedUsername) == 0 && strcmp(password,allowedPassword) == 0){
        ctrl = 0;
    }
    
    if (ctrl == FAIL) {
        printf("Invalid message sent.\n");
        snprintf(msg, sizeof(msg), "Invalid Message\n");
    } else {
         printf("Message sent!\n");
        snprintf(msg, sizeof(msg),
                "<Body><Name>%s</Name><year>%s</year><BlogType>%s</BlogType><Author>%s</Author></Body>\n",
                allowedName, allowedYear, allowedBlogType, allowedAuthor);
    }

    SSL_write(ssl,msg,strlen(msg));

    int sd = SSL_get_fd(ssl);
    SSL_free(ssl);
    close(sd);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <port>\n", argv[0]);
        exit(0);
    }

    int port = atoi(argv[1]);
    SSL_CTX *ctx;

    /* TODO:
     * 1. Initialize SSL context using InitServerCTX
     * 2. Load server certificate and key using LoadCertificates
     */

    ctx = InitServerCTX();

    char* CertFile = "server.crt";
    char* KeyFile = "server.key";
    LoadCertificates(ctx,CertFile,KeyFile);


    int server = OpenListener(port);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);
        printf("Connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

        /* TODO:
         * 1. Create new SSL object from ctx
         * 2. Set file descriptor for SSL using SSL_set_fd
         * 3. Call Servlet to handle the client
         */

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        Servlet(ssl);


    }

    close(server);
    SSL_CTX_free(ctx);
}
