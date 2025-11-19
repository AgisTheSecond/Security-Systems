#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h> //install the required package
#include <openssl/sha.h>
#include <errno.h>

#define LOG_FILE "/tmp/access_audit.log"
#define EMPTY_SHA256 "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"




struct log_entry {

	int uid; /* user id (positive integer) */
	pid_t pid; /* process id (positive integer) */

	char *file; /* filename (string) */

	struct tm time;

	int operation; /* access type values [0-3] */
	int action_denied; /* is action denied values [0-1] */

	char filehash[SHA256_DIGEST_LENGTH * 2 + 1]; /* file hash - sha256 - evp */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};

int get_sha256(const char *filename, char *output);
void write_log(struct log_entry logC);


FILE *
fopen(const char *path, const char *mode) 
{

	struct log_entry logC;

	logC.uid = getuid();
	logC.pid = getpid();
	logC.action_denied = 0;
	time_t t = time(NULL);
	logC.time = *gmtime(&t);
	memset(logC.filehash, 0, SHA256_DIGEST_LENGTH * 2 + 1);

	struct stat st;
    int existed = (stat(path, &st) == 0);


	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);


	/* add your code here */
	char *abs_path = realpath(path, NULL);
    	if (!abs_path) {
        	perror("Failed to resolve absolute path");
        	abs_path = strdup(path);  // Fallback to original path
    	}
    	
    	logC.file = abs_path;
	
    /*Determine operation type*/
	if (original_fopen_ret != NULL && !existed){
		logC.operation = 0;
		//memcpy(logC.fingerprint, NULL_SHA256, SHA256_DIGEST_LENGTH*2 + 1);
		strcpy(logC.filehash, EMPTY_SHA256);

	}
	else if (original_fopen_ret){
		logC.operation = 1;
		if(get_sha256(logC.file, logC.filehash) != 0){
			printf("Hashing Error\n");
		}
	}
	else {
        	logC.action_denied = 1;
        	memset(logC.filehash, '0', SHA256_DIGEST_LENGTH * 2);
		logC.filehash[SHA256_DIGEST_LENGTH * 2] = '\0';

        	logC.operation = ((mode[0] == 'w' || mode[0] == 'a' || mode[0] == 'x') && !existed) ? 0 : 1;
    	}
	
	// Writes log and frees the allocated memory for abs_path
	write_log(logC);
	free(abs_path);


	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	struct log_entry logC;
    logC.operation = 2;
    logC.uid = getuid();
    logC.pid = getpid();
    time_t t = time(NULL);
    logC.time = *gmtime(&t);
    memset(logC.filehash, 0, SHA256_DIGEST_LENGTH*2+1);

    int fd = fileno(stream);
    char proc_fd[255] = {0};
    char filename[255] = {0};
    sprintf(proc_fd, "/proc/self/fd/%d", fd);
    readlink(proc_fd, filename, 255);
    logC.file = realpath(filename, NULL);

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);


	/* add your code here */
    /*Detect if the write was denied*/
	if(original_fwrite_ret != nmemb){
        logC.action_denied = 1;
    }else{
        logC.action_denied = 0;
    }


    if(get_sha256(logC.file, logC.filehash) != 0){
			printf("Hashing Error\n");
		}
    write_log(logC);
    free((void *)logC.file);

	return original_fwrite_ret;
}


int 
fclose(FILE *stream)
{
	struct log_entry logC;
    logC.operation = 3;
    logC.uid = getuid();
    logC.pid = getpid();
    time_t t = time(NULL);
    logC.time = *gmtime(&t);
    memset(logC.filehash, 0, SHA256_DIGEST_LENGTH*2+1);

    int fd = fileno(stream);
    char proc_fd[255] = {0};
    char filename[255] = {0};
    sprintf(proc_fd, "/proc/self/fd/%d", fd);
    readlink(proc_fd, filename, 255);
    logC.file = realpath(filename, NULL);


	int original_fclose_ret;
	int (*original_fclose)(FILE*);

	/* call the original fclose function */
	original_fclose = dlsym(RTLD_NEXT, "fclose");
	original_fclose_ret = (*original_fclose)(stream);


	/* add your code here */
    /*Check if close was denied*/
	if(original_fclose_ret != 0){
        logC.action_denied = 1;
    }else{
        logC.action_denied = 0;
    }


    if(get_sha256(logC.file, logC.filehash) != 0){
			printf("Hashing Error\n");
		}
    write_log(logC);
    free((void *)logC.file);
	

	return original_fclose_ret;
}

int get_sha256(const char *filename, char *output) {

	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

    int (*original_fclose)(FILE *);
    original_fclose = dlsym(RTLD_NEXT, "fclose");




    FILE *f = original_fopen(filename, "rb");
    if (!f) {
        
        fprintf(stderr, "Failed to open file: %s\n", filename);
        return -1;
    }

    /* Create a new OpenSSL digest context for SHA-256 hashing*/
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        
        original_fclose(f);
        fprintf(stderr, "Failed to create digest context\n");
        return -2;
    }

    unsigned char md_value[EVP_MAX_MD_SIZE];  
    unsigned int md_len;                     
    unsigned char buffer[1024];              
    size_t bytes;

    /* Initialize the digest context for SHA-256*/
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        /* If initialization fails, clean up resources and return an error.*/
        original_fclose(f);
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Failed to initialize digest\n");
        return -3;
    }

    /* Read from the file and update the digest incrementally*/
    while ((bytes = fread(buffer, 1, sizeof(buffer), f)) > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, bytes) != 1) {
            
            original_fclose(f);
            EVP_MD_CTX_free(mdctx);
            fprintf(stderr, "Failed to update digest\n");
            return -4;
        }
    }

    /* Finalize the digest, i.e., complete the hash computation*/
    if (EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
        /* If finalization fails, perform cleanup and return an error*/
        original_fclose(f);
        EVP_MD_CTX_free(mdctx);
        fprintf(stderr, "Failed to finalize digest\n");
        return -5;
    }

    /* Close the file and free the digest context now that the hash is computed*/
    original_fclose(f);
    EVP_MD_CTX_free(mdctx);

    /* Convert the binary hash to a hexadecimal string.*/
    for (int i = 0; i < md_len; i++) {
        sprintf(output + (i * 2), "%02x", md_value[i]);
    }
    output[md_len * 2] = '\0';  

    return 0;  
}


void write_log(struct log_entry logC) {

	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	int (*original_fclose)(FILE *) = dlsym(RTLD_NEXT, "fclose");
	

    /*check if log file opens then write the log*/
    FILE *fp = original_fopen(LOG_FILE, "a");
    if (!fp) {
        fprintf(stderr, "Error opening log file.\n");
        return; 
    }

    fprintf(fp, "%d,%d,%s,%d,%d,%02d-%02d-%d,%02d:%02d:%02d,%s\n",
            logC.uid,logC.pid, logC.file, logC.action_denied, logC.operation,
            logC.time.tm_mday, logC.time.tm_mon + 1, logC.time.tm_year + 1900,
            logC.time.tm_hour, logC.time.tm_min, logC.time.tm_sec, logC.filehash);

    original_fclose(fp);
}