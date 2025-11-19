#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

#define MAXUSERNO 100


void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./audit_monitor \n"
		   "Options:\n"
		   "-s, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{

	/* add your code here */
	int users[MAXUSERNO][2]

	

	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return;

}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./access_audit.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./access_audit.log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:s")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 's':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
