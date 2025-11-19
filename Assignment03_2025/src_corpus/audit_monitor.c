#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>

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

struct user_denied {
    int uid;
    int count;
    char **files;
    int fcount;
    struct user_denied *next;
};

struct user_mod {
    int uid;
    int accessed;
    int modifications;
    char last_hash[128];
    int dirty;
    struct user_mod *next;
};

/* Acquire or create a denied-access user record */

static struct user_denied *get_denied_user(struct user_denied **head, int uid)
{
    struct user_denied *u = *head;

    while (u) {
        if (u->uid == uid)
            return u;
        u = u->next;
    }

    u = malloc(sizeof(*u));
    u->uid = uid;
    u->count = 0;
    u->files = NULL;
    u->fcount = 0;
    u->next = *head;
    *head = u;
    return u;
}

/* Acquire or create a modification tracking record */
static struct user_mod *get_mod_user(struct user_mod **head, int uid)
{
    struct user_mod *u = *head;

    while (u) {
        if (u->uid == uid)
            return u;
        u = u->next;
    }

    u = malloc(sizeof(*u));
    u->uid = uid;
    u->accessed = 0;
    u->modifications = 0;
    u->last_hash[0] = '\0';
    u->dirty = 0;
    u->next = *head;
    *head = u;
    return u;
}

/* Parse the log entry */
static int parse_log_entry(char *line, struct log_entry *e)
{
    char filepath[512];
    int day, mon, year, hh, mm, ss;

    int matched = sscanf(
        line,
        "%d,%d,%511[^,],%d,%d,%d-%d-%d,%d:%d:%d,%64s",
        &e->uid,
        &e->pid,
        filepath,
        &e->action_denied,
        &e->operation,
        &day, &mon, &year,
        &hh, &mm, &ss,
        e->filehash
    );

    if (matched < 11)
        return 0;

    e->file = strdup(filepath);

    e->time.tm_mday = day;
    e->time.tm_mon = mon - 1;
    e->time.tm_year = year - 1900;
    e->time.tm_hour = hh;
    e->time.tm_min = mm;
    e->time.tm_sec = ss;

    return 1;
}


void usage(void)
{
    printf("\nUsage:\n"
           "  ./audit_monitor -s\n"
           "  ./audit_monitor -i <filename>\n"
           "\nOptions:\n"
           "  -s   Print malicious users (more than 5 denied distinct files)\n"
           "  -i   Print per-user modifications and unique changes for file\n"
           "  -h   Show this help\n\n");
    exit(1);
}


void list_unauthorized_accesses(FILE *log)
{
    char line[2048];
    struct log_entry e;

    struct user_denied *users = NULL;

    rewind(log);

    while (fgets(line, sizeof(line), log)) {

        if (!parse_log_entry(line, &e))
            continue;

        /*check if access was denied for this line*/
        if (e.action_denied != 1) {
            free(e.file);
            continue;
        }

        char *abs = realpath(e.file, NULL);
        if (abs) {
            free(e.file);
            e.file = strdup(abs);
            free(abs);
        }
        /*Get or create record for user*/
        struct user_denied *u = get_denied_user(&users, e.uid);
        /*check if the denied file has been already counted for the user if not store it*/
        int exists = 0;
        for (int i = 0; i < u->fcount; i++) {
            if (strcmp(u->files[i], e.file) == 0) {
                exists = 1;
                break;
            }
        }

        if (!exists) {
            u->files = realloc(u->files, sizeof(char *) * (u->fcount + 1));
            u->files[u->fcount++] = strdup(e.file);
            u->count++;
        }

        free(e.file);
    }

    printf("Malicious users:\n");
    struct user_denied *p = users;
    while (p) {
        if (p->count > 5)
            printf("UID %d — %d denied distinct files\n", p->uid, p->count);
        p = p->next;
    }
}


void list_file_modifications(FILE *log, char *file_to_scan)
{
    char *abs = realpath(file_to_scan, NULL);
    if (!abs) {
        printf("File not found: %s\n", file_to_scan);
        return;
    }
    file_to_scan = abs;

    char line[2048];
    struct log_entry e;
    struct user_mod *users = NULL;

    char global_last_hash[128] = "";
    int unique_modifications = 0;

    rewind(log);

    while (fgets(line, sizeof(line), log)) {

        if (!parse_log_entry(line, &e))
            continue;

        if (strcmp(e.file, file_to_scan) != 0) {
            free(e.file);
            continue;
        }

       /*Detect global hash change*/
        if (e.filehash[0] != '\0') {
            if (global_last_hash[0] != '\0' &&
                strcmp(global_last_hash, e.filehash) != 0)
            {
                unique_modifications++;
            }

            strncpy(global_last_hash, e.filehash, sizeof(global_last_hash));
        }

  		/*Detect and update per user modifications*/ 
        struct user_mod *u = get_mod_user(&users, e.uid);
        u->accessed = 1;

        if (e.operation == 2) {  // fwrite
            u->dirty = 1;
        }

        if (e.filehash[0] != '\0') {

            if (u->last_hash[0] != '\0') {

                if (u->dirty && strcmp(u->last_hash, e.filehash) != 0) {
                    u->modifications++;
                }
            }

            strncpy(u->last_hash, e.filehash, sizeof(u->last_hash));
            u->dirty = 0;
        }

        free(e.file);
    }

    printf("Users who accessed file: %s\n", file_to_scan);

    struct user_mod *p = users;
    while (p) {
        if (p->accessed)
            printf("UID %d -> %d modifications\n",
                   p->uid, p->modifications);
        p = p->next;
    }

    printf("Total unique modifications: %d\n", unique_modifications);

    free(abs);
}



int main(int argc, char *argv[])
{
    int ch;
    FILE *log;

    if (argc < 2)
        usage();

    log = fopen("/tmp/access_audit.log", "r");
    if (!log) {
        printf("Error opening log file \"%s\"\n", "/tmp/access_audit.log");
        return 1;
    }

    int didSomething = 0;

    while ((ch = getopt(argc, argv, "hi:s")) != -1) {
        switch (ch) {
        case 'i':
            list_file_modifications(log, optarg);
            didSomething = 1;
            break;

        case 's':
            list_unauthorized_accesses(log);
            didSomething = 1;
            break;

        default:
            usage();
        }
    }

    if (!didSomething)
        usage();

    fclose(log);
    return 0;
}
