 Assignment 3 — Security Systems

 Authors
Charalampos Mylonakis — 2022030133  
Agisilaos Fotinakis — 2022030190  



#  Overview
This project Access Control Logging in C:


#  Task 1 — Audit Logging Library

File: audit_logger.c

In this file we develop a library which overrides the functions fopen() ,fwrite() ,fclose() so that they audit and log their operations.

First we use log_entry struct to use all the required parameters for the log.
In the fopen function we check if the file already existed using start() function, open the file using the original fopen and assign all the log entry parameters using the correct operation and access_denied values and then write in the log file using the write_log function. We use this function with LD_Preload.
In the fwrite function we check if access was denied then use the original fwrite to write in file. We log our operation and all th log entry parameters.The file hash is calculated with the get_sha256 function which uses openSSL/sha.h library. We then write the log entry in the file.
The fclose function follows the same logic using the original fclose function, the openSSL/sha.h library and the write_log function.

The write_log function opens the log file (by default: /tmp/access_audit.log) and appends the new log entry.

#  Task 2 — Audit Log Analyzer
File: audit_monitor.c

In this file we have a command line tool which analyzes the log file created by the library audit_logger.so
It's first function is to detect suspicious users, users that have tried to access more than 5 distinct files for which they don't have permissions.
For this purpose we create a user struct that counts the files for which each user is denied access. The implementation is the function list_anauthorized_access.
We use this function with command line input : ./audit_monitor -s
It's second function is to analyze all file activity giving some parameters for the given file. This implementation is the function list_file_modifications which checks the different hash values to determine the number of modifications.
We use this function with command line input : ./audit_monitor -i <filename>

#  Task 3 — Test the Audit System
File: test_audit.c

This file tests the logging system by creating ,writing and appending in multiple files. It also tries to open files without permissions so we can generate denied actions. This programm runs with the audit_logger.so preloaded so we create logs. We can also run the monitor commands after to check if the logs work.

Monitor output:
./audit_monitor -s
Malicious users:
UID 1000 — 6 denied distinct files

./audit_monitor -i file_2
Users who accessed file: /home/agis/Security-Systems/Assignment03_2025/src_corpus/file_2
UID 1000 -> 1 modifications
Total unique modifications: 3

#   Compilation
all: audit_logger audit_monitor test_audit


audit_logger: audit_logger.c
  gcc -Wall -fPIC -shared -o audit_logger.so audit_logger.c -lcrypto -ldl 


audit_monitor: audit_monitor.c 
  gcc audit_monitor.c -o audit_monitor


test_audit: test_audit.c 
  gcc test_audit.c -o test_audit


run: audit_logger.so test_audit
  LD_PRELOAD=./audit_logger.so ./test_audit


clean:
  rm -rf audit_logger.so
  rm -rf test_audit
  rm -rf audit_monitor









