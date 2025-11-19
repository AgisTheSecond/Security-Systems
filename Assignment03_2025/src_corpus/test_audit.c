#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


int main() 
{

	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};

	char testFile_1[] = "testFile_1";
	char testFile_2[] = "testFile_2";
	char test_append[] = "this is appended";



	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}

		/* add your code here */

	//test open and write for files without permission
	file = fopen(testFile_1,"w+");
	if(file != NULL){
		fprintf(file, "Junks for File 1");
		fclose(file);
	}

	file = fopen(testFile_2,"w+");
	if(file != NULL){
		fprintf(file, "Junks for File 2");
		fclose(file);
	}

	chmod(testFile_1, 0);
	chmod(testFile_2, 0);

	for(int i=0;i<7;i++){
		file = fopen(testFile_1, "r");
		if(file != NULL)
			fclose(file);
		file = fopen(testFile_2, "r");
		if(file != NULL)
			fclose(file);
	}

	//test for append in file
	file = fopen(filenames[2], "a");
	fwrite(test_append, sizeof(test_append), 1, file);
	fclose(file);




}
