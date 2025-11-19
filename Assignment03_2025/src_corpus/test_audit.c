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

	//char testFile_1[] = "testFile_1";
	//char testFile_2[] = "testFile_2";
	char test_append[] = "\nthis is appended";



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

	/*test open and write for files without permission*/
	char deniedFiles[6][20] = {
    "denied1", "denied2", "denied3",
    "denied4", "denied5", "denied6"
};

for (int i = 0; i < 6; i++) {
    file = fopen(deniedFiles[i], "w");
    if (file) fclose(file);
    chmod(deniedFiles[i], 0);
}

for (int r = 0; r < 10; r++) {
    for (int i = 0; i < 6; i++) {
        file = fopen(deniedFiles[i], "r");
        if (file) fclose(file);
    }
}


	/*test for append in file*/
	file = fopen(filenames[2], "a");
	fwrite(test_append, strlen(test_append), 1, file);
	fclose(file);




}
