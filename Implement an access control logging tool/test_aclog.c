#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][10] = {"file_10", "file_11", 
			"file_12", "file_13", "file_14",
			"file_15", "file_16", "file_17", 		
			"file_18", "file_19"};


	/* example source code */

	for (i = 0; i < 10; i++) {
		//chmod
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}


	for(int i=0;i<10;i++){
		chmod(filenames[i],0);
		file = fopen(filenames[i], "w+");
	if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
}
}