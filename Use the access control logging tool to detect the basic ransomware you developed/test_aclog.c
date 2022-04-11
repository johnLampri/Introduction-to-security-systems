#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

int main(int argc, char **argv){
	if (argc<2){
		printf("The number of arguments is not correct");
		return 1;
	}
	int i;
	char randomString[10]="123456789";
	char* directory=argv[1];
	char buffer[4096];
	int num_of_files=atoi(argv[2]);
	char filename[255];
	for(i=0;i<num_of_files;i++){
		realpath(directory,buffer);
		snprintf(filename,255,"/Testfile%d.txt",i+1);
		strcat(buffer,filename);


		FILE *file=fopen(buffer,"w+");
		if(file==NULL){
		 printf("Could not create the file");
		}else{
			fwrite(randomString,10,1,file);
			fclose(file);
		}
	}



return 0;

}