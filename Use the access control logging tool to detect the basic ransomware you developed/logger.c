#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <errno.h>
void logattempt(const char*,int,int);
#define logfile "/tmp/file_logging.log"
#define MAX_PATH 4096


void logattempt(const char* path, int is_action_denied,int access_type){
	int uid=getuid(),inputfileLength=0,traverse_file;
	time_t system_time=time(NULL);
	struct tm tm=*localtime(&system_time);
	char truepath[4096];//UNIX systems maximum filepath is 4096 characters including NULL
	unsigned char md5_output[MD5_DIGEST_LENGTH];
	MD5_CTX md;
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	realpath(path,truepath);


	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	original_fopen_ret = (*original_fopen)(path, "r+");

	if(original_fopen_ret!=NULL){
		if(fseek(original_fopen_ret,0,SEEK_END)!=0) exit(1);
		inputfileLength=ftell(original_fopen_ret);
		fseek(original_fopen_ret,0,SEEK_SET);
		unsigned char* input=(unsigned char *)malloc((inputfileLength+1)*sizeof(char));
		MD5_Init(&md);
		while((traverse_file=fread(input,1,inputfileLength,original_fopen_ret))>0){
			MD5_Update(&md,input,traverse_file);
		}

		MD5_Final(md5_output,&md);
		fclose(original_fopen_ret);
	}
	
	original_fopen_ret = (*original_fopen)(logfile, "a");
	if(original_fopen_ret==NULL) return;
	
	fprintf(original_fopen_ret,"%u %s %d-%d-%d %d:%d:%d %d %d ",uid, truepath, tm.tm_mday, tm.tm_mon+1,tm.tm_year+1900,tm.tm_hour,tm.tm_min,tm.tm_sec, access_type,is_action_denied);

	if (inputfileLength>0){
		int i;
		for(i=0;i<MD5_DIGEST_LENGTH;i++){
			fprintf(original_fopen_ret," %02x",md5_output[i]);
		}
	}
	fprintf(original_fopen_ret,"\n");

	fclose(original_fopen_ret);

}


FILE *
fopen(const char *path, const char *mode) 
{
	int is_action_denied;
	int file_existed=access(path,F_OK);
	int action_access;

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	is_action_denied=0;
	if(file_existed==-1){
		action_access=0;
	}else{
	action_access=1;
}
	if(original_fopen_ret==NULL){
		if(errno==EACCES ||errno==EPERM ||(access(path,W_OK)==0||access(path,R_OK)==0)){
			is_action_denied=1;
	}	
}
		

	logattempt(path,is_action_denied,action_access);

	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	char filepath[MAX_PATH],temp[MAX_PATH];
	int access_type=2;
	
	int is_action_denied=0;


	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	sprintf(temp,"proc/self/fd/%d",fileno(stream));
	ssize_t nr;
	if(0>(nr=readlink(temp,filepath,MAX_PATH))) return -1;
	else filepath[nr]='\0';
	int file_existed=access(filepath,F_OK);
	if(access(filepath,W_OK)){
		is_action_denied=1;
	}

	if(file_existed==-1){
		access_type=0;
		logattempt(filepath,is_action_denied,access_type);
	}
	logattempt(filepath,is_action_denied,2);
	return original_fwrite_ret;
}

FILE*  fopen64(const char* path, const char * mode){
	return fopen(path,mode);
}

