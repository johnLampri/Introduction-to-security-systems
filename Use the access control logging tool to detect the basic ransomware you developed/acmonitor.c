#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define MAX_PATH 4096

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */
	char access_denied[8][MAX_PATH];
	int times_denied;
	int times_accessed;
	struct entry *next_user;
};

struct filenames{
	char* filename;
	struct filenames* next_filename;
};
struct encrypted_filenames{
	char* filename;
	struct encrypted_filenames* next_filename;
};

struct entry* head;
struct filenames* head_filenames=NULL;
struct encrypted_filenames* head_encrypted_filenames=NULL;


void
usage(void)
{
	printf(
		"\n"
		"usage:\n"
		"\t./monitor \n"
		"Options:\n"
		"-m, Prints malicious users\n"
		"-i <filename>, Prints table of users that modified "
		"the file <filename> and the number of modifications\n"
		"-h, Help message\n\n"
		);

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
	int uid;
	char filepath[MAX_PATH];
	int year, month, day,hour,min,sec;
	int access_type;
	int action_denied;
	unsigned char md;
	char* data=NULL;
	size_t length=0;
	int read;
	char* fingerprint;
	struct entry* temp;
	struct entry* new_entry;

	int flag=1;
	int isinarray=0;
	int i;

	while((read = getline(&data,&length,log))!= EOF){


		sscanf(data,"%d %s %d-%d-%d %d:%d:%d %d %d",&uid, filepath, &day, &month,&year,&hour,&min,&sec, &access_type,&action_denied);
		if(action_denied==1 && head==NULL){
			temp=(struct entry*)malloc(sizeof(struct entry));
			temp->next_user=(struct entry*)malloc(sizeof(struct entry));
			head=temp;
			head->uid=uid; /* user id (positive integer) */
			head->times_denied=0;
			head->next_user=NULL;
		}
		if(action_denied==1){ 
			temp=head;
			while(temp->uid!=uid && temp->next_user!=NULL){
				temp=temp->next_user;
			}

			if(temp->uid!=uid && temp->next_user==NULL){
				new_entry=(struct entry*)malloc(sizeof(struct entry));
				temp->next_user=(struct entry*)malloc(sizeof(struct entry));
				temp->next_user=new_entry;
				new_entry->uid=uid;
				new_entry->times_denied=0;
				new_entry->next_user=NULL;
				temp=new_entry;
				//new_entry->next_entry_of_the_user=NULL;
			}

			for(i=0;i<8;i++){
				if(strcmp(filepath,temp->access_denied[i])==0){
					isinarray=1;
				}
			}
			if(isinarray==0 && temp->times_denied<9){
				temp->times_denied++;
				memcpy(temp->access_denied[temp->times_denied-1],filepath,MAX_PATH);
			}	
		}	

	}

	temp=head;
	while(temp!=NULL){
		if(temp->times_denied>=8){
			printf("Malicious user found with uid: %d \n", temp->uid);
		}

		if(temp->next_user!=NULL){
			temp=temp->next_user;

		}
	}
	while(head!=NULL){
		temp=head->next_user;
		free(head);
		head=temp;
	}
	
	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	int uid;
	char filepath[MAX_PATH];
	int year, month, day,hour,min,sec;
	int access_type;
	int action_denied;
	char* fingerprint;
	unsigned char md;
	char* data=NULL;
	size_t length=0;
	size_t read;
	char* filename;
	struct entry* temp;
	struct entry* new_entry;
	int i;

	while((read = getline(&data,&length,log))!= -1){
		sscanf(data,"%u %s %d-%d-%d %d:%d:%d %d %d",&uid, filepath, &day, &month,&year,&hour,&min,&sec, &access_type,&action_denied);
		filename=strrchr(filepath,'/')+1;
		if(action_denied==0 && head==NULL && strcmp(file_to_scan,filename)==0){
			temp=(struct entry*)malloc(sizeof(struct entry));
			temp->next_user=(struct entry*)malloc(sizeof(struct entry));
			head=temp;
			head->uid=uid; /* user id (positive integer) */
			head->times_accessed=0;
			head->next_user=NULL;
		}
		if(action_denied==0  && strcmp(file_to_scan,filename)==0){ 
			temp=head;
			while(temp->uid!=uid && temp->next_user!=NULL){
				temp=temp->next_user;
			}

			if(temp->uid!=uid && temp->next_user==NULL){
				new_entry=(struct entry*)malloc(sizeof(struct entry));
				temp->next_user=(struct entry*)malloc(sizeof(struct entry));
				temp->next_user=new_entry;
				new_entry->uid=uid;
				new_entry->times_accessed=0;
				new_entry->next_user=NULL;
				temp=new_entry;
			}

			temp->times_accessed++;

		}	

	}
	while(temp!=NULL){
		printf("The number of times the file Has been accessed is: %d by the user: %d \n", temp->times_accessed,temp->uid);
		temp=temp->next_user;
	}


	return;

}



void recent_creation(FILE *log,int number_of_files){
	int uid;
	char filepath[MAX_PATH];
	int year, month, day,hour,min,sec;
	int access_type;
	int action_denied;
	char* fingerprint;
	char* data=NULL;
	size_t length=0;
	size_t read;

	time_t timenow;
	struct tm date;

	int counter=0;

	while((read = getline(&data,&length,log))!= -1){
		sscanf(data,"%u %s %d-%d-%d %d:%d:%d %d %d",&uid, filepath, &day, &month,&year,&hour,&min,&sec, &access_type,&action_denied);
		if(action_denied==0 && access_type==0){
			memset(&date,0,sizeof date);
			date.tm_year=year-1900;
			date.tm_mon=month-1;
			date.tm_mday=day;
			date.tm_hour=hour;
			date.tm_min=min;
			date.tm_sec=sec;
			time(&timenow);
			if(difftime(timenow,mktime(&date))<=1200){
				counter++;
			}
		}
	}


	if(counter>=number_of_files){
		printf("Alert: The number of files that have been created the last 20 minutes are: %d",counter);
	}else{
		printf("The number of files tha have been created are: %d",counter);
		printf("\n");
	}

	return;
}






void find_encrypted_files(FILE *log){

	int uid;
	char filepath[MAX_PATH];
	int year, month, day,hour,min,sec;
	int access_type;
	int action_denied;
	char* fingerprint;
	char* data=NULL;
	size_t length=0;
	size_t read;
	struct encrypted_filenames* temp_encrypted_filenames;
	struct encrypted_filenames* new_entry_encrypted_filenames;
	struct filenames* temp_filenames;
	struct filenames* new_entry_filenames;

	while((read = getline(&data,&length,log))!= -1){
		sscanf(data,"%u %s %d-%d-%d %d:%d:%d %d %d",&uid, filepath, &day, &month,&year,&hour,&min,&sec, &access_type,&action_denied);
		char* filename=strrchr(filepath,'/')+1;

		if(access_type==0){
			if(strstr(filename,".encrypt")){
				if(head_encrypted_filenames==NULL){
					temp_encrypted_filenames=(struct encrypted_filenames*)malloc(sizeof(struct encrypted_filenames));
					temp_encrypted_filenames->next_filename=(struct encrypted_filenames*)malloc(sizeof(struct encrypted_filenames));
					temp_encrypted_filenames->next_filename=NULL;
					head_encrypted_filenames=temp_encrypted_filenames;
					temp_encrypted_filenames->filename=filename;
				}else{
					new_entry_encrypted_filenames=(struct encrypted_filenames*)malloc(sizeof(struct encrypted_filenames));
					new_entry_encrypted_filenames->next_filename=(struct encrypted_filenames*)malloc(sizeof(struct encrypted_filenames));
					new_entry_encrypted_filenames->next_filename=NULL;
					temp_encrypted_filenames->next_filename=new_entry_encrypted_filenames;
					new_entry_encrypted_filenames->filename=filename;
				}
			}else{
				if(head_filenames==NULL){
					temp_filenames=(struct filenames*)malloc(sizeof(struct filenames));
					temp_filenames->next_filename=(struct filenames*)malloc(sizeof(struct filenames));
					temp_filenames->next_filename=NULL;
					head_filenames=temp_filenames;
					temp_filenames->filename=filename;
				}else{
					new_entry_filenames=(struct filenames*)malloc(sizeof(struct filenames));
					new_entry_filenames->next_filename=(struct filenames*)malloc(sizeof(struct filenames));
					new_entry_filenames->next_filename=NULL;
					temp_filenames->next_filename=new_entry_filenames;
					new_entry_filenames->filename=filename;

				}

			}
		}
	}
	temp_encrypted_filenames=head_encrypted_filenames;
	temp_filenames=head_filenames;
	int counter=0;
	while(temp_encrypted_filenames!=NULL && counter<10){
		if(temp_filenames!=NULL){
			if(strstr(temp_encrypted_filenames->filename,temp_filenames->filename)){
				printf("The file %s has been encrypted \n", temp_filenames->filename);
			}
			temp_filenames=temp_filenames->next_filename;
		}else{
			temp_encrypted_filenames=temp_encrypted_filenames->next_filename;
			temp_filenames=head_filenames;
		}
		counter++;
	}
}











	int 
	main(int argc, char *argv[])
	{
		int n;
		int ch;
		FILE *log;

		if (argc < 2)
			usage();
		log = fopen("/tmp/file_logging.log", "r");
		if (log == NULL) {
			printf("Error opening log file \"%s\"\n", "/tmp/file_logging.log");
			return 1;
		}

		while ((ch = getopt(argc, argv, "ehiv:m")) != -1) {
			switch (ch) {	
				case 'e':
				 find_encrypted_files(log);
				break;	
				case 'i':
				list_file_modifications(log, optarg);
				break;
				case 'm':
				list_unauthorized_accesses(log);
				break;
				case 'v':
				n=atoi(argv[2]);
				recent_creation(log,n);
				break;
				default:
				usage();
			}

		}

		fclose(log);
		argc -= optind;
		argv += optind;	

		return 0;
	}
