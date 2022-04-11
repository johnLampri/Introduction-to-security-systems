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


struct entry* head;

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
	

		sscanf(data,"%d %s %d-%d-%d %d:%d:%d %d %d ",&uid, filepath, &day, &month,&year,&hour,&min,&sec, &access_type,&action_denied);
		if(action_denied==1 && head==NULL){
			temp=(struct entry*)malloc(sizeof(struct entry));
			temp->next_user=(struct entry*)malloc(sizeof(struct entry));
			head=temp;
			head->uid=uid; /* user id (positive integer) */
			head->times_denied=0;
			head->next_user=NULL;
		}
		if(action_denied==1){ //THINK BEFORE SUBMITTING
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
		sscanf(data,"%u %s %d-%d-%d %d:%d:%d %d %d %s",&uid, filepath, &day, &month,&year,&hour,&min,&sec, &access_type,&action_denied,fingerprint);
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


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("/tmp/file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "/tmp/file_logging.log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
			case 'i':
			list_file_modifications(log, optarg);
			break;
			case 'm':
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
