#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define N 50

char notCapsCheckEncrypt(char,int*);
char CapsCheckEncrypt(char,int*);
char numericalCheckEncrypt(char,int*);
char notCapsCheckDecrypt(char,int*);
char CapsCheckDecrypt(char,int*);
char numericalCheckDecrypt(char,int*);



void getRandomKey(int k, char* Key){
	 char testchar[N];
	FILE* random=fopen("/dev/urandom","r");
	int keylen=strlen(Key);
int i=0;
	int j=0;
	while(i<keylen){
		if(j=keylen){
			j=0;
			fgets(testchar,keylen,(FILE*)random);
		}
		
		if(isdigit(testchar[j]) || isalpha(testchar[j])){
			Key[i]=testchar[j];
			i++;
			
		}
		j++;
	}
		fclose(random);
		
}

char*  OTPEncrypt(char* password,char* Key,char* encrypted){
	
	int i=0;
	
	for (i=0; i<strlen(password); i++){
		encrypted[i]=Key[i] ^ password[i];  
		
	}
}

void  OTPDecrypt(char* encrypted,char* Key,char* decrypted){
	
	int i=0;
	
	for (i=0; i<strlen(encrypted); i++){
		decrypted[i]=Key[i] ^ encrypted[i];  
	}

}

char*  CaesarsEncrypt(int Key,char* password,char * encrypted){

	int  length = strlen(password); 
	int temp;
	//int Key;
	char testchar[length];	



int i;
Key=Key%62;
int saveKey=Key;
for(i=0; i<N;i++){
	unsigned char temp=password[i];
	if(temp>='0' && temp<='9'){
		temp=numericalCheckEncrypt(temp,&Key);
	}else if(temp>='A' && temp<='Z'){
		temp=CapsCheckEncrypt(temp,&Key);
	}else if(temp>='a' && temp<='z'){
		temp=notCapsCheckEncrypt(temp,&Key);
	}else if(temp=='\0'){
		encrypted[i]=temp;
		i=N;
	}else{
			
			i=N;
		return encrypted;
	}
	encrypted[i]=temp;
	Key=saveKey;
}

return encrypted;
}




char * CaesarsDecrypt(int Key,char* encrypted, char * decrypted){
	int  length = strlen(encrypted); 
	char testchar[length];
	int temp,saveKey=Key;
int i;
for(i=0; i<N;i++){
	unsigned char temp=encrypted[i];
	if(temp>='0' && temp<='9'){
		temp=numericalCheckDecrypt(temp,&Key);
	}else if(temp>='A' && temp<='Z'){
		temp=CapsCheckDecrypt(temp,&Key);
	}else if(temp>='a' && temp<='z'){
		temp=notCapsCheckDecrypt(temp,&Key);
	}else if(temp=='\0'){
		decrypted[i]=temp;
		i=N;
	}else{
			
			i=N;
		return decrypted; 
	}
	decrypted[i]=temp;
	Key=saveKey;
}
	return decrypted; 
}

char CapsCheckEncrypt(char k,int* key){
	unsigned char temp=k+*key;
	if(temp>'Z'){
		temp='a';
		*key= *key-('Z'- k)-1;
		temp=notCapsCheckEncrypt(temp,key);
	}
		return temp;
}

char numericalCheckEncrypt(char k,int* key){
	unsigned char temp=k+*key;
	if(temp>'9'){
		temp='A';
		*key= *key-('9'- k)-1;
		temp=CapsCheckEncrypt(temp,key);
	}
		return temp;
}



char notCapsCheckEncrypt(char k,int* key){
	unsigned char temp=k+*key;
	if(temp>'z'){
		temp='0';
		*key= *key-('z'- k)-1;
		temp=numericalCheckEncrypt(temp,key);
	}
	return temp;
}

char numericalCheckDecrypt(char k,int* key){
	unsigned char temp=k-*key;
	if(temp<'0'){
		temp='z';
		*key= *key-(k-'0')-1;
		temp=notCapsCheckDecrypt(temp,key);
	}
		return temp;
}

char notCapsCheckDecrypt(char k,int* key){
	unsigned char temp=k-*key;
	if(temp<'a'){
		temp='Z';
		*key= *key-(k-'a')-1;
		temp=CapsCheckDecrypt(temp,key);
	}
	return temp;
}


char CapsCheckDecrypt(char k,int* key){
	unsigned char temp=k-*key;
	if(temp<'A'){
		temp='9';
		*key= *key-(k-'A')-1;
		temp=numericalCheckDecrypt(temp,key);
	}
		return temp;
}

char CapsCheckEncryptVigenere(char k,int* key){
	unsigned char temp=k+*key;
	if(temp>'Z'){
		temp='A';
		*key= *key-('Z'- k)-1;
		temp=CapsCheckEncryptVigenere(temp,key);
	}
		return temp;
}

char CapsCheckDecryptVigenere(char k,int* key){
	unsigned char temp=k-*key;
	if(temp<'A'){
		temp='Z';
		*key= *key-(k-'A')-1;
		temp=CapsCheckDecryptVigenere(temp,key);
	}
		return temp;
}

void ViginereCipherEncrypt(char* input, char* key,char* encrypted){
	int i=0;
	int f=0;
	int keylen=strlen(key);
	if(strlen(key)<strlen(input)){
		for(i=0; i<strlen(input);i++){
			f=i%keylen;
			key[i]=key[f];
		}
		
	
	}	
	i=0;		
	while(i<strlen(input) && input[i]!='\0'){

		int temp=key[i]-'A';
		char  tempchar;
		tempchar=input[i];
		encrypted[i]=CapsCheckEncryptVigenere(tempchar,&temp);

		i++;
	} 

} 

void ViginereCipherDecrypt(char* encrypted, char* key,char* decrypted){
	int i=0;
	int f=0;
		
	i=0;		
	while(i<strlen(encrypted) && encrypted[i]!='\0'){

		int temp=key[i]-'A';
		char  tempchar;
		tempchar=encrypted[i];
		decrypted[i]=CapsCheckDecryptVigenere(tempchar,&temp);

		i++;
	} 

}

void OTP(){

	  char password[N];
	int Key;
	  char key[N];
	static  char encrypted[N];
	 static char decrypted[N];
	 int i=0;

	printf("[OTP]input: ");
	scanf("%s",password);
	getRandomKey(strlen(password)+1,key);
	OTPEncrypt(password,key,encrypted);
	printf("[OTP]encrypted: ");

	for(i=0;i<strlen(encrypted);i++){
		if(encrypted[i]>='!'){
			printf("%c",encrypted[i]);
		}
	}
	printf("\n");
	OTPDecrypt(encrypted,key,decrypted);
	
	printf("[OTP]decrypted: %s \n",decrypted);



}
void Caesars(){
	char password[N];
	char encryptedCaesars[N];
	 char decryptedCaesars[N];
int Key;


	 printf("[Caesars]input: ");
	scanf("%s", password);
	printf("[Caesars]key: ");
	scanf("%d",&Key);
	CaesarsEncrypt(Key,password,encryptedCaesars);
	printf("[Caesars]encrypted: ");
	printf("%s",encryptedCaesars);
			printf("\n[Caesars]decrypted: ");
	CaesarsDecrypt(Key,encryptedCaesars,decryptedCaesars);
	printf("%s",decryptedCaesars);
			printf("\n");


}

void Vigenere(){
	char password[N];
 	char encrypted[N];
	static  char decrypted[N];
	char key[N];
	printf("[Vigenere]input: ");
	scanf("%s",password);
	printf("[Vigenere]key: ");
	scanf("%s",key);
	ViginereCipherEncrypt(password,key,encrypted);
		printf("[Vigenere]encrypted: ");
	printf("%s \n",encrypted);
	ViginereCipherDecrypt(encrypted,key,decrypted);
	printf("[Vigenere]decrypted: ");
	printf("%s",decrypted);
	printf("\n");
}


