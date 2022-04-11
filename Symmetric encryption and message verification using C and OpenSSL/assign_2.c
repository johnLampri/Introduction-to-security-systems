#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#include <sys/stat.h>
#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */

int encryptDecrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int ,int);
unsigned char* readFromFile(char* , int* );
void writeToFile(unsigned char*,char*,int);




/*
 * Prints the hex value of the input
 * 16 values per line
 */

void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{
	/* TODO Task A */
	 const EVP_CIPHER* evpCypher;
	if(bit_mode==128){
		evpCypher=EVP_aes_128_ecb();
	}else{
		evpCypher=EVP_aes_256_ecb();
	}
	EVP_BytesToKey(evpCypher,EVP_sha1(),NULL,password,strlen((const char*)password),1,key,NULL);
	printf("Key gen succesful. \n!");
}


/*
 * Encrypts the data
 */
void
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{

	/* TODO Task B */
	encryptDecrypt(plaintext,plaintext_len,key,iv,ciphertext,bit_mode,1);
		printf("Encryption succesful. \n!");

}


/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{	

	int plaintext_len=encryptDecrypt(ciphertext,ciphertext_len,key,iv,plaintext,bit_mode,0);
	printf("Decryption succesful. \n!");
	return plaintext_len;
	

}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{

	/* TODO Task D */
	CMAC_CTX* cmacCtx=CMAC_CTX_new();
	const EVP_CIPHER* evpCypher;
	size_t length;
	if(bit_mode==128){
		evpCypher=EVP_aes_128_ecb();
	}else{
		evpCypher=EVP_aes_256_ecb();
	}

	CMAC_Init(cmacCtx,key,bit_mode/8,evpCypher,NULL);
	CMAC_Update(cmacCtx,data,data_len);
	CMAC_Final(cmacCtx,cmac,&length);
	CMAC_CTX_free(cmacCtx);
			printf("Generated cmac succesfully. \n!");

}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{	
	printf("Verified cmac succesfully. \n!");
	return memcmp(cmac1,cmac2,BLOCK_SIZE);
}
/* TODO Develop your functions here... */



/*reads a file and stores it's content into an array.*/

unsigned char* readFromFile(char* inputfile, int* inputfileLength){
			

	FILE* file=fopen(inputfile,"rb");
	if(!file) exit(1);
	if(fseek(file,0,SEEK_END)!=0) exit(1);
	*inputfileLength=ftell(file);

	fseek(file,0,SEEK_SET);

	unsigned char* input=(unsigned char *)malloc((*inputfileLength+1)*sizeof(char));
	int i=fread(input,1,*inputfileLength,file);
	fclose(file);
	printf("Read from file succesfully. \n!");

	return input;
}
	/*writes a file.*/

void writeToFile(unsigned char* data,char* outputfile,int data_length){
	FILE* file=fopen(outputfile,"wb");
	//if(!file) exit(1);
	fwrite(data,1,data_length,file);
	fclose(file);
	printf("Written to file succesfully. \n!");

}

/*
*It is used to either decrypt or encrypt the operations is depndant to the value of define op.
*If it is 1 it encrypts, 0 it decrypts.
*/

int encryptDecrypt(unsigned char *text, int text_len, unsigned char *key,
    unsigned char *iv, unsigned char *endtext, int bit_mode,int defineop){
	EVP_CIPHER_CTX* evpCypherCtx=EVP_CIPHER_CTX_new();
	const EVP_CIPHER* evpCypher;
	int length,destinationlength=0;


	if(bit_mode==128){
		evpCypher=EVP_aes_128_ecb();
	}else{
		evpCypher=EVP_aes_256_ecb();
	}
	EVP_CipherInit(evpCypherCtx,evpCypher,key,NULL,defineop);
	EVP_CipherUpdate(evpCypherCtx,endtext,&length,text,text_len);
	destinationlength=length;
	EVP_CipherFinal(evpCypherCtx,text + length, &length);
	destinationlength=length+destinationlength;
	EVP_CIPHER_CTX_free(evpCypherCtx);
	return destinationlength;
}

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	unsigned char * input=NULL;
	unsigned char* output=NULL;
	int  input_file_length=0;
	int output_file_length=0;
	unsigned char cmac_verify[BLOCK_SIZE];
	int verify_cmac_flag;

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;

	unsigned char key[256];
	unsigned char iv[256];

	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:degvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 'g':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	

	/* TODO Develop the logic of your tool here... */

	/* Keygen from password */
	
	keygen(password,key,iv,bit_mode);

	input=readFromFile(input_file,&input_file_length);


	/* Operate on the data according to the mode */

	if(op_mode==0){
		/* encrypt */
		output_file_length=input_file_length-(input_file_length%BLOCK_SIZE)+BLOCK_SIZE;
		output=(unsigned char *)malloc(output_file_length);
		encrypt(input,input_file_length,key,iv,output,bit_mode);
		writeToFile(output,output_file,output_file_length);

	}else if(op_mode==1){
	/* decrypt */
		output=(unsigned char *)malloc(input_file_length);
		output_file_length=decrypt(input,input_file_length,key,iv,output,bit_mode);
		writeToFile(output,output_file,output_file_length);

	}else if(op_mode==2){
	/* sign */

		output_file_length=input_file_length-(input_file_length%BLOCK_SIZE)+2*BLOCK_SIZE;
		output=(unsigned char *)malloc(output_file_length);
		encrypt(input,input_file_length,key,iv,output,bit_mode);
		//the pointer is moved to the correct position
		gen_cmac(input,input_file_length,key,output +(output_file_length-BLOCK_SIZE) ,bit_mode);
		writeToFile(output,output_file,output_file_length);

	}else if(op_mode==3){
			/* verify */
		output=(unsigned char *)malloc(input_file_length);
		output_file_length=decrypt(input,input_file_length ,key,iv,output,bit_mode);
		//the pointer is moved to the correct position
		gen_cmac(output,output_file_length,key,cmac_verify,bit_mode);
		verify_cmac_flag=verify_cmac(cmac_verify,input+(input_file_length-BLOCK_SIZE));
		if(verify_cmac_flag==1){
			printf("TRUE");
			writeToFile(output,output_file,output_file_length);
		}else{
			printf("FALSE");

		}
	}

		

	/* Clean up */
	free(output);
	free(input);
	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
