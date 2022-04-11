#include "rsa.h"
#include "utils.h"

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
 size_t *primes;
    int prime[limit+1];
    int i;
    int j;
    int count=0;
    for (int i=0;i<=limit;i++){
        prime[i]=1;
       }
    for(i=2;i <=limit ;i++){
        if(prime[i]==1){
            for(j=i*i;j<=limit;j=j+i){
                prime[j]=0;
            }


        }
    }

    for(i=2;i<=limit;i++){
        if(prime[i]==1){
            count++;
        }
    }
    primes= (size_t*)malloc(sizeof(size_t)*count);
    j=0;
    for(i=2;i<=limit;i++){
        if(prime[i]==1){
            primes[j]=(size_t)i;
            j++;
        }
    }

    *primes_sz=count;




    return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
    if(a==0){
        return b;
    }
	
    if(b==0){
        return a;
    }

    if(a>b){
        return gcd(a-b,b);
    }else{
        return gcd(a,b-a);
    }



}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
    int random;
	size_t e;
    int flag=0;
    while(flag!=1){
        random=(rand()%(fi_n-1))+2;   
        if(gcd(random,fi_n)==1){
            e=(size_t)random;
            flag=1;
        }

    }

	return e;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{
    int i;
	for(i=1;i<b;i++){
        if(((a%b)*(i%b))%b ==1){
            return i;
        }
    }
}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */


unsigned char* readFromFile(char* inputfile, int* inputfileLength){
            

    FILE* file=fopen(inputfile,"rb");
    if(!file) exit(1);
    if(fseek(file,0,SEEK_END)!=0) exit(1);
    *inputfileLength=ftell(file);

    fseek(file,0,SEEK_SET);

    char* input=( char *)malloc((*inputfileLength+1)*sizeof(char));
    int i=fread(input,1,*inputfileLength,file);
    fclose(file);

    return input;
}


void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;
    size_t *primes;
    int number_of_primes=0;
	//1)
    primes=sieve_of_eratosthenes(RSA_SIEVE_LIMIT,&number_of_primes);
    //2)
    p=primes[rand()%number_of_primes];
    q=primes[rand()%number_of_primes];
    //3)
    n=p*q;
    //4)
    fi_n=(p-1)*(q-1);
    //5)
    e=choose_e(fi_n);
    d=mod_inverse(e,fi_n);
    FILE* file=fopen("hpy414_private.key","a");
     if(!file) exit(1);
    fwrite(&n,sizeof(size_t),1,file);
    fwrite(&d,sizeof(size_t),1,file);
    fclose(file);

    file=fopen("hpy414_public.key","a");
     if(!file) exit(1);
    fwrite(&n,sizeof(size_t),1,file);
    fwrite(&e,sizeof(size_t),1,file);
    fclose(file);


}


int pow_mod(int base,int exponent,int mod){
    base=base%mod;
    int result=1;
    while(exponent>0){
        if(exponent%2){
            result=(result*base)%mod;
        }
        base=(base*base)%mod;
        exponent=exponent/2;
    }


    return result;


}




/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
    
    char* key;
    size_t* output;
	int input_length,key_length,output_length;
    int n,secondkey;
    char* input=readFromFile(input_file,&input_length);

    output_length=input_length*sizeof(size_t);
    output=(size_t*)malloc(output_length);
    key=readFromFile(key_file,&key_length);
    memcpy(&n,key,sizeof(size_t));
    memcpy(&secondkey,key+sizeof(size_t),sizeof(size_t));
    int i;
    for(i=0;i<input_length;i++){
        output[i]=pow_mod((size_t)(input[i]),secondkey,n);
    }
    FILE* file=fopen(output_file,"w");
     if(!file) exit(1);
     fwrite(output,sizeof(size_t),input_length,file);

     fclose(file);
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

	char* key;
    int input_length,key_length;
    int inputfileLength;
    int n,secondkey;
    size_t* out;
   // char* input=readFromFile(input_file,&input_length);
    FILE* file=fopen(input_file,"rb");
    if(!file) exit(1);
    if(fseek(file,0,SEEK_END)!=0) exit(1);
    inputfileLength=ftell(file);
    int plaintext_length=inputfileLength/sizeof(size_t);

    fseek(file,0,SEEK_SET);
    size_t* input=( size_t *)malloc((inputfileLength)*sizeof(char));
    int i=fread(input,1,inputfileLength,file);
    fclose(file);
    key=readFromFile(key_file,&key_length);
    memcpy(&n,key,sizeof(size_t));
    memcpy(&secondkey,key+sizeof(size_t),sizeof(size_t));

    unsigned char* plaintext=(unsigned char*)malloc(plaintext_length*sizeof(unsigned char));
    for(i=0;i<inputfileLength/sizeof(size_t);i++){
        plaintext[i]=(unsigned char)pow_mod(input[i],secondkey,n);
    }
     file=fopen(output_file,"w");
     if(!file) exit(1);
     fwrite(plaintext,sizeof(unsigned char),plaintext_length,file);
     fclose(file);
}





