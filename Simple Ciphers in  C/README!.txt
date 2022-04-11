
Files:
1)simple_crypto.h: It contains the declarations of the functions that have been used.
2)simple_crypto.c: Consists of the implemented functions.The cryptographic functions are fully functional.

--------------------------OTP--------------------------------
This function uses the logical function XOR to the input and a random key generated from u/dev/urandom.
If the encrypted output has a non printable ascii character the function does not print it.

--------------------Ceasar's Cipher--------------------------
The cipher works with the condition that the input is alhpanumeric and that the numeric,uppercase and lowercase are a single set. The function was implemented with the use of recursion.


----------------Viginere's cipher---------------------------
For the implementation of this function a Ceasar's cipher for each letter and the key for the Caesars cipher was the corresponding key letter the ascii value of letter A.

------------------------------------------------------------



3)demo.c: This file is used to execute the main function that calls the function for each corresponding algorithm.

4) makefile: A makefile to compile the code.







gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0