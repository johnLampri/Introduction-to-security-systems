Task A
The function EVM_BytesToKey() was used to generate a key.

Task B - Task C
For these two tasks a single gunction was created encryptdecrypt where depending on it's input it either decrypts(0) or incrypts(1). After processing the data the output is stored in a file specified by the user.

Task D
First the process encrypts the file and then it generates and signs the ciphertext. After it stores the ciphertext in a file specified by the user.

Task E
The process is supposed to read a ciphertext, get it's cmac and decrypt the ciphertext. Then it generates a cmac from the plaintext and compares the two cmacs.
Task F
All the operations were succesfull except the 4th step. For some reason it could not verify any files.

gcc VERSION
gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0


