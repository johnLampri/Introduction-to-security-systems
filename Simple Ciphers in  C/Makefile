demoprogram: demoprogram.o
	gcc -o demoprogram demoprogram.o simple_crypto.o

demoprogram.o: simple_crypto.o demoprogram.c
	gcc -c demoprogram.c

simple_crypto.o: simple_crypto.c
	gcc -c simple_crypto.c

clear:
	rm *.o demoprogram
