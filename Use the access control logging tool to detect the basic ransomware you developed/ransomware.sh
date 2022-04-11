#!/bin/bash
#directory="/home/ilamprinidis/Documents/test"
#j=5
directory=""
let number=0
function create(){
	LD_PRELOAD=./logger.so ./test_aclog "$directory" "$number"
}

function encrypt(){
	for i in $directory/*
	do
		LD_PRELOAD=./logger.so openssl enc -aes-256-ecb -a -in $i -out $i.encrypt -k 1234 
		rm $i
	done
}


function printmenu(){
	printf "how to use: \n"
	printf -- "-c <directory> <numberOfFiles> the number of files to be created for the testing of the ransomware \n"
	printf -- "-e <directory> encrypt all the files in the specified directory \n"
}

	if [[ "$1" == "-c" ]] ; then
		directory="$2"
		number="$3"
		create
	elif [[ "$1" == "-e" ]]
		then 
			directory="$2"
			encrypt
		else
			printmenu
	fi
	exit 0
