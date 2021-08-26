#!/bin/bash
#
# printfiles.sh first compiles and builds driver.c file. Then, it
#   runs the executable file for each output file from afl-fuzz 
#   (output files are in the out${FOLDERNUM}/default/queue folder). 
#   The output is sent to standard output and so that it can be copied 
#   into the driver.py file to use as functional tests 
#
# Sample usage:
#   ./printfiles.sh folder_num
# Example:
#   	./printfiles.sh 5
#   reads files information for folder numbers from 1..5 
#   for all folders "output/out${FOLDERNUM}/default/queue" folder
#   and prints the functional test array for the driver.py
#   like folder names
#       output/out1/default/queue
#       output/out2/default/queue
#       ...
#       output/out5/default/queue
#

FNAME="triangle"
CC=gcc
StartFolder=$1
LastFolder=$2

rm -rf ${FNAME}.o ${FNAME} 

VAR=$(${CC} -g -c -o ${FNAME}.o ${FNAME}.c 2>&1)

if echo "$VAR" | grep -q "error:"; then
  echo "error:"
else
    DRIVER="driver4printfile"
    ${CC} ${FNAME}.o -g -o ${DRIVER} ${DRIVER}.c

    for (( folder=${StartFolder}; folder<=${LastFolder}; folder++ ))
    do
        # echo ${folder}
        for input_file in output/out${folder}/default/queue/*
        do
            ./${DRIVER} < ${input_file}
        done
    done
fi

