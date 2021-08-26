#!/bin/bash
# Sample usage for gcc
#   ./run.sh hex_string nhigh
#   ./run.sh 35333241374232453942364639090E000000 5
# *) assuming last 4 bytes of the hexstring are the length of hexstring (12000000 => 18 bytes)
# *) run the program repeatedly 5 times
#

FNAME="test/bndriver"

for (( c=0; c < ${2}; c++ ))
do
    ./${FNAME} $1
done


