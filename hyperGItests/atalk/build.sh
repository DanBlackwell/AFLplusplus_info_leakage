#!/bin/bash
#
# Sample usage for ALEN 16
#    ./build.sh 
#

rm -f atalk.o driver1

VAR=$(g++ -g -o atalk.o -c atalk.c 2>&1)

if echo "$VAR" | grep -q "error:"; then
  echo "error: $VAR"
else
	g++ -std=c++11 atalk.o -g -o driver driver.cpp
	python3 driver.py
fi
