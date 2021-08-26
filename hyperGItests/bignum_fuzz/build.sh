#!/bin/bash
# Sample usage for gcc
#   ./build.sh hex_input nhigh  
#   ./build.sh 35333241374232453942364639090E000000  5
# *) assuming last 4 bytes of the hexstring are the length of hexstring (0E000000 => 14 bytes)
# *) run the program repeatedly 5 times

VAR=$(./buildbntest.sh 35333241374232453942364639090E000000  5)

if echo "$VAR" | grep -q "error:"; then
  echo "error:"
else
    python3 driver.py
fi

