#!/bin/bash


for file in out/default/queue/*
do
    echo "${file}"
    test/bndriver < ${file} 
    echo ""
done
