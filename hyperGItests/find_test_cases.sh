#!/bin/bash

export RUNTIME=$(( 8 * 3600 )) 
export RUNTIME=$(( 3600 )) 
export BRANCHES=8

mkdir -p results 
pushd results
#	mkdir -p atalk 
#	pushd atalk 
#		mkdir -p IN/ OUT/
#  		echo "0000000045CB76472730426C46797A2927004D585858585858" > IN/seed
#		echo "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE" > IN/seed2
#  		timeout $RUNTIME afl-fuzz -H $BRANCHES -i IN/ -o OUT -- /hyperGItests/atalk/atalk 2>&1 > fuzzing.log &
#	popd
#
#	mkdir -p classify 
#	pushd classify 
#		mkdir -p IN/ OUT/
#		echo "29 3" > IN/seed
#	  	timeout $RUNTIME afl-fuzz -H $BRANCHES -i IN/ -o OUT -- /hyperGItests/classify/classify 2>&1 > fuzzing.log &
#	popd
#
	mkdir -p triangle 
       	pushd triangle 
		mkdir -p IN/ OUT/
		echo "29 3 28" > IN/seed
		timeout $RUNTIME afl-fuzz -H $BRANCHES -i IN/ -o OUT -- /hyperGItests/triangle/triangle 2>&1 > fuzzing.log &
	popd
#
#	mkdir -p underflow 
#	pushd underflow 
#		mkdir -p IN/ OUT/
#		echo "-46 144114834507431000" > IN/seed
#		echo "1 -557221675008" > IN/seed2
#		echo "1079 140723055538320" > IN/seed3
#		timeout $RUNTIME afl-fuzz -H $BRANCHES -i IN/ -o OUT -- /hyperGItests/underflow/underflow 2>&1 > fuzzing.log &
#	popd
#
#	mkdir -p heartbleed 
#	pushd heartbleed 
#		mkdir -p IN/ OUT/
#  		echo "35333241374232453942364639090900000012000000" > IN/seed
#		echo "353332413742324539423646390909000000" > IN/seed2
#		echo "D62F6BEB04B5A7FEBB56D078E638CA45FFC00000" > IN/seed3
#  		timeout $RUNTIME afl-fuzz -H $BRANCHES -i IN/ -o OUT -- /hyperGItests/heartbleed/test/heartbeat_simple.exe 2>&1 > fuzzing.log &
#	popd
#
#	mkdir -p bignum_fuzz
#       	pushd bignum_fuzz
#		mkdir -p IN/ OUT/
#  		echo "F109000000" > IN/seed
#  		timeout $RUNTIME afl-fuzz -H $BRANCHES -i IN/ -o OUT -- /hyperGItests/bignum_fuzz/bnafl-driver 2>&1 > fuzzing.log &
#	popd

	wait

	pushd triangle
                mkdir -p MINIFIED
                afl-cmin -i OUT/default/queue -o MINIFIED -- /hyperGItests/triangle/triangle
	popd

#        pushd heartbleed
#                mkdir -p MINIFIED
#                afl-cmin -i OUT/default/queue -o MINIFIED -- /hyperGItests/heartbleed/test/heartbeat_simple.exe
#        popd

popd
