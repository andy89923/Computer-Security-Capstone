#!/bin/sh

#gdb Timeout

echo "Solution 1:"
gdb --batch --command=test.gdb --args ./Timeout

echo
echo "Solution 2:"
LD_PRELOAD=$PWD/inject.so ./Timeout
