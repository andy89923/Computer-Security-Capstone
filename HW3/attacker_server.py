#!/usr/bin/env python3

# The program is used to launch attacker server. The port to use 
# have to define when program launching.
# $./attacker_server <Attacker port>” to set up the attacker server

import sys
import time

usage_txt = "./attacker_server <Attacker port>"
target_port = None

def main():
	global target_port

	try:
		target_port = sys.argv[1]
	except:
		print(f"Usage:\n{usage_txt}")
		return

	print(f"Launching the Attacker Server on port: {target_port}")
	time.sleep(3)
	print(f'Actually nothing to do in this file')
	return 

if __name__ == '__main__':
    main()