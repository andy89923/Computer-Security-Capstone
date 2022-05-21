import sys
import itertools
import time

file_path = 'test.dat'

f = open(file_path)
tmp = f.readlines()
lin = [line.rstrip('\n') for line in tmp]
lin = lin + lin
tried = []

for i in range(1, len(lin) + 1):
	for j in itertools.permutations(lin, i):
		now = ''.join(j)
		if now in tried: continue;
		tried.append(now)
		print(now)
		time.sleep(0.5)