#!/usr/bin/python3 

import random
import string

charset = string.ascii_letters + string.digits + '_{}'

class MyRandom:
	def __init__(self):
		self.n = 2**256
		self.a = random.randrange(2**256)
		self.b = random.randrange(2**256)

	def _random(self):
		tmp = self.a
		self.a, self.b = self.b, (self.a * 69 + self.b * 1337) % self.n
		tmp ^= (tmp >> 3) & 0xde
		tmp ^= (tmp << 1) & 0xad
		tmp ^= (tmp >> 2) & 0xbe
		tmp ^= (tmp << 4) & 0xef
		return tmp

	def random(self, nbit):
		return sum((self._random() & 1) << i for i in range(nbit))


f = open('output.txt')
h = f.read().strip()
f.close()

c = bytes.fromhex(h)

rnds = [0, 182, 109, 219]

all_possible = []
while len(all_possible) < 4:
	random_sequence = []
	rng = MyRandom()
	random_sequence = [rng.random(8) for _ in range(10)]
	# print(random_sequence)
	if not random_sequence in all_possible:
		all_possible.append(random_sequence)


# print(all_possible)



def dfs(p, pre):
	if p >= len(c): return
	print("DFS:", p, pre)
	
	for i in all_possible:
		now = pre
		poi = p
		ok = True
		for j in i:
			cha = chr(c[poi]^j)
			if cha not in charset: 
				ok = False
				break
			now = now + cha
			poi = poi + 1
			if poi == len(c):
				if 'CSC2022' in now:
					print("\nFlag:")
					print(now)
				break
		if ok: dfs(poi, now)


dfs(0, "")

# CSC2022{yoU_Are_4_crYPT4NalYs7_tNhzBlyyjztEObcEYRFwiZZqvAIZ}
