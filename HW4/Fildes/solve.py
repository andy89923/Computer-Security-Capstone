#!/usr/bin/python3

# https://ithelp.ithome.com.tw/articles/10217253 
from pwn import remote
import warnings

warnings.filterwarnings("ignore", category=BytesWarning)

server_ip = "140.113.207.246"
target_pt = 20221

rmt = remote(server_ip, target_pt)
rmt.recvuntil('Give me a magic number')

# set fd = 0 to indicate input from command line
rmt.send(str(0xDEADBEAF))

rmt.recvuntil('OK, then give me a magic string')
rmt.send('YOUSHALLNOTPASS\n')

rmt.recvuntil('Maybe you learn something :)')

# Flag
print(rmt.recvrepeat().decode())

# CSC2022{CHI7tY_cH1T7y_b@n9_8an9}
