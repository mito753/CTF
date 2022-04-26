from pwn import *

context(os='linux', arch='amd64')
context.log_level = 'debug'

BINARY = './tm'
elf  = ELF(BINARY)

s = process(BINARY)

#buf = "8"*21+"\x00"+"8v=t\x1a\x07\x1a{(5\"=t90;>5;&)"
#buf = "}3x1_B_>mpgx1|u~{p~cl\x00" 
#buf = "}3y1_B_>mpgy1{u}{p}cl\x00"
buf = "bctf{tur1ng_m4_C_1n3}\n\x00"
pause()
s.sendline(buf)

s.interactive()
