from pwn import *

context(os='linux', arch='amd64')
context.log_level = 'debug'

BINARY = './gambler-baby1'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "ctf.b01lers.com"
  PORT = 9202
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  #libc = elf.libc

f = open("letters")

for i in range(901):
  letter = f.readline()[:-1]
  s.sendlineafter("letters: ", letter)

s.interactive()
