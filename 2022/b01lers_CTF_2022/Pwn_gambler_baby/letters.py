from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './gambler-baby1a'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "51.124.222.205"
  PORT = 13370
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  #libc = elf.libc

f = open("letters", "w")

for i in range(1000):
  s.sendlineafter("letters: ", "aaaa")
  s.recvuntil("Correct word: ")
  letter = s.recvuntil("\n")[:-1]
  f.write(letter)
  f.write("\n")

f.close
