from PIL import Image
im = Image.new('RGB', (3000,2000))
f = open("data.dat", "rb")
f.read(17)

for y in range(2000):
  for x in range(3000):
    b = f.read(4)
    if (ord(b[0])>>1)&1 == 0x1:
      r1 = g1 = b1 = 0
    else:
      r1 = g1 = b1 = 255
    im.putpixel((x,y), (r1,g1,b1))

im.save('flag.png')

'''
mito@ubuntu:~/CTF/TJCTF_2022/Reverse_block-game$ python make_flag_image.py 
'''
