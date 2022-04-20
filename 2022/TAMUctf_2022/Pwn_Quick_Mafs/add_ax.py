import os

e0 = open("elf04a", "rb")
os.system("ropper -f elf04a --nocolor | grep 'add ax' rop04.txt | grep 'lea rbx' > rop04b.txt")
b0 = open("rop04b.txt")

e1 = e0.read()
b1 = b0.read()
b2 = b1.split("\n")

print(b2)

target = 0x5318
mv = 0
mp = 0

for i in range(len(b2)-1):
  p0 = b2[i].find("[0x")
  a0 = int(b2[i][p0+3:p0+9], 16)
  a1 = a0 - 0x401000
  a2 = int.from_bytes(e1[a1:a1+2], byteorder='little')
  a3 = int(b2[i][:18], 16)
  print("i =", i, "addr =", hex(a0), hex(a1), hex(a2))
  if a2 < target - 0x30:
    if a2 > mv:
      mv = a2
      mp = i
      ma = a3
      
print("mp =", mp, ", mv = ", hex(mv), ", ma =", hex(ma), ", diff =", hex(target - mv))         





