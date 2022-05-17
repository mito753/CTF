f1 = open("data_click_before.dat", "rb")
f2 = open("data_click_after.dat", "rb")

f1.read(17)
f2.read(17)

for y in range(2000):
  for x in range(3000):
    b1 = f1.read(4)
    b2 = f2.read(4)
    if b1[0] != b2[0]:
      print(y, x, "(", hex(b1[0]), hex(b2[0]), ") (", hex(b1[1]), hex(b2[1]), ") (", hex(b1[2]), hex(b2[2]), ") (", hex(b1[3]), hex(b2[3]), ")")
