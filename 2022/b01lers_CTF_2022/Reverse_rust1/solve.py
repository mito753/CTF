from z3 import *
x = IntVector("x", 22)
s = Solver()
for i in range(22):
  s.add(And(x[i] >= 0x30, x[i] < 0x7e))

s.add(x[0] + x[1] + x[2] + x[3] == 0x115)
s.add(x[4] * x[5] + x[6] + x[7] == 0x1337)
s.add(x[8] + x[9] > 99)
s.add(x[10] / x[11] == 2)
s.add(x[12] * x[13] > 1000)
s.add((x[14] + x[15]) * 5 > 200)
s.add(x[0x10] - x[0x11] == 0x2a)
s.add(x[0x12] - x[0x13] == 0x2)
s.add(x[0x14] * x[0x15] > 999)

r = s.check()
if r == sat:
  m = s.model()
  print(m)
  flag =""
  for i in range(22):
    flag += chr(m[x[i]].as_long())
  print(flag)
