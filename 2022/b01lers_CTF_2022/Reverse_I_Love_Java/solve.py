c = [116,122,54,50,93,66,98,117,75,51,97,78,104,119,90,53,94,36,105,84,40,69]
#c = [116,122,51,48,51,52,98,48,48,54,97,54,49,119,52,52,48,33,105,51,61,32]
#      0   1   2  3  4  5   6  7   8   9  10  11  12  13  14 15 16 17  18  19  20  21
r0 = [19, 17, 15, 6, 9, 4, 18, 8, 16, 13, 21, 11,  7,  0, 12, 3, 5, 2, 20, 14, 10, 1]
r1 = [13, 21, 17, 15, 5, 16, 3, 12, 7, 4, 20, 11, 14, 9, 19, 2, 8, 1, 6, 0, 18, 10]
x = [0,1,2,1,2,5,4,1,1,7,3,7,0,10,5,5,1,16,10,2,12,17]


f0 = []

for i in range(22):
  f0.append(c[i]^x[i])

print f0

f1 = []
for i in range(22):
  f1.append(f0[r1[i]])

print f1

f2 = f1[::-1]

print f2

f3 = ""

for i in range(22):
  f3 += chr(f2[i])

print f3
