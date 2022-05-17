c = "fxqftiuuus\x7fw`aaaaaaaaa'ao"

f = ""

for i in range(len(c)):
  f += chr(ord(c[i])^0x12)

print f
