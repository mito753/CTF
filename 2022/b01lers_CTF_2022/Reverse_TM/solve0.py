c = "8v=t\x1a\x06\x1a{(\x1a\"=t90;>5;&)"
f = ""

for i in range(len(c)):
  if ord(c[i])%2 == 1:
      f += chr((ord(c[i]) ^ 0x45) - 10) 
  else:
      f += chr(ord(c[i]) ^ 0x45) 

print f[::-1]

