def SQF(p1, p2):
  #print hex(p1), hex(p2)
  l1 = p1 - 0x30
  l2 = p2 - 0x30
  edx = l2
  eax = edx
  eax += eax
  eax += edx
  eax = eax << 2
  ecx = eax - 4
  edx = l1
  eax = edx
  eax += eax
  eax += edx
  eax = eax << 4
  eax += ecx
  eax -= l2
  l3 = eax
  ecx = l3
  if ecx < 0:
    ecx = 0x100000000 + ecx
  edx = edx
  eax = 0xcccccccd
  rax = eax * edx
  rax = rax >> 0x20
  edx = eax
  edx = edx >> 3
  eax = edx
  eax = eax << 2
  eax = eax + edx
  eax = eax + eax
  ecx = (ecx - eax) % 10
  #print hex(rax), hex(eax), hex(ecx), hex(edx)
  eax = ecx
  l3 = eax
  return eax

#p0 = "0000000000000000000000"
p0 = "7"
c0 = "7759406485255323229225"
c = ""

n = "0123456789"


for k in range(len(c0)-1): 
 for n0 in n:
  p1 = p0 + n0
  c = p0[0]
  v4 = ord(p0[0])
  for i in range(len(p1)-1):
    v1 = ord(p1[i+1])
    v2 = SQF(v4, v4 + i)
    v3 = v1 - 0x30 + v2
    v4 = v3 + (v3/10) * (-10) + ord('0')
    c += chr(v4)
  print c
  if c0[0: len(p1)] == c:
    print "******** HIT ! ********"
    p0 += n0
    print p0
    break
