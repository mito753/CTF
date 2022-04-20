import ctypes

ctypes.cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
libc = ctypes.CDLL("/lib/x86_64-linux-gnu/libc.so.6")

for i0 in range(256):
  for i1 in range(256):
    for i2 in range(256):
      seed = i0*256*256+i1*256+i2
      libc.srand(seed)
      if libc.rand() == 306291429:
        print(seed, hex(seed))
        print(libc.rand())
        print(libc.rand()) 


