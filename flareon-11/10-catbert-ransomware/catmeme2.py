encrypted = bytearray.fromhex("59 a0 4d 6a 23 de c0 24 e2 64 b1 59 07 72 5c 7f")

x = 0x1337


for i in range(4):
    for j in range(4):
        x = (((0x343fd * x) + 0x269ec3) % 0x80000000)
        b = (x >> (j * 8)) & 0xFF
        encrypted[(i * 4) + j] ^= b

print(encrypted)
