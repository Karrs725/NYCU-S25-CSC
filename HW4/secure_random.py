from pwn import *
import time
from ctypes import CDLL


def long_secure_random(seed):
    libc.srand(seed)
    r = [libc.rand() % 32323 for _ in range(100)]
    for i in range(1, 100):
        r[i] = (
            r[i] * r[i - 1] ** 3 + r[i] * r[i - 1] ** 2 * 3 + r[i] * r[i - 1] * 2 + r[i]
        ) % 2**32
    return r[99]


libc = CDLL("libc.so.6")

while True:
    now = int(time.time())
    r = remote("140.113.207.245", 30171, level="error")
    t = r.recv().decode()
    payload = str(long_secure_random(now))
    r.sendline(payload.encode())
    result = r.recv().decode()
    if "succeed" in result:
        print(t)
        print(result)
        break
    r.close()
