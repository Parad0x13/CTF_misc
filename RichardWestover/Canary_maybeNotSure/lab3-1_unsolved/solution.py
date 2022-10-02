#!/usr/bin/python3
# 2022.10.01.2345.EST
from pwn import *

overflow = b""

#with remote("csc748.hostbin.org", 7031) as p:
with gdb.debug("./lab3-1.bin") as p:
    payload = b""
    payload += b"\n"

    p.send(payload)
    p.interactive()
