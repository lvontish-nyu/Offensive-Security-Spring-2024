from pwn import *
import re

#############################################################
#	stropsploit.py											#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Reverse Engineering 1: Strops Challenge Solver Script	#
#	02/07/2024												#
#############################################################

# A function to send a line and receive the response
#	Input: Message String, Connection
#	Output: Recieved message
def sendRecv(msg, dst):
	dst.sendline()
	#ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	r = dst.recv()
	return r

# A function to convert encoded input to a string and remove text format characters
#	Input: Encoded string
#	Output: Unencoded string
def cleanLine(ln):
	ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	l = ansi_escape.sub('', str(ln, encoding='utf-8'))
	return l

# A function to find the memory location of the CMP function that strops uses to compare the guess to the flag
#	Input: Connection
#	Output: Memory location in hex string
def findCMP(p):
	m = open("mainDisas.txt", "a")
	m.write("Main Method Disasembly:" + "\n")

	p.sendline("disas main")
	#ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

	n = 0

	while True:
		#l = p.recvline()
		#ln = ansi_escape.sub('', str(l, encoding='utf-8'))
		#z = ansi_escape.sub('', ln)
		ln = cleanLine(p.recvline())
		m.write(ln)
		if re.search("End of assembler dump.", ln):
			break
		elif re.search("cmp.*eax.*edx", ln):
			cline = ln
		elif(n == 20):
			# Must page through disassembly for some reason
			p.sendline("c")
		n+=1

	m.write("Found the memory location: [")
	c = re.split("\s+", cline)
	m.write(c[1])
	m.write("]")
	return c[1]

# A function to iterate through interactions with the strops binary
# 	Sends a guess to the program
#	Waits until strops reaches the set breakpoint
#		Sends debug command to set the value of EAX to that of EDX
#		Saves current state of EAX register
#	Input: Connection
#	Output: None
def getFlag(p):
	#infoEAX = [0] * 40
	#r = sendRecv("c")
	#print(r)
	log = open("Strop.txt", "a")
	p.sendline("c")

	# Wait for the enter flag prompt and send a guess
	while True:
		r = cleanLine(p.recvline())
		# print(r)
		if re.search("Enter your flag:", r):
			guess = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			p.sendline(guess.encode())
			#print(p.recv())
			print("Sending flag!")
			break

	# Loops through as strops reaches the breakpoint at CMP
	for i in range(40):
		# Save debugger response in log
		r = cleanLine(p.recv())
		log.write(r)
		# Save EDX value in EAX value then write EAX information to log
		p.sendline("set $eax = $edx")
		p.sendline("info registers eax")
		r = cleanLine(p.recv())
		log.write(r)

		# Break once we get "correct" response
		if re.search("Correct", r):
			print("Correct!!")
			break
		# Send debugger continue command
		p.sendline("c")
	log.close()
	return 0

# A function to retreive the flag data from the log file
#	Input: None
#	Output: Decoded Flag
def parseFlag():
	log = open("Strop.txt", "r")
	f = ""
	i = 0
	for line in log:
		if re.search("eax.*0x.*", line):
			l = re.split("\s+", line)
			n = re.split("x", l[3])
			f += n[1]
	return bytes.fromhex(f).decode('ascii')


def main():
	# Start gdb session
	p =  process("/bin/bash")
	p.sendline("gdb ./strops.bin -q")
	p.recv()
	p.sendline("break _start")
	p.recv() # GDB response with one line indicating that the breakpoint is set
	p.sendline("r")
	print(p.recv())

	# Find location of cmp
	loc =findCMP(p)
	# Set breakpoint at cmp location and delete breakpoint at _start
	cmd = "break *" + loc
	#print(cmd)
	p.sendline(cmd)
	print(p.recv())
	p.sendline("clear _start")
	print(p.recv)

	# Interact with strops and save debugger output
	getFlag(p)
	# Parse the flag from the log file
	print(parseFlag())
	
		

if __name__=="__main__": 
	main()