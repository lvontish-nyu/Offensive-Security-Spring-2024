from pwn import *
import re

#############################################################
#	HRC_Remote.py											#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Reverse Engineering 3: Hand Rolled Cryptex				#
#	02/21/2024												#
#############################################################

# Host and port for the remote challenge
HOST = 'offsec-chalbroker.osiris.cyber.nyu.edu'
PORT = 7332

# A function to convert encoded input to a string and remove text format characters
#	Input: Encoded string
#	Output: Unencoded string
def cleanLine(ln):
	ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	l = ansi_escape.sub('', str(ln, encoding='utf-8'))
	return l

# A function to send the answer to question 1
#	Input: Connection
#	Output: Response
def question1(p):
	p.recvuntil(b'>')
	ans = "./flag.txt"
	p.sendline(ans.encode())
	p.recvuntil(b'>')
	ans = "0"
	p.sendline(ans.encode())
	return(cleanLine(p.recvline()))

# A function to send a the answer to question 2
#	Input: Connection
#	Output: Response  
def question2(p):
	p.recvuntil(b'>')
	ans = "5"
	p.sendline(ans.encode())
	return(cleanLine(p.recvline()))

# A function to send a the answer to question 3
#	Input: Connection
#	Output: Response  
def question3(p):
	p.recvuntil(b'>')
	ans = "\x02"
	p.sendline(ans.encode())
	p.recvuntil(b'flag')
	return(cleanLine(p.recvline()))


def main():
	# Start remote session
	p = remote(HOST, PORT)
	print(p.recvline())
	print(question1(p))
	print(question2(p))
	print(question3(p))
	# Close remote session
	p.close()

if __name__=="__main__": 
	main()