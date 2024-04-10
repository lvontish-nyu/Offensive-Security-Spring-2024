from pwn import *
import re

#############################################################
#	HRC_Local_Debug.py										#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Reverse Engineering 3: Hand Rolled Cryptex				#
#	02/21/2024												#
#############################################################

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

# A function to send a string to question 3 and get register information
#	Input: Connection, potential answer string
#	Output: String containing register data
def FuzzQ3(p, ans):
	p.recvuntil(b'>')
	p.sendline(ans.encode())
	p.recvuntil("Breakpoint")
	p.recvline()
	p.sendline("info registers eax")
	return(cleanLine(p.recvline()))

# A function to solve question 3
#	Input: Connection
#	Output: N/A 
def runFuzz(p):
	fuzz = ['2','32','02','032','002','0032','%2','%32','%02','%032','x2','x32','x02','#x32','&#x32','\2','\32','\02','\\x2','\x32','\x02','0x2','0x32','0x02','\0x2','\0x32','\0x02']
	log = open("HRC_Q3_dbg.txt", "a")
	log.write("Hand Rolled Cryptex Q3 Debug Log:" + "\n")
	p.sendline('break *0x55555555586d')
	flag = -1
	i = 0
	for guess in fuzz:
		p.sendline('r')
		question1(p)
		question2(p)
		q3 = FuzzQ3(p, guess)
		p.sendline('c')
		reg = re.split("\s+", q3)
		if(reg[3] == '2'):
			print("Correct Answer Found")
			log.write("Valid Answer!\n")
			log.write("Guess at index " + str(i) + "= "+ guess + "\n" + q3)
			p.recvuntil(b'flag')
			flag = cleanLine(p.recvline())
		else:
			p.recvuntil("(gdb)")
		i += 1
	return flag

# A function to send a the answer to question 3
#	Input: Connection
#	Output: Response  
def question3(p):
	p.recvuntil(b'>')
	ans = "\x02"
	p.sendline(ans.encode())
	p.recvuntil(b'flag')
	return(cleanLine(p.recvline()))

# A function to solve question 3
#	Input: Connection
#	Output: N/A 
def runSolve(p):
	p.sendline('r')
	#print(p.recvline())
	print(question1(p))
	print(question2(p))
	print(question3(p))
	# Close remote session
	p.close()
	return 0

def main():
	
	# Start gdb session
	p =  process('/bin/bash')
	p.sendline('gdb ./hand_rolled_cryptex -q')

	# Uncomment for if solving or debugging
	#runSolve(p)
	print(runFuzz(p))


if __name__=="__main__": 
	main()