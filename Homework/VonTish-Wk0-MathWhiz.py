from pwn import *
import re

# A function to start the remote connection
#	Input: URL string, Port int
#	Output: Connection
def start(U, P):
	io = remote(U, P)
	return io

# Gets the integer value of a text number
#	Input: Text string number
#	Output: Integer
def getValue(t):
	if t == "ONE":
		return 1
	elif t == "TWO":
		return 2
	elif t == "THREE":
		return 3
	elif t == "FOUR":
		return 4
	elif t == "FIVE":
		return 5
	elif t == "SIX":
		return 6
	elif t == "SEVEN":
		return 7
	elif t == "EIGHT":
		return 8
	elif t == "NINE":
		return 9
	elif t == "ZERO":
		return 0

# A function to translate a text string into a string of integers
#	Input: Text string number
#	Output: Itegers in string form
def textToIntStr(t):
	tStr = t.split("-")
	a = tStr
	n = 0
	for num in tStr:
		a[n] = str(getValue(num))
		n+=1

	ans = "".join(a)
	return ans


# A function to translate the response into a math problem and return the answer
#	Input: Byte string representing math problem and the log file
#	Output: Byte string representing the answer	
def doSomeMath(byteString, log):
	# Translate into readable problem
	byteString = byteString[:-4]
	problem = str(byteString, encoding='utf-8')
	log.write(problem)
	mathList = problem.split()
	i = 0
	while i < len(mathList):
		# Check to see if the number is made of text or not
		if re.search("^\D+$", mathList[i]):
			mathList[i] = textToIntStr(mathList[i])	
		i += 2
	mathString = " ".join(mathList)
	# Perform calculation and return answer
	str_ans = str(eval(mathString))
	byte_ans = str_ans.encode()
	log.write(" = " + str_ans+ "\n")
	return byte_ans

# A function to recieve questions and send answers
#	Input: Connection
#	Output: Number of problems completed
def QandA(conn, log):
	n = 0
	while n < 100:
		log.write("Question " + str(n) + "\n")
		b = conn.recvline()
		ans = doSomeMath(b, log)
		#conn.pack(ans)
		conn.sendline(ans)
		b = conn.recvline()
		log.write(str(b) + "\n")
		n+=1
	b = conn.recvall()
	print((str(b) + "\n"))
	log.write(str(b) + "\n")

def main():
	# Start remote connection
	URL = "offsec-chalbroker.osiris.cyber.nyu.edu"
	PORT = 1236
	conn = start(URL, PORT)

	log = open("MathWhiz.txt", "a")

	# Get the greeting, which is 183 char/183 bytes long
	g = conn.recvn(183)
	log.write("Greeting: " + str(g) + "\n")

	# Get the math problem next
	n = QandA(conn, log)

	log.close()



if __name__=="__main__": 
	main()