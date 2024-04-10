Writeup for [[Strops]]
## Challenge Breakdown
Running the Challenge
	Takes in number and exits
```bash
./strops.bin 
Enter your flag: TheTorturedPoetsDepartment
Nope.
```

Main Method Compares Entered number to secret flag byte by byte
```c
undefined8 main(void)

{
  ...omitted for brevity...
  printf("Enter your flag: ");
  read(1,flagGuess,0x40);
  counter = 0;
  do {
    if (0x22 < counter) {
      puts("Correct!");
LAB_001012c6:
      ...omitted for brevity...
      return 0;
    }
    if ((byte)~flag[(int)counter] != flagGuess[(int)counter]) {
      puts("Nope.");
      goto LAB_001012c6;
    }
    counter = counter + 1;
  } while( true );
}
```
Can see that compare in the assembly code too: (use last disas)
```
					 LAB_00101268                   XREF[1]:     001012b0(j)  
00101268 8b 45 ac        MOV        EAX,dword ptr [RBP + counter]
0010126b 48 98           CDQE
0010126d 48 8d 15        LEA        RDX,[flag]
		 ac 2d 00 00
00101274 0f b6 04 10     MOVZX      EAX,byte ptr [RAX + RDX*0x1]=>flag
00101278 0f be c0        MOVSX      EAX,AL
0010127b f7 d0           NOT        EAX
0010127d 89 c2           MOV        EDX,EAX
0010127f 8b 45 ac        MOV        EAX,dword ptr [RBP + counter]
00101282 48 98           CDQE
00101284 0f b6 44        MOVZX      EAX,byte ptr [RBP + RAX*0x1 + -0x50]
		 05 b0
00101289 0f be c0        MOVSX      EAX,AL
0010128c 39 c2           CMP        EDX,EAX
0010128e 74 16           JZ         LAB_001012a6

```

```bash
(gdb) disas main
Dump of assembler code for function main:
	...omitted for brevity...
   0x0000555555555284 <+116>:   movzbl -0x50(%rbp,%rax,1),%eax
   0x0000555555555289 <+121>:   movsbl %al,%eax
   0x000055555555528c <+124>:   cmp    %eax,%edx
   0x000055555555528e <+126>:   je     0x5555555552a6 <main+150>
	 ...omitted for brevity...
   0x00005555555552da <+202>:   leave
   0x00005555555552db <+203>:   ret
```

```bash
(gdb) disas main
Dump of assembler code for function main:
	...omitted for brevity...
	0x0000555555555268 <+88>:    mov    -0x54(%rbp),%eax
	0x000055555555526b <+91>:    cltq
	0x000055555555526d <+93>:    lea    0x2dac(%rip),%rdx        # 0x555555558020 <flag>
	0x0000555555555274 <+100>:   movzbl (%rax,%rdx,1),%eax
	0x0000555555555278 <+104>:   movsbl %al,%eax
	0x000055555555527b <+107>:   not    %eax
	0x000055555555527d <+109>:   mov    %eax,%edx
	0x000055555555527f <+111>:   mov    -0x54(%rbp),%eax
	0x0000555555555282 <+114>:   cltq
	0x0000555555555284 <+116>:   movzbl -0x50(%rbp,%rax,1),%eax
	0x0000555555555289 <+121>:   movsbl %al,%eax
	0x000055555555528c <+124>:   cmp    %eax,%edx
	0x000055555555528e <+126>:   je     0x5555555552a6 <main+150>
	 ...omitted for brevity...
   0x00005555555552da <+202>:   leave
   0x00005555555552db <+203>:   ret
```

## Attempt
### Debugger
Trying manually with GDB
```bash
gdb ./strops.bin

(No debugging symbols found in ./strops.bin)
(gdb) break _start
Breakpoint 1 at 0x10e0
(gdb) r
Starting program: /home/kali/Desktop/1-Week/strops.bin 
Breakpoint 1.2, 0x00007ffff7fe5360 in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) disas main
Dump of assembler code for function main:
...omitted for brevity...
   0x0000555555555289 <+121>:   movsbl %al,%eax
   0x000055555555528c <+124>:   cmp    %eax,%edx
   0x000055555555528e <+126>:   je     0x5555555552a6 <main+150>
...omitted for brevity...
End of assembler dump.
(gdb) break *0x000055555555528c
Breakpoint 2 at 0x55555555528c
(gdb) c
Continuing.
Enter your flag: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Setup breakpoint. At breakpoint, look at registry values and save edx in eax so they always match.
```
Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x66                102
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x66                102
(gdb) info registers eax
eax            0x66                102
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x6c                108
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x6c                108
(gdb) info registers eax
eax            0x6c                108
(gdb) c
Continuing.

...omitted for brevity...

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x7d                125
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x7d                125
(gdb) info registers eax
eax            0x7d                125
(gdb) c
Continuing.
Correct!
[Inferior 1 (process 2849417) exited normally]
(gdb) q
```

Translate hex values

|Break|Value|Break|Value|
|---|---|---|---|
|1|0x66|19|0x73|
|2|0x6c|20|0x5f|
|3|0x61|21|0x61|
|4|0x67|22|0x6e|
|5|0x7b|23|0x64|
|6|0x6c|24|0x5f|
|7|0x30|25|0x72|
|8|0x30|26|0x65|
|9|0x70|27|0x61|
|10|0x73|28|0x64|
|11|0x5f|29|0x73|
|12|0x61|30|0x5f|
|13|0x6e|31|0x6f|
|14|0x64|32|0x5f|
|15|0x5f|33|0x6d|
|16|0x78|34|0x79|
|17|0x30|35|0x7d|
|18|0x72|||

Ultimate string: ``flag{l00ps_and_x0rs_and_reads_o_my}``

### Code
Want to automate process
Edited code below, real code attached and in Appendix:
Main method initiates GDB session, finds the memroy location of the compare and sets a breakpoint there, before repeating debugger commands to get flag value.
```python
def main():
	# Start gdb session, set breakpoint at start, and then run strops
	p =  process("/bin/bash")
	p.sendline("gdb ./strops.bin -q")
	p.sendline("break _start")
	p.sendline("r")

	# Find location of cmp
	loc =findCMP(p)
	
	# Set breakpoint at cmp location and delete breakpoint at _start
	cmd = "break *" + loc
	p.sendline(cmd)
	p.sendline("clear _start")

	# Interact with strops and save debugger output
	getFlag(p)
	# Parse the flag from the log file
	print(parseFlag())
```

Main method initiates gdb session
Calls findCMP to find memory value of jump automatically

```python
def findCMP(p):
	m = open("mainDisas.txt", "a")
	m.write("Main Method Disasembly:" + "\n")
	p.sendline("disas main")

	n = 0
	while True:
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
```

Find cmp sends command to print disassembly of main method
Loops through disassembly line by line
	saves each line to document
	Looks for line matching comparison
	Returns memory location of CMP

After CMP, sets breakpoint at that address, deletes start breakpoint

```python
# Set breakpoint at cmp location and delete breakpoint at _start
cmd = "break *" + loc
p.sendline(cmd)
p.sendline("clear _start")

# Interact with strops and save debugger output
getFlag(p)
# Parse the flag from the log file
print(parseFlag())
```

Then calls getFlag to do the debugger interaction.
It
	Sends the flag guess,
	Lets program keep running
		At each breakpoint, it saves RDX value in RAX and writes debugger responses and RAX value to the log
		Breaks if the program responds "correct"

```python
def getFlag(p):
	log = open("Strop.txt", "a")
	p.sendline("c")

	# Wait for the enter flag prompt and send a guess
	while True:
		r = cleanLine(p.recvline())
		if re.search("Enter your flag:", r):
			guess = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			p.sendline(guess.encode())
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
			break
		# Send debugger continue command
		p.sendline("c")
	log.close()
	return 0
```

in the interaction loop, the program more or less spams "set eax" "info eax" over and over, writes down the debugger output, and then hits continue over and over until the loop is complete

Then parseflag comes along to parse the output
```python
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
```
It opens the textfile with debugger output and iterates through each line looking for anything formatted like the EAX info
	Then splits out the Hex value of in the EAX register and saves it to a string
After parsing the entire log, it returns the ascii text of the hex values

Successful run
```bash
python3 stropsploit.py
[+] Starting local process '/bin/bash': pid 2895274
...omitted for brevity...
@@flag{l00ps_and_x0rs_and_reads_o_my}
[*] Stopped process '/bin/bash' (pid 2895274)
```

Does this code always work?

...no...
Unsuccessful run
```
python3 stropsploit.py     
[+] Starting local process '/bin/bash': pid 2895204
/home/kali/Desktop/1-Week/stropsploit.py:107: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline("gdb ./strops.bin -q")
...omitted for brevity...
@@flag{l00
[*] Stopped process '/bin/bash' (pid 2895204)
```

Sometimes causes strops to crash, way more errors too.

Could input issues be the fix?
	Hard to figure out how to send data to program and not GDB



Full cleaned up code:
```python
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

	n = 0
	while True:
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
	log = open("Strop.txt", "a")
	p.sendline("c")

	# Wait for the enter flag prompt and send a guess
	while True:
		r = cleanLine(p.recvline())
		if re.search("Enter your flag:", r):
			guess = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			p.sendline(guess.encode())
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
```

