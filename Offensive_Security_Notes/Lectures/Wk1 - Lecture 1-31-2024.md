

Stuff
Drop Deadline coming up in FEB
* The next week's topic is gonna be relevant for the next 8 weeks

Hot Challenges (Due next week)
* [[Numerix]]
* [[Strops]]
* [[Postage]]
* Recurse

[[Binary Ninja]]/[[Ghidra]]
Pointers
Memory mapping
Static/ vs dynamic
[[GDB]]
GDB Base Address
Ascii vs Byte Value - Inputs
[[PwnTools]] debug

Sat Solver - z3_test.py


How to "get good" at RE
* Write program
* Compile
* Use decompiler
* WILL NOT HAVE SOURCE CODE FOR ANY OF THE RE CHALLENGES IN THIS CLASS

# Simple C Program:
```
#include "stdlib.h"
#include "string.h"
#include "stdio.h"

int main() {
	char buf[0x4];
	fgets(buf, sizeof(buf), stdin);
	long input = atoi(buf);
	printf("You gave me hex 0x%lx\n", inpt)
	return 0;
}
```

## What does the program do?
	Line 6 - Creates a 4 byte character "array"
	Line 7 - Takes user input and stores in that array (string of chars)
	8 - converts buffer to int
		`atoi` converts a string to an int
	9 - Prints out value as hex

## Where is the character buffer? ON THE STACK
	(in the function stack frame)

## Two tools to look at program
Binary ninja cloud
	cloud.binary.ninja
	Cloud version of Binary ninja
		Not free
	Good interface
Will also be using Ghidra



Most people prefer Intel syntax - follows more programming conventions


When trying to understand how program works, look at Opcodes
* those are the CPU instructions
* Can't change run to run (but may change due to control flow)
* "Assembly tells no lies"

Most tools also show a deompiler so you don't have to read assembly
* decompiled code *may or may not be true*
* Works best if you use c-like language for decompiled code

Ghidra you get more out of unless you're willing to pay more for Binary ninja

Stack buffer overflows are bad - two key pieces of data live on the stack
- Controlling either of those is how you really start messing with the program flow

6 Registers of order
* RDI

First 6 args are pushed in registers
* tehr est are in the stack
in x86, all arguments are passed on the stack



Fast call
* decompiler should figure out that calling convention
* is only in x86
* Won't see it a lot (or maybe at all)

XOR can be used to clear a register easily

Char != ASCII char, it's just a single byte unit
* it can be any byte value


# Pointers
(How they work in memory)


Example code:
![[Pasted image 20240131200650.png]]

Program "calls out different data types"
Makes Heap buffer and puts strings in it?

![[Pasted image 20240131200943.png]]

