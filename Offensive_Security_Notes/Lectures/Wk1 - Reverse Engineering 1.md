Goes with [[Wk1 - Lecture 1-31-2024]]
# Introduction
## Focus on x86_64
### 64-bit x86 Binaries == x86_64
* Run on linux
* Often not as much obfuscation
It is also known as amd64, or i64, or x86 64-bit
* Unintended successor to Intel x86 Architecture
	* Intel had Itanium, which never took off
* AMD extended Intel's 32 bit architecture to 64 bits

x86_64 is a CISC variable-length instruction set, multi-sized register access instruction set
* CISC = Complex Instruction Set Computing
	* Single instruction can do many things
		* Memory accesses, register reads, ...etc
	* Variable length instruction set
		* Different instructions can be different sizes
			  x86_64 instructions can be anything from 1 to 16 bytes long
* Multi-size register access means you can access certain parts of the register, which are different sizes

## Registers
### What is a register?
Basically local variable on the CPU
* Registers are 64 bits
* Instantly accessible by CPU
x86_64 has many registers:
	For example: `rax` ` rbx` ` rcx` ` rdx` ` rdi` ` rsi` ` rsp` ` rip` ` r8-r15`
Special Registers
* `RIP` - The instruction pointer
* `RSP` - The stactk pointer
* `RBP` - The base pointer
### Sized Access
![[Pasted image 20240202115339.png]]

## Instructions
### What should the CPU execute?
* This is determined by the `RIP` register
	* `IP` == Instruction poionter
### Process
1) Fetch the instruction at the address in `RIP`
2) Decode the instruction
3) Run the instruction
#### Example:
![[Pasted image 20240202115535.png]]
Format is:
OPERATION DEST_REGISTER SRC_REGISTER
### Step-Through Example
Will be moving through the following instructions:
`0x0804000: mov eax, 0xdeadbeef`
`0x0804005: mov ebx, 0x1234`
`0x080400a: add, rax, rbx`
`0x080400d: inc rbx`
`0x0804010: sub rax, rbx`
`0x0804013: mov rcx, rax`

Registers at Start:
```
rip = 0x00804000
rax = 0x00000000
rbx = 0x00000000
rcx = 0x00000000
rdx = 0x00000000
```
Note that the value of RIP changes as it points to the memory location of the next instruction to execute
#### 1) `0x0804000: mov eax, 0xdeadbeef`
Placed value of `0xdeadbeef` into `eax` register
Registers after Instruction:
```
rip = 0x00804005
rax = 0xDEADBEEF
rbx = 0x00000000
rcx = 0x00000000
rdx = 0x00000000
```
#### 2) `0x0804005: mov rbx, 0x1234`
Placed value of `0x1234` into `rbx` register
	`Note: Initial ppt says "ebx" but the value of ebx is never shown so I assume that's a typo`
Registers after Instruction:
```
rip = 0x0080400A
rax = 0xDEADBEEF
rbx = 0x00001234
rcx = 0x00000000
rdx = 0x00000000
```
#### 3) `0x080400a: add, rax, rbx`
Added the value of the `rbx` register to the value stored in `rax`
```
v(rbx) = v(rbx) + v(rax)
v(rbx) = 0xDEADBEEF + 0x1234
v(rbx) = 0xDEADD123
```
Registers after Instruction:
```
rip = 0x0080400D
rax = 0xDEADD123
rbx = 0x00001234
rcx = 0x00000000
rdx = 0x00000000
```
#### 4) `0x080400d: inc rbx`
Increase the value stored in the `rbx` register
```
v(rbx) = v(rbx) + 1
v(rbx) = 0x1234 + 1
v(rbx) = 0x1235
```
Registers after Instruction:
```
rip = 0x00804010
rax = 0xDEADD123
rbx = 0x00001235
rcx = 0x00000000
rdx = 0x00000000
```
#### 5) `0x0804010: sub rax, rbx`
Subtract the value of the `rbx` register from the value stored in `rax`
```
v(rax) = v(rax) - v(rbx)
v(rax) = 0xDEADD123 - 0x00001235
v(rax) = 0xDEADBEE
```
Registers after Instruction:
`Note: In the ppt they only showed the register output after both moves, so I'm making an assumption again`
```
rip = 0x00804013
rax = 0xDEADBEEE
rbx = 0x00001235
rcx = 0x00000000
rdx = 0x00000000
```
#### 6) `0x0804013: mov rcx, rax`
Place the value of the `rax` register into `rcx`
Registers after instruction:
```
rip = 0x00804016
rax = 0xDEADBEEE
rbx = 0x00001235
rcx = 0xDEADBEEE
rdx = 0x00000000
```

### Control Flow
#### How to express conditionals in x86?
Conditional jumps:
* `jnz [address]`
* `je [address]`
* `jge [address]`
* `jle [address]`
They jump if the condition is true
	if it is False, they just go to the next instruction instead

### EFLAGS
Easily forgotten but important register
* Flags stored here
* Many instructions set them
	  Ex:
		`add rax`
		`rbx` sets the `o` (overflow) flag if the sum is greater than a 64 bit register can hold and wraps around
		The `jo` instruction allows jumping based on the overflow flag
* Most important thing is `cmp` instruction
	* `cmp` `rax` `rbt`
	* `jle` error
	* Jumps if `v(rax) <= v(rbx)`

## Memory
Memory is just bytes
* hold instructions, numbers, strings ...etc (basically everything)
* Always represented in hex
	Hello == `48 65 6c 6c 6f 00`
Ex:

| Assembly | Hex |
| ---- | ---- |
| `add rax, rbx` | `48 01 d8` |
| `mov rax, 0xDEADBEEF` | `48 c7 c0 ef be ad de` |
| `mov rax, [0xDEADBEEF]` | `67 48 8b 05 ef be ad de` |
### Addresses
* Memory is basically a big array
	* The memory addresses are indices in the array
* Ex: (Last command in the table above)
	`mov rax, [0xDEADBEEF]` 
	* Square brackets mean "get the data from this address"
	* C/C++ have similar syntax
		`rax = *0xDEADBEEF`

	* Basically, in this case `0xDEADBEEF` is the memory address, NOT the value
## The Stack
Stack is used as "scratch space" for applications
	It's where they operate
	Arguments, variables, ...etc are all stored in the stack
### Visual:
![[Pasted image 20240202123329.png]]
### The Stack
* From data structires
* LIFO (Last In First Out)
	* `Push` things on top to add
	* `Pop` things off top to remove
	![[Pasted image 20240202123538.png]]
* Built in to most architectures
	* Not fancy, is just memory, `rsp`, and `rbp`

`rsp` register is the "stack pointer"
* Points to the memory location that is currently the top of the stack
	`push rax` will decrease `v(rsp)`
	`pop rax` will increase `v(rsp)`
		This seems backwards BUT, as shown in the stack diagram, the stack grows downwards into the unallocated memory space shared by the `stack` and the `heap`
		![[Pasted image 20240202123822.png]]

### Pushing and popping
`[push/pop] [address]`
`push`
	`push [src_address]`
	Decreases `rsp` value to store new data
	Then stores the contents of the source address at the top of the stack (the new `rsp` value)
`pop`
	`pop [dst_address]`
	Stores the data at the top of the stack in the destination address
	Then increases the value of `rsp` so that it points to the new top of the stack
#### Examples
`push rax`
* Decreases `rsp` value by 8
	* `rsp` value is the address of the start of the stack
* Moves contents of `rax` into memory at the new location value stored in `rsp`
* *Effectively*, these commands happen:
	`sub rsp, 8`
	`mov [rsp], rax`
`pop rax` is then *effectively*
	`mov rax, [rsp]`
	`add rsp, 8`

## Functions
Functions are *nothing more* than code that returns something
Functions are *very high level* the CPU doesn't *"really understand"* the concept
	Two instructions: `call` and `ret`
	Not a clear delineation of where it starts and ends in the instructions
Compiler generates functions based on the code
	Sets up stack for it to execute function
		"Creating space on the stack" aka creating the "Stack Frame"
	These instructions allocate a certain amount of space on the stack to use
		`push rbp`
		`mov rbp, rsp`
		`sub rsp, 0x100`
Function instructions
* `call [address]`
	* The call instruction calls a function
	* Pushes the value of `rip` on stack
	* Jumps to that address
* `ret`
	* pops a value from the stack and stores in `rip` 
	* Jumps to that location
	* Cleanup the stackframe first!
In example:
![[Pasted image 20240202125056.png]]
Values are put in register, then a call happens
	Return address is placed onto stack by the call
Space is allocated for things like variables and such inside of the stackframe (I think)
### Calling Conventions
How do I pass arguments to my functions?
* Done entirely by convention
	* There are no real rules
* Everything we'll touch in this class uses **SystemV AMD64 ABI** so these calling conventions **do** hold:
	* The first 6 arguments passed to a function are passed, from left to right, in these registers:
		`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`
	* Further arguments are pushed to the stack
	* The return value of the function is stored in `rax` when the function returns
	`Note from the professor: "It takes a long time to remember this so don't feel bad if you need a reference`
### Experimentation
* The [Compiler Explorer](https://godbolt.org) 
	* Generates assembly based on input C (or C++) code
		* Highlights corresponding lines
	* May be good for understanding how high-level constructs map into assembly


# Reverse Engineering Resources
Hex Editors
- [010 Editor](https://www.sweetscape.com/010editor/)
- [hexworkshop](http://www.hexworkshop.com/overview.html)
- [Hexfiend](http://ridiculousfish.com/hexfiend/)  
Document Analysis
- [Ole tools](http://www.decalage.info/python/oletools)
- [Origami pdf](https://github.com/cogent/origami-pdf)
Scripting
- [IDA IDC docs](https://www.hex-rays.com/products/ida/support/idadoc/162.shtml)
- [Abyss IDA plugin](https://github.com/patois/abyss)
- [Alleycat IDA plugin](https://github.com/tacnetsol/ida/tree/master/plugins/alleycat)
- [BinWalk](https://github.com/ReFirmLabs/binwalk)
- [Binary Ninja Plugins](https://github.com/Vector35/community-plugins)
- [Ghidra scripts](https://github.com/AllsafeCyberSecurity/ghidra_scripts)
- [Ghidra tips and tricks](https://www.youtube.com/playlist?list=PLXqdTlog3E_8Ucym6klVOY9RmjdIy3cbm)
- [Daenerys](https://github.com/daenerys-sre/source)
Articles
- [Disassembly using IDA Pro](https://medium.com/@jain.sm/disassembly-of-binary-with-ida-pro-7267d8425823)
- [Next generation debuggers](https://www.blackhat.com/presentations/bh-europe-07/ERSI/Whitepaper/bh-eu-07-ersi-WP-apr19.pdf)
- [Reverse Engineering C++](https://corecppil.github.io/CoreCpp2019/Presentations/Gal_Behind_Enemy_Lines_Reverse_Engineering_Cpp_in_Modern_Ages.pdf)
- [Java Vulnerabilities](https://www3.thalesgroup.com/download/OvercomingJavaVulnerabilities_WP_(A4)_web.pdf)
- [BlackHat Ghidra](https://www.youtube.com/watch?v=kx2xp7IQNSc)
- [Ghidra color executed instructions](https://github.com/alephsecurity/general-research-tools/tree/master/ghidra_scripts/ColorInstructions)

# Setting up the Hacking Environment for RE
Two main types of tools for RE
* Disassemblers
	* Possibly with a decompiler
* Debuggers
## Disassemblers
Take the raw machine code (binaries) and "disassembles" the assembly  instructions the CPU would run
* Using one is considered static analysis
Most common disassemblers
* IDA
* Binary Ninja
* Ghidra
	These are all cross platform comprehensive RE tooklits
## Debuggers
Let you look at a program while it's running
### Linux
* gdb
	* Default linux debugger
### Windows
* WinDbg is free
* New "Preview" version has cool features
## Other tools
Angr and Z3 will be needed for week 5
	Both require Python

# Ghidra
Will save info in [[Ghidra]]
## Keybinds/HotKeys
`L`: Rename
`Ctrl+L`: Retype
`G`: Goto
`;`(semicolon): Comment
### Recommended Settings
`Edit` -> `Tool Options` -> `Listing Fields` -> `Cursor Text Highlight` -> `Mouse Button to Activate = LEFT`
## Ghidra Video 1
Best open-source toolkit
Breaks everything into "Projects"
* Project is a collection of binaries and libraries grouped together
Create new project
	`File -> New Project`
	Import things by hitting `I`
* it's an ELF (which is how x86 bins are stored on Linux)
Double click imported file to open "Codebrowser"
* This is the "meat of the reverse engineering toolkit
Default Analyze options are okay
This will give us the assessmbly
### Example
Go into **Start**
* Start is entry point of the binary
	`_start`
	The `_start` function assembly code highlighted in blue:
	![[Pasted image 20240202133532.png]]
	Decompiled `_start` function:
	![[Pasted image 20240202133503.png]]
	Not much to see in this Start Function, it calls the main function
	Can hop straight into main from there
Main
	The `main` function assembly:
	Decompiled `main` function:
	![[Pasted image 20240202133754.png]]
	Can see a pretty reasonable decompilation of the test program
	Identified the strings out of things like `readline`
Function behavior:
* `Line 12`: Readline outputs a prompt and stores the user input (probably their name)
	* Readline returns the char array that was entered
	* Char array stored in value of `local_10`, a `long` initialized at `Line 11`
* `Line 13`: Prints out a message and the user input data stored in `local_10`
	* Then that memory is freed
* Grab a random number at `Line 15` and store it in `local_lc`
	* Decompiler recognizes that all of these commands amount to a Mod100 math function
		![[Pasted image 20240202134555.png]]
* Then enter loop to guess the number
		Note, it didn't recognize that the data here was actually a string:
		![[Pasted image 20240202134807.png]]
		Can actually manually set the datatype when we find things like this:
		![[Pasted image 20240202135007.png]]
		Now it shows `%d` in the disassembly
*  Now we can name things
	`Right Click` -> `Rename Variable`
Here we've renamed the variable used for the user input as `guess` and have changed the comparison value in the "you've found a secret" if statement from `Hex` to `Decimal` so that it's easier to understand:
```
if (guess == 1337) {
	puts("You\'ve found a secret!");
}
```

We were able to assume that the number was in base 10 because `%d` is *usually* base 10

One of the best things about Ghidra is selecting a line in the compiled code will make it highlight the corresponding lines in the assembly.
It also has "undo"

Clean up functions using edit too:
![[Pasted image 20240202135600.png]]

   Next example will use a more complicated binary and go over how to define our own custom datatypes!

## Ghidra Video 2

To start reversing, you can either:
* double click `_start` in the assembly code and traverse to `main` from there
* Click `g` and then type in where you want to go

Changed main arguments to fit with C conventions
	from
		`undefined8 main(int param_1, long param_2)`
	to
		`undefined8 main(int argc, char **argv)` 
	He also set it to autohighlight variables he clicks on
		Can change which keybind that is with `tools`
		![[Pasted image 20240202172650.png]]
This is what the main method looks like now
	![[Pasted image 20240202172806.png]]
There's some weirdness to look through
	`Line 19`:
		`if((argc - 1U & 1) == 0 {`
		Basically this subtracts 1 from argc, which is the number of arguments sent to the program
		then the &1 takes the value of the leading bit
		It's looking to ensure there were an even number of arguments
	After that we get into the meat of the program
```
local_30 = 1;
while(local_30 < argc){
	pcVar1 = arggv[local_30];
	iVar3 = atoi(argv[(long)local_30 + 1]);
	ppcVar4 = [char **]malloc(0x18);
}
```
Rewrote as: (Can't get Ghidra to rewrite loop as for loop)
```
i = 1;
while(i < argc){
	ith_arg = arggv[i];
	i_plus_1_arg_as_int = atoi(argv[(long)i + 1]);
	allocation = [char **]malloc(0x18);
}
```
So for each argument
	Save the argument value in a variable
	Add 1 to the value and save as an int
	Allocate memory
We're still in the While loop here as we move to the next bit
```
if (allocation == (char **)0x0){
	perror('malloc');
	return 1;
}
```
If the allocation is 0, throw up a malloc error
We don't care as much about this

```
*allocation = ith_arg;
*(int *)(allocation + 1) = i_plus_1_arg_as_int;
ppcVar1 = allocation
```
Storing pointer in the first 8 bytes of the allocation
Then storing the second int in the next 8 bytes
	In this case, the assembly might actually be easier:
	`MOV dword ptr [allocation + 0x8], EBX`
Then store allocation into that local variable

```
if (local_28 != (char **)0x0) {
	*(char ***)(local_28 + 2) = allocation;
	ppcVar1 = local_30
}
```

Gonna create a type
	We know the allocation is always a certain size
	know we're storing a string in it
Go into type manager:
	![[Pasted image 20240202175229.png]]
	Hit `create new structure`
	
# Binary Ninja
Will save info in [[Binary Ninja]]
## Keybinds/Hotkeys
`N`: Rename
`Y`: Retype
`G`: Goto
`[SPACE]`: Linear/Graph tggle
`I`: Step through ILs
`[TAB]`: Toggle between linear disassembly and HLIL
`;`: Comment

# IDA
Will save info in [[IDA Cheat Sheet]]
## Keybinds/Hotkeys
`N`: Rename
`Y`: Retype
`G`: Goto
`X`: Show crossreferences
`[SPACE]`: Linear/Graph tggle
`;`: Comment
