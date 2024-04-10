These are foundations for things like `ROP` that will be important later, but not as likely to see in the wild

# Stack Overview
At any point in time, when executing a function, we have the stack space
`rbp` is always at the top
`rsp` is always at the bottom
Create stack space to store data for operations
* it's basically scratch paper
### What happens when we call a function
1) Store the next instruction `rip` to the stack, which pushes `rsp` down
2) Then it pushes `rbp` to the stack at the  beginning of the function
	* Saves `rbp` for the previous function's stack frame
3) Then moves the value of `rsp` into `rbp`
	* This pushes `rbp` down for this new function's stack frame
4) Then decrease `rsp` the size of the 
	`sub rsp 0xz`
	`RSP`
What about when we exit a function
1) push `rbp`
2) mov `rbp`, `rsp`
3) `leave`
	Pops `rsp`
	pops `rip` so it points to prev instruction
1) `ret`
2) 
Cleans things up so the stack frames are exactly the same


How does this work when we do a stack overflow?
Sometimes we fuck up the stack offsets


# Lockbox Solution
Used pwntools `checksec` for quick analysis
	No pie: any addresses is loaded in at the exact address
	No Stack Canary

Other things to try
`vmmap` will find things in the virtual memory

Couldn't have chosen a stack address to write to for lockbox because the stack addresses might be different remotely (which is why )


Can see what addresses are writable with vmmap too


# Shellcode 
It's the code that gets you a shell

![[Pasted image 20240228201502.png]]

All this does is read in the buffer and execute it
	The buffer lives in the stack

![[Pasted image 20240228201727.png]]
Parts of the binary are RWX  and the stack can be executed
Nothing that can be written should be executed
(it was compiled with the flag `execstack`)

How do we pop a shell from bytes in the stack?
It's going to interpret everything at that address as opcodes (assembly)
	Essentially the `foo();` is a `CALL` in assembly, 

### `system(59)` would be a good command to put on the stack
Aka `execvte`
	Takes in: `(char *filename, args, env)`
	From `man`: `int execve(const char *pathname, char *const _Nullable argv[], char *const _Nullable envp[])`
	Can use it like `execvte("/bin/sh", 0, 0)`
		*then probably need to encode in bytes...and figure out how to get into the stack*

# Pwn 2: Canary Attacking and Linking
Slides/video lecture
## Canary Mitigation/Evasion
### Stack Canaries
* Stack canaries are a mitigation that prevent the stack from being overwritten
* A random value is gnerated at program startup, then placed on the stack before the return address.
* If the value doesn't match what is expeected, then `__stack_chk_fail` is called
	* Without it, the overwritten stack pointer would have been called
![[Pasted image 20240305203908.png]]
* Canaries provide a reasonable mitigation to stack-smashing attacks
	* Guessing a 64 but value is hard, especially if the program exits when it's wrong
* However, it can be evaded
	* Canary Leaking
	* Canary Brute Forcing
### Stack Canary Leaking
Situations where one might be able to leak a canary:
* User-controlled format string
* User-controlled length of an output
	Ex: `Hey, can you send me 100 bytes?` type program
### Stack Canary Brute Forcing
* The canary is determined when the program starts for the first time
* If the program forks, it keeps the same **stack** cookie in the child process
	* If our input can overwrite the canary sent to a child process, we can iterate through a list and brute force it one byte at a time
* Challenge programs have all used `stdin`/`stdout` to communicate with the user
	* Most use a network socket
	* Often done over accept and fork
##### Accept and Fork
The server waits for a connection to come in, then forks off a child process to hadnle the conenction
* The forked off child process gets a copy of the parent process memory
	* This includes the stack canary
* We can use whether or not a child process crashes to tell whether we have correctly guessed a byt of the canary token

Stack canary brute forcing works a lot like Blind SQLi
* Also only works on functions that don't append a `NULL` byte to our input
	* We need exact control of that last byte
	* Functions like `read` and `recv` do this
* General Process
	* Overflow byte-by-byte
		* If there was a crash, that byte was wrong
		* If there isn't that byte was correct
		* Move to the next byte until you've brute forced them all!
![[Pasted image 20240305204711.png]]
#### Example:
| Canary Value | Result |
| ---- | ---- |
| 00 | No Crash |
| 00 00 | Crash |
| 00 01 | Crash |
| 00 02 | No Crash |
| 00 02 00 | Crash |
...etc

Eventually, when you have all 8 bytes without a crash, you can add the canary to your payload,.overwrite `rbp`/`rip` and pass the canary check
* Standard stack-based overflow techniques now apply, as long as the canary stays in place
## Linking
### Static vs Dynamic Linking
* Programs require a lot of functionality you don't want to actually write yourself
	Ex: `fopen`, `gets`, `print`, `puts`, ...etc
* There are a lot of common 3rd party libaries
	Ex: `Boost`, `openssl`, ...etc
	* Must dynamically or statically link to use these libraries
STATIC Linking
* Everything is brought into the binary
* The binary doesn't need anything else from the system
* The binary is usually quite large
DYNAMIC Linking:
* Use binaries that are (likely) already present on the system
* Binary is quite small and simple, therefore much faster to build
### Dynamic Linking
Dynamic linking requires "exports" from the necessary libraries
* A program that uses these exports will store them in the `Global Offset Table` (`GOT`)
* When a program uses one of these library exports:
	* The stub invokes the linker
	* The linker loads the necessary library into the process memory space
	* The linker resolves the function address of the desired function
	* The function address is placed in the `GOT`
Think of the GOT as *"a bunch of trampolines that are resolved as needed*
Can see with:
	`GHIDRA: Window --> Memory Map`
#### Abusing Dynamic Linking
The GOT has `rw` privileges
* Given a *"Write What Where Primitive"* (a good opportunity), you can overwrite the GOT entries
* Then your specified address will be executed as soon as the GOT entry is called
* I did this in [[Git it GOT it, Good]]
#### Dynamic Linking Mitigations
RELRO
* RELocations Read Only
* Two Variants:
	* Partial RELRO
		* Does nothing against this exploit lol
	* Full RELRO
		* Pre-resolves all symbols
		* Marks the `GOT` as read-only
		* Boooooooo

# Challenges
[[Backdoor]]
[[Git it GOT it, Good]]
[[School]]
# More Reading
[[The Stack]]
[[Stack Buffer Overflow]]
[[Return Oriented Programming]]]
[[Binary Exploitation - Attacking Dynamic Linking]]
