# Introduction to Return Oriented Programming
(Slides/Intro content)
## Exploitation Thus Far
Things haven't been *too challenging*

We've had some nice helpers:
* [[No eXecute (NX Bit)]] is disabled
	* Yay, free "shellcode trampoline"
* Functions like `give_shell` hanging around
* Most binaries imported `system` so that we could leverage it
The real world (and many CTF challenges) are much more difficult
* Rarely can we just jump to shellcode
* No nice little helper functions
	* Often no imports too
*What do we do now?!?*

# ROP ([[Return Oriented Programming]])
ROP is a code-reuse attack
* Don't need our own code to exploit
ROP allows us to modify the control flow to execute whatever we want
* uses nothing but `ret` primatives
###### At a high level:
* You have smashed the stack, but it's **non-executable**
* There is no address to jump to to pop a shell
* You can still return somewhere and use the stack to do other things
	Like `pop`!
	* And then `ret` again after that
	* ...and after that...
	* .........and after that...
###### Fun Facts about `x86`
* Functions aren't really "a thing" in x86
	* This means it's fine to just jump to the middle of a function
* Instructions are variable length
	* Has from 1 to 15 bytes per instruction
	* Can jump to the middle of an instruction
		* Jumping at different points yields different opcodes, giving us **way more** instructions than the programmer intended
* If we can smash the callstack, we can control return pointers
	* This will let us do things like return then return again
* x86 *kinda* understands instructions
	* What it really understands is the call stack
		Ex: Operations like `call` and `ret` instructions push and pop to the callstack

What does `ret` really do?
	`pop rip`
* If we control the stack, we control what it pops
	* Therefore, we can control multiple returns, each one making small changes
###### If we can find useful byte sequences that end with `ret`, we can use them as *gadgets*

Instructions are multiple bytes long AND they're variable length
	Ex: `ret` is 1 byte (opcode = `0xc3`)
* If you look for all instances of `0xc3`, you can find sequences of instructions that will lead up to a `ret`

You can jump to any byte, the processor will happily decode and run it
* Live your truth, jump to the *middle* of multi-byte instructions

## Example
### `mov rax, 0xc30f05 ; ret == 48 c7 c0 05 0f c3 00 c3`

If we offset a few bytes into this instruction sequence:
	`05 of c3` == `syscall; ret`
* This one is more powerful than what you'll see often
	* But there will be tons of these little *gadgets* in large enough programs

### `ROPGadget`
Tool to find these gadgets
* Install with `pip`
* Use with `grep`

# `POP X; POP Y; POP Z; RET`
Arguments are passed in registers
* Need to set registers in order to pass arguments to functions
All `pop <register>` instructions are 1-byte long
* Many programs have them leading up to a `ret`
###### So to set the first argument:
Find a `pop rdi; ret` gadget
Have the next return go to the function
**Ex:**
	`pop_rdi_ret, hello_world, puts`
## Example
Assume we have gadgets, and that the string `/bin/sh` is in memory at `0x600000`
The full call to `execve` will be:
	`execve("/bin/sh", NULL, NULL)`
In assembly, we want to do roughly the following:
```
move rdi, 0x600000
mov rsi, 0
mov rdx, 0
mov rax, 0x3b
syscalll
```
##### Our Gadgets:
A: `syscall; ret`
B: `pop rdi; ret`
C: `pop rsi; ret`
D: `pop rdx; ret`
E: `pop rax; ret`
###### At the beginning:
Stack:
```
RetAddr --> B
			0x600000
			C
			0x0
			D
			0x0
			D
			0x0
			E
			0x3b
			A
```
###### B:  `pop rdi; ret`
Pops the address on the top of the stack into `rdi`, then calls `ret` to jump to C
Stack:
```
			B
	rsp --> 0x600000
RetAddr --> C
			0x0
			D
			0x0
			D
			0x0
			E
			0x3b
			A
```
Registers:
```
RDI: 0x600000
```
###### C: `pop rsi; ret`
Pops the value on the top of the stack into `rsi`, then calls `ret` to jump to D
Stack:
```
			B
			0x600000
			C
	rsp --> 0x0
RetAddr --> D
			0x0
			D
			0x0
			E
			0x3b
			A
```
Registers:
```
RDI: 0x600000
RSI: 0x0
```
###### D: `pop rdx; ret`
Pops the value on the top of the stack into `rdx`, then calls `ret` to jump to E
Stack:
```
			B
			0x600000
			C
			0x0
			D
			0x0
			D
	rsp --> 0x0
RetAddr --> E
			0x3b
			A
```
Registers:
```
RDI: 0x600000
RSI: 0x0
RDX: 0x0
```
###### E: `pop rax; ret`
Moves the value `0x3b` into  `rax`, then calls `ret` to jump to A
Stack:
```
			B
			0x600000
			C
			0x0
			D
			0x0
			D
			0x0
			E
	rsp --> 0x3b
RetAddr --> A
```
Registers:
```
RDI: 0x600000
RSI: 0x0
RDX: 0x0
RAX: 0x3b
```
###### Then A runs `syscall`
This way `syscall` runs with all of the proper arguments in the value
###### Gadgets are essentially a way of crafting *shellcode* that doesn't exist in the binary from parts of the binary
## Harvesting Gadgets
CTF binaries are often small and have limited gadgets

Leverage shared libraries (ie, `libc`)
* shared libraries (`.so` files) are loaded at a different location each time
	* Not predictable
* The program knows where the functions are though
	* If you can leak addresses from within `libc`, you can calculate the differential address to another function
		Ex: If you can leak `puts`, you can figure out where `system` is
	* `LibC` akso has useful strings (like `"/bin/sh\0x00"`) if you look for them
		`ELF('libc-2.19.so').data.find('/bin/sh\x00')`
## `LibC` Calculation Example
###### In Pwntools:
```
In [1]: from pwn import *

In [2]: # Suppose we know the address of puts is 0x00007ffff7a7c690

In [3]: puts_addr = 0x00007ffff7a7c690

In [4]: libc = ELF('libc-2.19.so')
[*] '/home/moyix/offsec/week_9/rop/libc-2.19.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

In [5]: libc_base = puts_addr - libc.symbols['puts']

In [6]: print hex(libc_base)
0x7ffff7a0c930

In [7]: system_addr = libc_base + libc.symbols['system']

In [8]: print hex(system_addr)
0x7ffff7a52ec0
```
## Exploit Scenario - Putting It All Together
We have full control of the stack
* The program does `getse(buf)`, or something similarly vulnerable
So we start our ROP...
1) `puts(puts_got_address` to leak the address of `puts`
2) We subtract the offset of `puts` in `libc` from that address to get the base address of `libc`
3) Then add the offset of `system` in `libc` to get the real address of `system`
4) We jump there with an argument of `"/bin/sh"` (also on the stack)
	This will give us a shell Yay
### Considerations:
* Sometimes a leak might cause a crash
* Remember, you can always return somewhere useful
	* "Continuity of Execution"
	* Ex: return into `main`

# Return Oriented Programming 2: Next Steps
(More slides)
## ROP (Like the Rolling Stones)
Sometimes we don't have the gadgets to accomplish what we need
	*You can't always get what you want*
	But if you **try some time** you find, you get what you need
### Example: Want to `syscall` to `execve` but have limited gadgets:
Available Opcodes:
```
pop rdi; ret
pop rsi; ret
syscall; ret
```
* No *easy* control of `rdx`
#### Time to get creative:
Do we have **any** control over `rdx`?
	`pop $REG; mov rdx, $REG; ret`
	`XOR`, `INC`, `ADD`, ...etc
Sometimes, you want to do the more complex ROP operations earlier in your chain and the easier ones at the end
* This lets you use some registers as "general registers" while you're setting up the target register
## Space Needed
Sometimes you need data in memory
* Sometimes it isn't available to you
	Ex: No libc leak, no stack leak
So, you need to write the data somewhere in memory... where do you put it?
### `.bss`/`.data`
Readable/Writeable Sections
	`.bss`: Initialized Data
	`.data` Unitialized data
Operating systems map memory in `0x1000` ranges
* They may not use the whole page
* There may be stack space at the end
#### Example:
![[Pasted image 20240309150114.png]]
The section "ends" at `0x601090
* Leaves `0xf70` space of data to mess with

How do we get data there?
	ROP (of course!)
Try to abuse `fgets`, `gets`, `read`, ...etc
`.bss` is predictable now that we know where it is

## [[Stack Pivoting]]: Maybe You Just Need More Stack Space
**RSP does not need to be fixed** it is malleable
##### Examples:
```
pop rsp; ret
add rsp, $REG; ret
```

What happens next?
* We get a brand new stack
* It's basically a second stage stack
## ROP Chain Strategy and Tricks
* Avoid complexity
	* The longer it is the more steps to cause issues
* Avoid writing memory near your stack
	* Don't want to overwrite the stack itself
* The simpler, the better
	* Think "elegant" *(Not elephant)*
* Let functions do the heavy lifting where possible:
	* Maybe there's a syscall with `0x3b` set up and you only need to populate one register
	* *"get creative"*
	* `one_gadget` tool may help find things
		* *"mileage may vary"*

# Other Resources
[[Gadgets]]
[[Return Oriented Programming]]
[[Ret2Plt]]
[[Ret2LibC]]
[[Syscalls]]

# Challenges
[[Gimbal]]
[[ROP Pop Pop]]
[[Inspector]]