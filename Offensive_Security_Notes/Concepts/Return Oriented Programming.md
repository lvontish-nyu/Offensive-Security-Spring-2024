[From CTF 101](https://ctf101.org/binary-exploitation/return-oriented-programming/)
**Return Oriented Programming** (**ROP**) is the art of chaining together small snippets of assembly with *stack control* to cause the program to do more complex things.
As demonstrated in [[Stack Buffer Overflow]], having stack control can be powerful. It allows us to overwrite saved instruction pointers, giving us control over what the program does next.
* Of course, not all programs have some sort of `give_shell` function like we've seen on some of the easier challenges.
* Must find a way to manually invoke `system` or another `exec` function to get a shell
# 32 Bit
###### Example Program:
```c
#include <stdio.h>
#include <stdlib.h>

char name[32];

int main() {
    printf("What's your name? ");
    read(0, name, 32);

    printf("Hi %s\n", name);

    printf("The time is currently ");
    system("/bin/date");

    char echo[100];
    printf("What do you want me to echo back? ");
    read(0, echo, 1000);
    puts(echo);

    return 0;
}
```

The `echo` variable provides us a route to perform a stack buffer overflow
* The `echo` array is initialized for 100 bytes but `read` is given a buffer size of 1000
* Can leverage this issue to control `EIP` when `main` returns
	* But oh no! We have no handy-dandy `give_shell` function!
		  *What do we do now!*
We can call `system` with an argument that we control!
* Arguments are passed in on the stack in 32-bit Linux programs
	* See [[Calling Conventions]]
* If we have stack control, we have argument control

When `main` returns, we want the stack to look like something had called `system` normally
* This will  prevent alignment issues
Stack After a Function Was Called:
```
		...                                 // More arguments
        0xffff0008: 0x00000002              // Argument 2
        0xffff0004: 0x00000001              // Argument 1
ESP ->  0xffff0000: 0x080484d0              // Return address
```

So `main`'s stack frame needs to look like:
```
        0xffff0008: 0xdeadbeef              // system argument 1
        0xffff0004: 0xdeadbeef              // return address for system
ESP ->  0xffff0000: 0x08048450              // return address for main (system's PLT entry)
```

That way, when `main` returns, it will jump to `system`'s PLT entry and the stack will look like `system` had just been called normally!
	**Note**: We don't care about what return address `system` will try to return to because we'll already have our shell by then!
## Arguments
We need to pass an argument to `system` for anything to happen.
* The stack and dynamic libraries "move around" every time a program is run due to Address Space Layout Randomization
	* We can't easily use the data on the stack or something like a string in `libc` for the argument
* In this case, we have a convenient `name` global which will be at a known location in the binary (in the `BSS` Segment)
## Putting it Together
Our Exploit will need to do the following:
1) Enter `"sh"` or another command to run as `name`
2) Fill the stack with:
	1) Garbage up to the saved `EIP`
	2) The address of `system`'s PLT entry
	3) A fake return address for `system` to jump to when it returns
	4) The address of the `name` global to act as the first argument to `system`
# 64 Bit
In 64-bit binaries it's a bit harder to pass arguments to functions.
* The basic idea is the same:
	  Overwrite the saved `RIP`
* Arguments are passed in *registers* in a 64-bit system rather than on the stack
	* See [[Calling Conventions]] for more
* To run `system`, we need to find a way to control the `RDI` register

To control `RDI`, we'll use small snippets of assembly in the binary called "*gadgets*"
* Usually code that pops one or more registers off the stack then calls `ret`
	* This will allow us to chain them together by making a large fake stack call
* Can find gadgets using tools like [RP++](https://github.com/0vercl0k/rp) and [ROP Gadget](https://github.com/JonathanSalwan/ROPgadget)
For example, if we need to control both `RDI` and `RSI`
* Can maybe find two gadgets that look like this:
```
0x400c01: pop rdi; ret
0x400c03: pop rsi; pop r15; ret
```
We can set up a fake stack call with these gadgets to sequentially execute them
* Will pop values we control into the registers
* Then end with a jump to `system`
## Example
```
        0xffff0028: 0x400d00   // where we want the rsi gadget's ret to jump to now that
						        rdi and rsi are controlled
        0xffff0020: 0x1337beef          // value we want in r15 (probably garbage)
        0xffff0018: 0x1337beef          // value we want in rsi
        0xffff0010: 0x400c03    // address that the rdi gadget's ret will return to
							    - the pop rsi gadget
        0xffff0008: 0xdeadbeef          // value to be popped into rdi
RSP ->  0xffff0000: 0x400c01            // address of rdi gadget
```

Stepping through this one instruction at a time:
	`main` returns, jumping to our `pop rdi` gadget
```
RIP = 0x400c01 (pop rdi)
RDI = UNKNOWN
RSI = UNKNOWN

        0xffff0028: 0x400d00   // where we want the rsi gadget's ret to jump to now that
						        rdi and rsi are controlled
        0xffff0020: 0x1337beef          // value we want in r15 (probably garbage)
        0xffff0018: 0x1337beef          // value we want in rsi
        0xffff0010: 0x400c03    // address that the rdi gadget's ret will return to
						        - the pop rsi gadget
RSP ->  0xffff0008: 0xdeadbeef          // value to be popped into rdi
```

Then `pop rdi` is executed, popping the top of the stack into `RDI`
```
RIP = 0x400c02 (ret)
RDI = 0xdeadbeef
RSI = UNKNOWN

        0xffff0028: 0x400d00     // where we want the rsi gadget's ret to jump to now
							        that rdi and rsi are controlled
        0xffff0020: 0x1337beef          // value we want in r15 (probably garbage)
        0xffff0018: 0x1337beef          // value we want in rsi
RSP ->  0xffff0010: 0x400c03      // address that the rdi gadget's ret will return to
									- the pop rsi gadget
```

The `RDI` gadget then returns, jumping us right to the `RSI` gadget
```
RIP = 0x400c03 (pop rsi)
RDI = 0xdeadbeef
RSI = UNKNOWN

        0xffff0028: 0x400d00    // where we want the rsi gadget's ret to jump to now that
							        rdi and rsi are controlled
        0xffff0020: 0x1337beef  // value we want in r15 (probably garbage)
RSP ->  0xffff0018: 0x1337beef  // value we want in rsi
```

`RSI` and `R15` are popped:
```
RIP = 0x400c05 (ret)
RDI = 0xdeadbeef
RSI = 0x1337beef

RSP ->  0xffff0028: 0x400d00            // where we want the rsi gadget's ret to jump to
											now that rdi and rsi are controlled
```

So finally, the `RSI` gadget returns, jumping to whatever function we want, but now with `RDI` and `RSI` set to values that we control!
# Other Related Articles:
[Address Space Layout Randomization (ASLR)](https://ctf101.org/binary-exploitation/return-oriented-programming/address-space-layout-randomization)
[What is the GOT](https://ctf101.org/binary-exploitation/what-is-the-got/)
[Stack Canaries](https://ctf101.org/binary-exploitation/stack-canaries/)