Info from:
* [Blog Post](https://ir0nstone.gitbook.io/notes/types/stack/stack-pivoting)

# Stack Pivoting
Lack of space for ROP
## Overview
**Stack Pivoting** is a technique for when there isn't enough space on the stack.
	Ex: We have 15 bytes past `rip`
	Can't complete a full ROP chain
Stack pivoting is essentially:
* Take control of `RSP` to "fake" the location of the stack

## A Few Techniques
### `pop rsp gadget`
The simplest, but also the least likely to exist
### `xchg $Reg, rsp`
If you can also find a `pop $Reg` gadget, this `xchg` gadget will swap the values with the ones in `rsp`
* Requires about 16 bytes of stack space after the saved return pointer
```
RetPtr ---> pop $Reg
			$Reg Value
			xchg $Reg, rsp
```
### `leave; ret`
This *very interesting* way of stack pivoting only requires 8 bytes

Every function (except `main`) is ended with a `leave; ret` gadget
`leave` is equivalent to:
```
mov rsp, rbp
pop rbp
```
So function endings look like:
```
mov rsp, rbp
pop rbp
pop rip
```
Therefore, when we overwrite `rip`, the 8 bytes before that overwrite `rbp`
	(Maybe this is something you noticed before)
	So... how does this help us?
`leave` moves the value in `rbp` into `rsp`
* If we can overwrite `rbp` then overwrite `rip` with the address of a `leave; ret` gadget
	* The value in `rbp` is moved to `rsp`
* Won't need any more stack space than just to overwrite `rip`