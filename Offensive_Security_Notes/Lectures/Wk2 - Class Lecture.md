Looking at decompiled code example
```c
{
	int iVar1;
	int iVar2;
	long in_FS_OFFSET;
	char local_28 [24];
	long local_10;

	local_10 = *(long *)(in_FS_OFFSET +  0x28);
	fgets(local_28, 0x14, stdin);
	iVar1 = atio(local_28);
	fgets(local_28, 0x14, stdin);
	iVar2 = atio(local_28);
	if((iVar2 < 0)||(iVar1 < 0)){
		puts("Both numbers must be greater athan 0\n");
		exit(1);
	}
	if(((iVar1 % 0xd == 0)&&(((iVar1 != 0xd && (0x5db < iVar1)) && (4999 < iVar2)))) && (iVar1 * iVar2 == 0xd04961)){
	  puts("you win\n");
	  return 0;
	}
	puts("Sorry, no\n");
	exit(1);
}
```

Code takes in two variables and then checks to see if they match a mathematical condtion.
Can solve using a solver
```python
from pwn import *
from z3 import *

a, b = Ints('a b')
s = Solver()
s.add(a >= 0)
s.add(b >= 0)

s.add(a % 13 == 0)
s.add(a != 13)
s.add(a > 0x5db)
s.add(b > 4999)
s.add(a * b = 0xd04961)

print(s.check())
print(s.model())
```
So this was pretty straightforward because the conditions were, but what if it wasn't

We make a function and pass a and b into that, then wait and see if the return value is what we 



# Dora Intro
What does this function do: 
`void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);`
This creates that map
Because the address is 0, it's not requesting a particular file, the OS will just pick an address

Protection of 7
	Protection is set like read/write/execute (so the protections allow for reading, writing, and executing)
Other flag value explanations are probably also in Man


# Casting
Example code:
![[Pasted image 20240212164741.png]]
##### `uVar3 = (uint)v;`
`MOVZX EAX byte ptr [v]`
	Moves the byte pointing to the value of variable `v` into the `eax` register and 0's out any other data in there
##### `iVar1 = (char)(uint)v`
`MOV byte ptr [RBP + local_val], AL`
	`AL` is the lower byte (8 bits) of `EAX`
	We can tell that that value is a single byte by looking at the stack
	
`LEA RAX[v]`
	Load the address of `v` into `RAX`
##### `iVar2 - (short)v`
`MOVZX EAX=>v, word ptr [RAX]`
	Move a word pointer from that address (stored in `RAX`) into `EAX`
	So this moves the 16 bit word into `EAX` and 0-extends it
`MOV word ptr [rbp + local_c], AX`
	Moves the first  bytes of `RAX` into the stack, offset by local e (which is the length of a word/short)

# Challenges
[[Bridge of Death]]
[[Dora]]
[[Due 02-14-2024]]