Sources
* [Ironstone Gitbook](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/gadgets)
# Gadgets
Controlling Execution with snippets of code

**Gadgets** are small snippets of code followed by a `ret`
	Ex: `pop rdi; ret`
We can manipulate the `ret` to string together a large chain of them to execute specific operations
* Do this by overwriting return address on the stack
## Example
Stack looks like this during execution of a `pop rdi; ret` gadget
```
rsp --> 0x10
		0x5655576724
```
What happens?
1) `0x10` is popped into `rdi` as it's at the top of the stack during `pop rdi`
2) After the `pop`, `rsp` moves:
```
		0x10
rsp --> 0x5655576724
```
3) The address `0x5655576724` is popped into `rip`
	This happens because `ret` is equivalent to `pop rip`
## Utilizing Gadgets
* When we overwrite the return pointer, we're overwriting the value that `rsp` points to.
* Once that value is popped, it points to the next value on the stack
	* We can overwrite that too
### Example:
Say we want to exploit a binary to do the following
* jump to a `pop rdi; ret` gadget
* pop `0x100` into `rdi` then jump to `flag()`
##### Step by step execution
Stack at start:
```
		<PADDING>
rsp --> GADGET ADDR
		0x100
		flag()
		[...]
rip --> RET
```

On the original `ret`, (which we overwrite the return pointer for), we pop the gadget address in
* Now `rip` moves to point to the gadget
* `rsp` moves to the next memory address
Stack:
```
		<PADDING>
		GADGET ADDR
rsp --> 0x100
		flag()
		[...]

		-GADGET-
rip --> POP RDI
		RET
```

Next, `rsp` moves to point to `0x100` and `rip` moves to point to the `pop rdi` gadget
* Now when we pop, `0x100` is moved into `rdi`
Stack:
```
		<PADDING>
		GADGET ADDR
		0x100
rsp --> flag()
		[...]

		-GADGET-
		POP RDI
rip --> RET
```

RSP moves onto the next item on the stack: the address of `flag()` The `ret` executes and the program calls `flag`

## Summary
Essentially, if the gadget pops values from the stack:
* Place those values in the stack after the gadget's address
	(Including the `pop rip` in `ret`)

If we want to pop `0x10` into `rdi` and then jump to `0x16`
	The payload will look like:
```
   Ret Addr --> pop rdi     <-- Gadget Address
				0x10       <-- Value into RDI
				0x16       <-- Value into RIP
```

If you have multiple `pop` instructions, you can just add more values:
```
   Ret Addr --> pop rdi     <-- Gadget Address
				0x10       <-- Value into RDI
				0x14       <-- Value into RSI
				0x18       <-- Value into RDX
				0x16       <-- Value into RIP
```

## Finding Gadgets with `ROPgadget`
```
$ ROPgadget --binary vuln-64

Gadgets information
============================================================
0x0000000000401069 : add ah, dh ; nop dword ptr [rax + rax] ; ret
0x000000000040109b : add bh, bh ; loopne 0x40110a ; nop ; ret
0x0000000000401037 : add byte ptr [rax], al ; add byte ptr [rax], al ; jmp 0x401024
[...]
```
Combine with `grep` to look for specific registers
```
$ ROPgadget --binary vuln-64 | grep rdi

0x0000000000401096 : or dword ptr [rdi + 0x404030], edi ; jmp rax
0x00000000004011db : pop rdi ; ret
```


I realized my first issue was that I wasn't writing to the correct address for `malloc_hook`, which I've fixed.
I'm still hung up on trying to call `system`.
The code attached is my debugger script. It uses the UAF to leak the libc address. Then it uses tcache poisoning to overwrite the `malloc_hook` value. 
Everything up to and including the overwrite works, but I think my `system` address value is wrong.
There are three `execve("/bin/sh")` gadgets that I found:
```
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL || r15 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp
```

Unfortunately, using any of these values results in a segfault in `execve`. 
This is the (cleaned up) program output if I use the last gadget: `system = libc + 0xe3b04`
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf$ python3 UAF_Pwn5-DBG.py 

Leaked Address:
0x7ffff7fafbe0
LibC Base Address:
0x7ffff7dc3000
System address?
0x7ffff7ea6b04
Malloc address?
0x7ffff7fafb70

Sending data: 0x7ffff7ea6b04
[*] Switching to interactive mode
$ x/2x 0x7ffff7fafb70
0x7ffff7fafb70 <__malloc_hook>:    0xf7ea6b04    0x00007fff

gef➤  $ c
Continuing.
=========== NYU OFFSEC ============
1.    Add a note
2.    Delete a note
3.    Edit a note
4.    Read a note
5.    Exit
=========== NYU OFFSEC ============
>$ 1
Size:
$ 24

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7ea6dc6 in __execvpe (file=<optimized out>, argv=<optimized out>, envp=<optimized out>) at execvpe.c:61
```

I think I just need a hint as to how I should be calling system/which gadget I should be using.
I'm not sure if it's something like the `ROP` chain, where there's steps I need before I actually make the call