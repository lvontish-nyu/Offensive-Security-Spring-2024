From [here](https://cyber.cole-ellis.com/binex/01-ret2win/win64).

Solving a 64-bit Ret2Win
**Remember**: 64-bit binaries pass parameters via the registers. The return pointer and base pointer are stored on the stack.
# Checking Security
`checksec` for the win:
```
$ checksec win64
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```

There are no protections on the binary, so ret2win will probably work.
# GDB Disassembly
## Function list
```
gef➤  info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401070  puts@plt
0x0000000000401080  system@plt
0x0000000000401090  gets@plt
0x00000000004010a0  fflush@plt
0x00000000004010b0  _start
0x00000000004010e0  _dl_relocate_static_pie
0x00000000004010f0  deregister_tm_clones
0x0000000000401120  register_tm_clones
0x0000000000401160  __do_global_dtors_aux
0x0000000000401190  frame_dummy
0x0000000000401196  win
0x00000000004011b5  read_in
0x00000000004011f3  main
0x000000000040121b  usefulGadgets
0x000000000040122c  _fini
```

Looking straight at `read_in`
* We know that `win` and `main` aren't relevant
## `read_in`
```
gef➤  disas read_in
Dump of assembler code for function read_in:
   0x00000000004011b5 <+0>:	endbr64 
   0x00000000004011b9 <+4>:	push   rbp
   0x00000000004011ba <+5>:	mov    rbp,rsp
   0x00000000004011bd <+8>:	sub    rsp,0x30
   0x00000000004011c1 <+12>:	lea    rax,[rip+0xe50]        # 0x402018
   0x00000000004011c8 <+19>:	mov    rdi,rax
   0x00000000004011cb <+22>:	call   0x401070 <puts@plt>
   0x00000000004011d0 <+27>:	mov    rax,QWORD PTR [rip+0x2e71]        # 0x404048 <stdout@GLIBC_2.2.5>
   0x00000000004011d7 <+34>:	mov    rdi,rax
   0x00000000004011da <+37>:	call   0x4010a0 <fflush@plt>
   0x00000000004011df <+42>:	lea    rax,[rbp-0x30]
   0x00000000004011e3 <+46>:	mov    rdi,rax
   0x00000000004011e6 <+49>:	mov    eax,0x0
   0x00000000004011eb <+54>:	call   0x401090 <gets@plt>
   0x00000000004011f0 <+59>:	nop
   0x00000000004011f1 <+60>:	leave  
   0x00000000004011f2 <+61>:	ret  
```

"Assembly Dance" Process
1) `main` calls `read_in` using a `call` operation.
	`call` does two things:
	1) Puts the return pointer (the address of the instruction in `main` after `call read_in`) on the stack
	2) Jumps to the address of the called function
		In this case, the address is `0x4011b5`, the first line of `read_in`
2) `push rbp` pushes the old base pointer on the stack so that it can be restored later
	This happens at line `0x4011b9`
3) `move rbp, rsp` sets the base pointer to the current stack pointer so that the bp can be used as a reference to the current stack frame
	This happens at line `0x4011ba`
4) `sub rsp,0x30` allocates `0x30` bytes onto the stack for local variables
	Happens at line `0x4011bd`

So after the "assembly dance," this is what our stack looks like:
```
 rsp -> ...
		0x30 Bytes
		base pointer
		return pointer
		...
```

The assembly has a call to `puts@plt` at line `0x4011cb` and to `gets@plt` at line `4011eb`
* The `puts` call just prints out the challenge text, so we'll focus on `gets`

# Inputting in 64 Bit

Parameters are passed via the registers for 64-bit programs
* `gets()` takes one argument:
	* The address where the input is stored
		* In this case, the binary writes to the stack

The address is moved to `rdi` in the following lines:
```
   0x00000000004011df <+42>:	lea    rax,[rbp-0x30]
   0x00000000004011e3 <+46>:	mov    rdi,rax
   0x00000000004011e6 <+49>:	mov    eax,0x0
   0x00000000004011eb <+54>:	call   0x401090 <gets@plt>
```
We can see that `rdi` gets the address of `rbp-0x30`
* so that's where the program writes the input data

# Getting the offset

Put in a breakpoint before the call:
```
gef➤  b *(read_in+54)
gef➤  run
```

The return address can be found by checking the instruction after the `call` to `read_in`:
```
0x0000000000401200 <+13>:	call   0x4011b5 <read_in>
0x0000000000401205 <+18>:	lea    rax,[rip+0xe30]        # 0x40203c
```

Looking at the stack, we do see our return pointer there:
```
gef➤  x/10gx $rsp
0x7fffffffe450:	0x0000000000000000	0x0000000000000000
0x7fffffffe460:	0x0000000000000000	0x0000000000000000
0x7fffffffe470:	0x0000000000000000	0x0000000000000000
0x7fffffffe480:	0x00007fffffffe490	0x0000000000401205
0x7fffffffe490:	0x0000000000000001	0x00007ffff7c29d90
```
Yep, right there:
```
gef➤  x/gx 0x7fffffffe488
0x7fffffffe488:	0x0000000000401205
```