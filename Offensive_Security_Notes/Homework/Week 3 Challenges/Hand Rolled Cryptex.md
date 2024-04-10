Points: 100
Location:  `nc offsec-chalbroker.osiris.cyber.nyu.edu 7332`
Lore: DaVinci Code?

First run
```
./hand_rolled_cryptex 
I found this weird cryptex...
...it seems to take some weird series of operations...
...but all the symbols are obscured...
...could you crack it for me??

The first round requires two inputs...
 > 13
 > 22

Oh no! That input broke the vial of vinegar, ruining
the papyrus scroll with the flag!
```

In Ghidra:
None of our functions have names...yay...
![[Pasted image 20240219130434.png]]

Ran using GDB, set a catch point at print and then had it disassemble where I'm at:
![[Pasted image 20240219131247.png]]
Which I think is here, in a totally useless place:
![[Pasted image 20240219131356.png]]
This is what the function code looks like:
```c
undefined8 FUN_00101377(void)
{
  syscall();
  return 2;
}
```


So I guess I have to find the place it's called


Binary Ninja will show a `main` and a `_start`
![[Pasted image 20240219142123.png]]


Main
![[Pasted image 20240219142211.png]]

So `sub_1169` is the print function
`sub_134` is where it reads the two inputs in
![[Pasted image 20240219142539.png]]
Reads in the first value as `rax_2`?
If that's 0, it sets `rax_3 = 0xffffffff`

First Number
![[Pasted image 20240219143553.png]]



So, essentially, once we enter our guess
```c
int roundOne(){
	void* fsbase
	int rax = *(fsbase + 0x28)
	int var48
	hrc_strcpy(&var48, "The first round ...etc \n >", 0x2b)
	hrc_print(1, &var48, sub13fe(&var8))
	int v = hrc_read(0, &readData, 0x100)
	if(v == 0){
		retValue = 0xffffffff
	}else{
		if(&readData[v - 1] == 0xa){
			&readData[v - 1] = 0
		}
		hrc_copy(&storedData, &readData, 0x20)
		hrc_overwrite(&readData, 0, 0x100)
		int var4d
		hrc_strcpy(&var4d, "\n >", 0x2b)
		hrc_print(1, &var4d, sub13fe(&var8))
		if(hrc_read(0, &readData, 0x100) == 0){
			retValue = 0xffffffff
		}else{
			val = sub_13cf(&storedDataa)
			if(val != 0xffffffff){}
				data_4010 = hrc_open(&storedData, val)
				hrc_overwrite(&storedData, 0, 0x20)
				hrc_overwrite(&readData, 0, 0x100)
				retValue = data_4010
			}else{
				retValue = 0xffffffff
			}
		}
		if(rax == *(fsbase + 0x28)){
			return retValue
		}
	}
}
```

##### `hrc_read`
Aka `sub_1359`:
![[Pasted image 20240219145700.png]]
essentially:
```c
int hrc_read(p1, p2, p3){
	*ptr = p2 // So p2 is a pointer to something...?
	return syscall(sys_read {0}, p1, ptr, p3)
}
```


##### `hrc_copy`
Aka `sub_12f6`
![[Pasted image 20240219154205.png]]
Looks like this copies the data from one array into another (until one of these reaches 0?)

##### hrc_overwrite
Aka`sub_1392`
![[Pasted image 20240219154520.png]]
I don't fully understand what the `.d` stuff does
Seems to essentially
```c
int hrc_overwrite(void* location, val, length){
	int i = 0
	while(true){
		if( i >= length){
			break
		}
		*(location + i) = val
		i++
	}
	return i
}
```
Overwrites the data with the specified character

##### `sub_13cf`
![[Pasted image 20240219170925.png]]
Checks the size of the new array?
##### `sub13fe`
![[Pasted image 20240219155804.png]]

##### `hrc_open`
Aka sub1377`
This is our sys_open!
![[Pasted image 20240219155740.png]]
She was hidden

So I THINK:
Takes in one piece of user-entered data
Saves that in our readData location
Copies everything in readData into storedData and then overwrites readData
Takes in another piece of user-entered data
Saves it in readData
Then it calls that open function using storedData

I think, for the second parameter...it just wants a number?
# File Open
It works as long as I pass it a real file:
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ echo "testtesttest" > test.txt
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ gdb ./hand_rolled_cryptex     
(gdb) r
Starting program: /home/kali/Desktop/3-Week/hand_rolled_cryptex 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
I found this weird cryptex...
...it seems to take some weird series of operations...
...but all the symbols are obscured...
...could you crack it for me??

The first round requires two inputs...
 > ./test.txt

 > 13
*The first chamber opened! Ok, the second phase requires a single input...

```

```
gdb ./hand_rolled_cryptex  
(gdb) r
Starting program: /home/kali/Desktop/3-Week/hand_rolled_cryptex 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
I found this weird cryptex...
...it seems to take some weird series of operations...
...but all the symbols are obscured...
...could you crack it for me??

The first round requires two inputs...
 > ./flag.txt

 > 0
*The first chamber opened! Ok, the second phase requires a single input...
 > q

Oh no! That input broke the vial of vinegar, ruining
the papyrus scroll with the flag!
[Inferior 1 (process 3661782) exited normally]
(gdb) q

```


it looks like, based on my decompiled Main method, the second call is `sub_160f`
Calls to questions:
![[Pasted image 20240219172939.png]]

# Second Question: `sub_160f`
![[Pasted image 20240219173111.png]]
```c
int q2(){
	void* fsbase;
	int rax = *(fsbase + 0x28);
	int var68;
	hrc_strcpy(&var68, "Text", 0x4f);
	hrc_print(1, &var68, sub13fe(&var68));
	int rax3;
	if(hrc_read(0, &readData, 0x100) != 0){
		int rax8 = hrc_read(not.b(readData) ^ 0xc9, &readData2, 0x100);
		hrc_overwrite(&readData, 0, 0x100);
		rax3 = rax8
	} else{
		rax3 = 0xffffffff
	}
	if(rax == *(fsbase + 0x28)){
		return rax3
	}
}
```

Ghidra
```c
undefined4 Question2(void)

{
  undefined4 uVar1;
  int iVar2;
  local_1a = 0;
  // Writing question
  uVar1 = get_Length(&local_68);
  hrc_write(1,&local_68,uVar1);
  iVar2 = hrc_read(0,&DAT_00104040,0x100);
  if (iVar2 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = hrc_read(~DAT_00104040 ^ 0xc9,&DAT_00104140,0x100);
    hrc_overwrite(&DAT_00104040,0,0x100);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar1;
}
```


So it reads in data
XORs it with `0xc9`
Uses that as the first value in a read call that saves the next user-input into readData2
And then will return that value as long as everything is good


I feel like we probably want a 0 again for that value in read data
so input1 ^ 0xc9 = 0?
...no
So I think that's the file descriptor..
0 = stdin
1 = stdout
2 = stderr

So wouldn't we want it to read stdin?
I guess maybe we don't want it to read in new user data


Looking back at the read function, it returns the value of syscall

```c
int hrc_read(p1, p2, p3){
	*ptr = p2 // So p2 is a pointer to something...?
	return syscall(sys_read {0}, p1, ptr, p3)
}
```
Looking at the `read` `man` page:
	`read() attempts to read up to _count_ bytes from file descriptor _fd_ into the buffer starting at _buf_.`

So the past few read starting at 0...but maybe this is different somehow
It doesn't seem to care about the actual data being read though, just the return value:
```
On success, the number of bytes read is returned (zero indicates end of file), and the file position is advanced by this number. It is not an error if this number is smaller than the number of bytes requested; this may happen for example because fewer bytes are actually available right now (maybe because we were close to end-of-file, or because we are reading from a pipe, or from a terminal), or because read() was interrupted by a signal.  See also NOTES.
On error, -1 is returned, and errno is set to indicate the error. In this case, it is left unspecified whether the file position (if any) changes.
```
So FD has to be 0, 1, or 2, but none of those values work...
fd=3?
# GDB
Find entry point, can use `info file`
Find entry and set break. Can't use `disas` can print instructions
	n # of instructions starting from `eip`
		`x/ni $eip`
`___libc_start_main@pl_` initializes processes and calls main
	Address is probably pushed right before that call
### Finding Entry Point
Must do this AFTER program has already ran
```
gdb ./hand_rolled_cryptex
(gdb) r
...omitted for brevity...
Oh no! That input broke the vial of vinegar, ruining
the papyrus scroll with the flag!
[Inferior 1 (process 3736152) exited normally]
(gdb) info file
Symbols from "/home/kali/Desktop/3-Week/hand_rolled_cryptex".
Local exec file:
        `/home/kali/Desktop/3-Week/hand_rolled_cryptex', file type elf64-x86-64.
        Entry point: 0x555555555080
        0x0000555555554318 - 0x0000555555554334 is .interp
        0x0000555555554338 - 0x0000555555554358 is .note.gnu.property
        0x0000555555554358 - 0x000055555555437c is .note.gnu.build-id
...omitted for brevity...
(gdb) q
```

After setting break, find where we think it calls main: (The call at the bottom)
```
gdb ./hand_rolled_cryptex
(gdb) break *0x555555555080
Breakpoint 1 at 0x555555555080
(gdb) r
Breakpoint 1, 0x0000555555555080 in ?? ()
(gdb) x/20i $pc
=> 0x555555555080:      endbr64
   0x555555555084:      xor    %ebp,%ebp
   0x555555555086:      mov    %rdx,%r9
   0x555555555089:      pop    %rsi
   0x55555555508a:      mov    %rsp,%rdx
   0x55555555508d:      and    $0xfffffffffffffff0,%rsp
   0x555555555091:      push   %rax
   0x555555555092:      push   %rsp
   0x555555555093:      lea    0xf16(%rip),%r8        # 0x555555555fb0
   0x55555555509a:      lea    0xe9f(%rip),%rcx        # 0x555555555f40
   0x5555555550a1:      lea    0x888(%rip),%rdi        # 0x555555555930
   0x5555555550a8:      call   *0x2f32(%rip)        # 0x555555557fe0
   0x5555555550ae:      hlt
   ...omitted for brevity
(gdb) break *0x555555557fe0
Breakpoint 2 at 0x555555557fe0

```


![[Pasted image 20240219184203.png]]
What is so important there?
![[Pasted image 20240219184005.png]]

RBP is currently all 0s


# GDB 2
I need to find where they call `__libc_start_main`
I can see it in `strings`
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ strings hand_rolled_cryptex
/lib64/ld-linux-x86-64.so.2
sKkTGT2"/
mgUa
libc.so.6
__stack_chk_fail
stdin
stdout
__cxa_finalize
setvbuf
__libc_start_main
GLIBC_2.4
GLIBC_2.2.5
_ITM_deregisterTMCloneTable
__gmon_start__
```


So `# __libc_start_main` takes in the location of `main` as it's main method:
```
int __libc_start_main(int (*main) (int, char * *, char * *), int __argc__, char * * __ubp_av__, void (*init) (void), void (*fini) (void), void (*rtld_fini) (void), void (* _stack_end_));
```
And in `entry`, we can see that call in Ghidra
Entry:
```c
void processEntry entry(undefined8 param_1,undefined8 param_2)
{
  undefined auStack_8 [8];  __libc_start_main(FUN_00101930,param_2,&stack0x00000008,FUN_00101f40,FUN_00101fb0,param_1, auStack_8);
  do {
    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```
So that makes `FUN_00101930` Our main method:, gonna renaime it
The main method code looks SO different in this version and is so much harder to read
Okay, but maybe we can use this information to figure out where main is in the debugger
![[Pasted image 20240220134351.png]]


Dug through, found question 1, so I think I can see it's response in RAX if I set a breakpoint after at `hand_rolled_cryptex+1c08h`
![[Pasted image 20240220135039.png]]
and then maybe I can see what that function returns
`555555554000 + 1c08 = 555555555C08`
Okay, so why does this return 3...?
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ gdb ./hand_rolled_cryptex
(gdb) break *0x555555555080
Breakpoint 1 at 0x555555555080
(gdb) r
Starting program: /home/kali/Desktop/3-Week/hand_rolled_cryptex 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x0000555555555080 in ?? ()
(gdb) info proc map
process 100090
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
      0x555555554000     0x555555555000     0x1000        0x0  r--p   /home/kali/Desktop/3-Week/hand_rolled_cryptex
(gdb) break *0x555555555C08
Breakpoint 2 at 0x555555555c08
(gdb) c
Continuing.
I found this weird cryptex...
...it seems to take some weird series of operations...
...but all the symbols are obscured...
...could you crack it for me??

The first round requires two inputs...
 > ./test.txt

 > 13

Breakpoint 2, 0x0000555555555c08 in ?? ()
(gdb) info registers rax
rax            0x3                 3
(gdb) 
```
So...that's strange


What is it taking in as the FD? Could it be the other number I entered?
Setting a breakpoint here 
![[Pasted image 20240221124555.png]]
`555555554000 + 1723 = 555555555723`




But now I can look more closely at Question 2
IT IS A NOT, I WAS RIGHT
```
undefined4 Question2(void)
{
  ...omitted for brevity...
  uVar1 = get_Length(&local_68);
  hrc_write(1,&local_68,uVar1);
  iVar2 = hrc_read(0,&DAT_00104040,0x100);
  if (iVar2 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = hrc_read(~DAT_00104040 ^ 0xc9,&DAT_00104140,0x100);
    hrc_overwrite(&DAT_00104040,0,0x100);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar1;
}
```
So now I update my solver script with that nice piece of information:
```
from z3 import *

def question2():
	s = Solver()
	a = BitVec('a',4)
	s.add(~(a) ^ 0xc9 == 0x3)
	print(s.check())
	print(s.model())

question2()

┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ python3 HRC_Solver.py
	sat
	[a = 5]
```
So let's try a 5!

It didn't work until I tried a 0 in the first one again....wild...so previous inputs do matter 
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ gdb ./hand_rolled_cryptex
(gdb) r
I found this weird cryptex...
...it seems to take some weird series of operations...
...but all the symbols are obscured...
...could you crack it for me??

The first round requires two inputs...
 > ./flag.txt

 > 13
*The first chamber opened! Ok, the second phase requires a single input...
 > 5
Oh no! That input broke the vial of vinegar, ruining
the papyrus scroll with the flag!
[Inferior 1 (process 107611) exited normally]

(gdb) r
I found this weird cryptex...
...it seems to take some weird series of operations...
...but all the symbols are obscured...
...could you crack it for me??

The first round requires two inputs...
 > ./flag.txt
 > 0
*The first chamber opened! Ok, the second phase requires a single input...
 > 5
Nice, the second chamber opened! Ok, the final level requires another single input...
 > 
```
Entering 13 (for no reasons other than Taylor Swift) maybe worked?
```
Nice, the second chamber opened! Ok, the final level requires another single input...
 > 13

The final chamber opened, but a flaw in the design
popped a vinegar vial which started to eat away at the papyrus
scroll inside. You hold it up, trying to decipher the text... [Inferior 1 (process 107790) exited normally]
```
Okay, that's not a local vs remote thing, I got the same response remote.


# Final Question
So looking at our main methods, it looks like it TRIES to print the value as it fades, using it's read method
![[Pasted image 20240220141904.png]]
And in our Q1, we see that's where the filename was saved
![[Pasted image 20240220142008.png]]
...can I use this to open /etc/shadow or something I wonder

So every other time we call that read method, we want a 1, so I'm going to assume we want that RAX value to be equal to 1
That `sub_175a` is our Question 3
```c
  local_8c = hrc_read(0,&DAT_00104040,0x100);
  if (local_8c == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    guess_Q3 = (int)DAT_00104040;
    if (guess_Q3 == 1) {
      uVar1 = 0xffffffff;
    }
    else if (guess_Q3 < 0) {
      uVar1 = 0xffffffff;
    }
    else {
      local_90 = 0xffffffff;
      if (guess_Q3 == 2) {
        local_90 = get_Length(&guess_Q3);
        uVar1 = local_90;
      }
      else {
        if (guess_Q3 < 3) {
          if (guess_Q3 == 0) {
            local_90 = FUN_001013cf((int)DAT_00104040);
            uVar1 = local_90;
            goto LAB_0010191a;
          }
          uVar1 = local_90;
          if (guess_Q3 == 1) goto LAB_0010191a;
        }
        puVar2 = (undefined4 *)FUN_00101201(guess_Q3,local_88,10);
        local_90 = *puVar2;
        uVar1 = local_90;
      }
    }
  }
LAB_0010191a:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar1;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
So we read in our guess, check to make sure the function was fine, and then store the guess as an int
Then we make a couple more checks
	if it is 1 - we fail
	if it < 0 - we fail
	if it is 2, we return the length of the integer? (which I assume is 1)
Otherwise, if the guess is less than three:
	Checks for 0 again

```c
int FUN_001013cf(char param_1)
{
  int iVar1;
  if ((param_1 < '0') || ('9' < param_1)) {
    iVar1 = -1;
  }
  else {
    iVar1 = param_1 + -0x30;
  }
  return iVar1;
}
```
This function checks our entered value to see if it's between 0-9
If it is,it returns that value + -0x30

I feel like it HAS to be 0 but I guess not for some reason

Gonna set a breakpoint at the move after Q3 and see what it returns
![[Pasted image 20240220143821.png]]
`555555554000 + 1c3a = 555555555C3A`

I think it needs to go in the second one because we KNOW it can't be 0
So this function takes in our guess as p1
```c
undefined * FUN_00101201(int param_1,undefined *param_2,int param_3)

{
  bool bVar1;
  char cVar2;
  int guess_val;
  int local_10;
  
  local_10 = 0;
  bVar1 = false;
  if (param_1 == 0) {
    *param_2 = 0x30;
    param_2[1] = 0;
  }
  else {
    guess_val = param_1;
    if ((param_1 < 0) && (param_3 == 10)) {
      bVar1 = true;
      guess_val = -param_1;
    }
    for (; guess_val != 0; guess_val = guess_val / param_3) {
      cVar2 = (char)(guess_val % param_3);
      if (guess_val % param_3 < 10) {
        cVar2 = cVar2 + '0';
      }
      else {
        cVar2 = cVar2 + 'W';
      }
      param_2[local_10] = cVar2;
      local_10 = local_10 + 1;
    }
    if (bVar1) {
      param_2[local_10] = 0x2d;
      local_10 = local_10 + 1;
    }
    param_2[local_10] = 0;
    FUN_00101187(param_2,local_10);
  }
  return param_2;
}
```

I think the meat of the function is in that for loop
```c
for (; guess_val != 0; guess_val = guess_val / param_3) {
  cVar2 = (char)(guess_val % param_3);
  if (guess_val % param_3 < 10) {
	cVar2 = cVar2 + '0';
  }
  else {
	cVar2 = cVar2 + 'W';
  }
  param_2[local_10] = cVar2;
  local_10 = local_10 + 1;
}
```


I'm wondering if it sets the value equal to the address of the data?
I think it certainly takes the last byte?
![[Pasted image 20240220163637.png]]

Bu that "guess" value seems to be the offset in the heap for where the data is supposed to  be


breaks:
```
break *0x555555555866
break *0x55555555586d
break *0x555555555870
break *0x555555555876
break *0x55555555587c
break *0x55555555587f
```


So what we determined is, before all of this `[DAT_00104040]` is set to 0x32 / 50
```
break *0x55555555583c
break *0x555555555843
```

Put in 1234 and it was set to 0x31

![[Pasted image 20240220171612.png]]
What about here
`555555554000 + 1f01 = *555555555F01`
`break *0x555555555F01`


Also gonna set some here in the hrc write
![[Pasted image 20240220172242.png]]
```
555555554000 + 1171 = 555555555171

break *0x555555555171
```


# Fuck


It's looking at the ASCII value of the first character
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ gdb ./hand_rolled_cryptex
(gdb) break *0x55555555586d
Breakpoint 1 at 0x55555555586d
(gdb) r
The first round requires two inputs...
 > ./flag.txt
 > 0
*The first chamber opened! Ok, the second phase requires a single input...
 > 5
Nice, the second chamber opened! Ok, the final level requires another single input...
 > 2

Breakpoint 1, 0x000055555555586d in ?? ()
(gdb) info registers eax
eax            0x32                50
(gdb) c
Continuing.
The final chamber opened, but a flaw in the design
popped a vinegar vial which started to eat away at the papyrus
scroll inside. You hold it up, trying to decipher the text... [Inferior 1 (process 354433) exited normally]
(gdb) r
Starting program: /home/kali/Desktop/3-Week/hand_rolled_cryptex 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
I found this weird cryptex...
...it seems to take some weird series of operations...
...but all the symbols are obscured...
...could you crack it for me??
The first round requires two inputs...
 > ./flag.txt
 > 0
*The first chamber opened! Ok, the second phase requires a single input...
 > 5
Nice, the second chamber opened! Ok, the final level requires another single input...
 > 1234
Breakpoint 1, 0x000055555555586d in ?? ()
(gdb) info registers eax
eax            0x31                49
(gdb) c
Continuing.
The final chamber opened, but a flaw in the design
popped a vinegar vial which started to eat away at the papyrus
scroll inside. You hold it up, trying to decipher the text... [Inferior 1 (process 354877) exited normally]
(gdb) q

```


Put in 2 - got 0x32
Put in 1234 - Got 0x31

```
break *0x555555555866
break *0x55555555586d
break *0x555555555870
break *0x555555555876
break *0x55555555587c
break *0x55555555587f
```

So I have to send 2 as a byte of data


And look at THAT, we have our flag AND eax is equal to 2
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ python3 HRC_Local_Debug.py                      
[+] Starting local process '/bin/bash': pid 228752
  p.sendline('gdb ./hand_rolled_cryptex -q')
  p.sendline('break *0x55555555586d')
  p.sendline('r')
 *The first chamber opened! Ok, the second phase requires a single input...
 Nice, the second chamber opened! Ok, the final level requires another single input...
  p.sendline("info registers eax")
 (gdb) eax            0x2                 2
  p.sendline('c')
(gdb) Continuing.

The final chamber opened, but a flaw in the design
popped a vinegar vial which started to eat away at the papyrus
scroll inside. You hold it up, trying to decipher the text... flag{This is not a real flag}
[Inferior 1 (process 228757) exited normally]
```

Next step, world domination, I mean, the remote solution:
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ python3 HRC_Remote.py
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 7332: Done
b'I found this weird cryptex...\n'
 *The first chamber opened! Ok, the second phase requires a single input...

 Nice, the second chamber opened! Ok, the final level requires another single input...

{str1PP3d_B1N4R135_r_S0o0_much_FUN_408012}

[*] Closed connection to offsec-chalbroker.osiris.cyber.nyu.edu port 7332
```

QED


# Q3 Brute Force Script
`2 %32 &#x32; Mg== 32 02 0x2 0x02 10 `
Data
```
'2','32','02','032','002','0032','%2','%32','%02','%032','x2','x32','x02','#x32','&#x32','\2','\32','\02','\x2','\x32','\x02','0x2','0x32','0x02','\0x2','\0x32','\0x02'
```


```
'\x02', '2'
```


Results:
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ python3 HRC_Local_Debug.py
[+] Starting local process '/bin/bash': pid 313099
Correct Answer Found
Correct Answer Found
Correct Answer Found
{This is not a real flag}
[*] Stopped process '/bin/bash' (pid 313099)

┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ cat HRC_Q3_dbg.txt
Hand Rolled Cryptex Q3 Debug Log:
Valid Answer!
Hand Rolled Cryptex Q3 Debug Log:
Valid Answer!
Guess at index 15= 
(gdb) eax            0x2                 2
Valid Answer!
Guess at index 17= 
(gdb) eax            0x2                 2
Valid Answer!
Guess at index 20= 
(gdb) eax            0x2                 2
```

Three Correct Answers, but won't print bc they're bytes haha
```
'\2', '\02', '\x02'
```


