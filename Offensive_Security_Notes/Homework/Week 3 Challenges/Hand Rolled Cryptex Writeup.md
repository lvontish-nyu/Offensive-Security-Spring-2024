writeup for [[Hand Rolled Cryptex]]
## Info
Points: 100
Location:  `nc offsec-chalbroker.osiris.cyber.nyu.edu 7332`
Lore: DaVinci Code
Flag: `flag{str1PP3d_B1N4R135_r_S0o0_much_FUN_408012}`
## Details
First run:
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
Look in Ghidra, none of our functions have names...yay
![[Pasted image 20240219130434.png]]

Sometimes using other tools is okay: Binary Ninja will show a `main` and a `_start`
![[Pasted image 20240219142123.png]]

What does main look like:

![[Pasted image 20240219172939.png]]
We've got our three questions (highlighted), it fails if any of them return something < 0

Finding things in Ghidra without symbols
Even though no symbols, we know it calls `__libc_start_main` because I can see it using `strings`
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
So that makes `FUN_00101930` Our main method, gonna rename it
Main in ghidra
```c
undefined8 hrc_main(void)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  long in_FS_OFFSET;
  long local_10;

  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  hrc_overwrite(&DAT_00104040,0,0x100);
  hrc_overwrite(&DAT_00104240,0,0x20);
  hrc_overwrite(&DAT_00104140,0,0x100);

  //Prints the greeting message
  uVar1 = get_Length(&local_1b8);
  hrc_write(1,&local_1b8,uVar1);
 
  iVar2 = Question1();
  if (((iVar2 < 0) || (iVar2 = Question2(), iVar2 < 0)) || (uVar1 = Question3(), iVar2 < 0)) {
    //Prints the "Oh no!" message
    uVar1 = get_Length(&local_c8);
    hrc_write(1,&local_c8,uVar1);
    uVar1 = get_Length(&local_168);
    hrc_write(1,&local_168,uVar1);
  }
  else {
    // Prints message and tries to open file
    uVar3 = get_Length(&local_c8);
    hrc_write(1,&local_c8,uVar3);
    uVar3 = get_Length(&DAT_00104140);
    hrc_write(uVar1,&DAT_00104140,uVar3);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
```

We can also use this information to figure out where Main and other locations are using the debugger
Main Location
![[Pasted image 20240220134351.png]]

Find entry point (after running)
```
gdb ./hand_rolled_cryptex
...omitted for brevity...
Oh no! That input broke the vial of vinegar, ruining
the papyrus scroll with the flag!
[Inferior 1 (process 3736152) exited normally]
(gdb) info file
Symbols from "/home/kali/Desktop/3-Week/hand_rolled_cryptex".
Local exec file:
        `/home/kali/Desktop/3-Week/hand_rolled_cryptex', file type elf64-x86-64.
        Entry point: 0x555555555080
```
Set break at entry then look at process map to find start address
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ gdb ./hand_rolled_cryptex
(gdb) break *0x555555555080
...omitted for brevity...
Breakpoint 1, 0x0000555555555080 in ?? ()
(gdb) info proc map
process 100090
Mapped address spaces:

          Start Addr           End Addr       Size     Offset  Perms  objfile
      0x555555554000     0x555555555000     0x1000        0x0  r--p   
```
Main method location Math
```
[Start Address] + [Main Method Offst]
555555554000 + 1930 = 555555555930
```

Now we know how to do that, we can continue.
### Question 1
```c

undefined4 Question1(void)

{
  undefined4 uVar1;
  int iVar2;
  long local_10;
  
  // Print question 1 message and store answer
  uVar1 = get_Length(&local_48);
  hrc_write(1,&local_48,uVar1);
  iVar2 = hrc_read(0,&readData,0x100);
  if (iVar2 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((&readData)[iVar2 - 1] == '\n') {
      (&readData)[iVar2 - 1] = 0;
    }
    hrc_copy(&storedData,&readData,0x20);
    hrc_overwrite(&readDat,0,0x100);
    local_4d = 0x203e200a;
    local_49 = 0;
    // Print ">" for next answer
    uVar1 = get_Length(&local_4d);
    hrc_write(1,&local_4d,uVar1);
    iVar2 = hrc_read(0,&DAT_00104040,0x100);
    if (iVar2 == 0) {
      uVar1 = 0xffffffff;
    }
    else {
      iVar2 = FUN_001013cf((int)DAT_00104040);
      if (iVar2 == -1) {
        uVar1 = 0xffffffff;
      }
      else {
	    // Print question 1 message and store answer
        DAT_00104010 = hrc_open(&DAT_00104240,iVar2);
        hrc_overwrite(&DAT_00104240,0,0x20);
        hrc_overwrite(&DAT_00104040,0,0x100);
        uVar1 = DAT_00104010;
      }
    }
  }
```

Takes in user entered data, saves it, takes a second piece of data, saves it, and then opens a file specified in the first user string.
First parameter must point to a valid file
Second parameter seems like it's just a number
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

### Question 2
Question 2 takes in one number and then performs operations
Image from Binary Ninja
![[Pasted image 20240219173111.png]]
Simplified code:
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

Reads in a number, performs XOR with 0xc9 and uses that value in a read call as the file descriptor
Assumed FD should be 0 because of previous calls

This time shown in Ghidra
```c
iVar2 = hrc_read(0,&DAT_00104040,0x100);
// ...omitted for brevity...
else {
	uVar1 = hrc_read(~DAT_00104040 ^ 0xc9,&DAT_00104140,0x100);
	hrc_overwrite(&DAT_00104040,0,0x100);
}
```

Solver for 0:
```python
def question2():
	s = Solver()
	a = BitVec('a',4)
	s.add(~(a) ^ 0xc9 == 0)
	print(s.check())
	print(s.model())
 
>> sat
>> [a = 6]
```

But that answer was not correct...heck

Eventually went and found what data Q1 returns by setting a breakpoint after the call to it
![[Pasted image 20240220135039.png]]

Console:
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ gdb ./hand_rolled_cryptex
(gdb) break *0x555555555C08
...omitted for brevity...
The first round requires two inputs...
 > ./test.txt
 > 13
Breakpoint 2, 0x0000555555555c08 in ?? ()
(gdb) info registers rax
rax            0x3                 3
```
It was a 3 .... wild

Rerunning the solver gets me a 5, which only worked once I input a 0. I think this value is the one that somehow ends up as the file descriptor?
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
 > 0
*The first chamber opened! Ok, the second phase requires a single input...
 > 5
Nice, the second chamber opened! Ok, the final level requires another single input...
```

### Question 3
Attempt looks like:
```
Nice, the second chamber opened! Ok, the final level requires another single input...
 > 13

The final chamber opened, but a flaw in the design
popped a vinegar vial which started to eat away at the papyrus
scroll inside. You hold it up, trying to decipher the text... [Inferior 1 (process 107790) exited normally]
```

So looking at our main methods, it looks like it TRIES to print the value after the message, using it's read method
![[Pasted image 20240220141904.png]]
And in our Q1, we see that's where the filename was saved
![[Pasted image 20240220142008.png]]

##### Full Code for appendix:
```c
undefined4 Question3(void)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  int guess_Q3;
  // Print question
  uVar1 = get_Length(&local_78);
  hrc_write(1,&local_78,uVar1);
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

##### Looking at the question
It makes a couple of checks based on the input, first, 
Then starts checks against the input if it's less than 0 or == 1, set return variable to failure
```c
guess_Q3 = (int)DAT_00104040;
if (guess_Q3 == 1) {
  uVar1 = 0xffffffff;
}
else if (guess_Q3 < 0) {
  uVar1 = 0xffffffff;
}
```
Next if statement, and then it gets complicated at the else
```c
if (guess_Q3 == 2) {
	local_90 = get_Length(&guess_Q3);
	uVar1 = local_90;
} else {
```
The statement `guess_Q3 = (int)DAT_00104040;` sets the value to the ascii value of the first character in the entered text
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ gdb ./hand_rolled_cryptex
(gdb) break *0x55555555586d
Breakpoint 1 at 0x55555555586d
...omitted for brevity...
Nice, the second chamber opened! Ok, the final level requires another single input...
 > 2
Breakpoint 1, 0x000055555555586d in ?? ()
(gdb) info registers eax
eax            0x32                50
...omitted for brevity...
[Inferior 1 (process 354433) exited normally]

(gdb) r
...omitted for brevity...
Nice, the second chamber opened! Ok, the final level requires another single input...
 > 1234
Breakpoint 1, 0x000055555555586d in ?? ()
(gdb) info registers eax
eax            0x31                49
```

Decided to fuzz input to determine which encoding of 2 would work. Fuzz function sets up breakpoint then loops through a list of potential encodings
```python
def runFuzz(p):
	fuzz = ['2','32','02','032','002','0032','%2','%32','%02','%032','x2','x32','x02','#x32','&#x32','\2','\32','\02','\\x2','\x32','\x02','0x2','0x32','0x02','\0x2','\0x32','\0x02']
	log = open("HRC_Q3_dbg.txt", "a")
	log.write("Hand Rolled Cryptex Q3 Debug Log:" + "\n")
	p.sendline('break *0x55555555586d')
	flag = -1
	i = 0
	for guess in fuzz:
		p.sendline('r')
		question1(p)
		question2(p)
		q3 = FuzzQ3(p, guess)
		p.sendline('c')
		reg = re.split("\s+", q3)
		if(reg[3] == '2'):
			print("Correct Answer Found")
			log.write("Valid Answer!\n")
			log.write("Guess at index " + str(i) + "= "+ guess + "\n" + q3)
			p.recvuntil(b'flag')
			flag = cleanLine(p.recvline())
		else:
			p.recvuntil("(gdb)")
		i += 1
	return flag

def main():
	# Start gdb session
	p =  process('/bin/bash')
	p.sendline('gdb ./hand_rolled_cryptex -q')
	print(runFuzz(p))

```
With each new guess it runs the program and sends the correct answers until question 3 when it calls the `FuzzQ3` function to send the guess
```python
def FuzzQ3(p, ans):
	p.recvuntil(b'>')
	p.sendline(ans.encode())
	p.recvuntil("Breakpoint")
	p.recvline()
	p.sendline("info registers eax")
	return(cleanLine(p.recvline()))
```
Then runFuzz checks the EAX value returned by the fuzzq3 method
If it is equal to two, the correct answer is logged and the function stores the flag
Otherwise, it waits for the program to end before running it again.
Running locally, we can see the value I stored in flag.txt
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
However, the encoded data wouldn't actually print, which is why the code returned the index
These are the correct values
```
'\2', '\02', '\x02'
```
This makes sense because they are equal to the ASCII encoding for 2. Could not be sent as stdin bc it will encode each character, but this sends the individual byte of "2"
## Solving
New solver script for remote challenge
Calls each question after starting the remote connection
```python
def main():
	# Start remote session
	p = remote(HOST, PORT)
	print(p.recvline())
	print(question1(p))
	print(question2(p))
	print(question3(p))
	# Close remote session
	p.close()
```
Each question sends the respective answer and returns the response. Question 3 waits for the flag data
```python
def question1(p):
	p.recvuntil(b'>')
	ans = "./flag.txt"
	p.sendline(ans.encode())
	p.recvuntil(b'>')
	ans = "0"
	p.sendline(ans.encode())
	return(cleanLine(p.recvline()))

def question2(p):
	p.recvuntil(b'>')
	ans = "5"
	p.sendline(ans.encode())
	return(cleanLine(p.recvline()))
 
def question3(p):
	p.recvuntil(b'>')
	ans = "\x02"
	p.sendline(ans.encode())
	p.recvuntil(b'flag')
	return(cleanLine(p.recvline()))
```
Running it gets us our flag:
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