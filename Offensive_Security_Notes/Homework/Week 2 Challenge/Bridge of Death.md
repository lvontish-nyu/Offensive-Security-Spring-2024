150 Points
Flag: `flag{@_W1tch_W3'v3_G0t_@_W1tch!!!!!!!!!}`
Location: `nc offsec-chalbroker.osiris.cyber.nyu.edu 8005`
Lore:
	Monty Python Reference, challenge and response

Challenge prompt:
![[Pasted image 20240211145228.png]]
### First Run (I fell to my death)
```
gdb ./bridge_of_death 
...omitted for brevity...
Reading symbols from ./bridge_of_death...
(No debugging symbols found in ./bridge_of_death)
(gdb) r
Starting program: /home/kali/Desktop/2-Week/bridge_of_death 
What is your name?
Juneau
What is your quest?
Pass this class!

kek
kek
kek
kek
Auuuuuuuugh!
[Inferior 1 (process 5082) exited normally]
(gdb) q
```
# Ghidra
## Main Method:
```c
undefined8 main(EVP_PKEY_CTX *param_1)
{
  int iVar1;
  
  init(param_1);
  puts(
      "Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other  side he see.\n\nWhat is your name?"
      );
  iVar1 = question1();
  if (iVar1 == 0) {
    throw_into_gorge_of_eternal_peril();
  }
  puts("What is your quest?");
  iVar1 = question2();
  if (iVar1 != 0) {
    throw_into_gorge_of_eternal_peril();
  }
  puts("What is the air-speed velocity of an unladen swallow?");
  iVar1 = question3();
  if (iVar1 != 0) {
    throw_into_gorge_of_eternal_peril();
  }
  puts("Right. Off you go.");
  print_flag();
  return 0;
}
```

Calls each question method, which I assume return a book based on whether it was correct.
	Opposite response for the first question

## Questions
### `question1()`
#### Code:
```c
void question1(void)
{
  long in_FS_OFFSET;
  char guess [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(guess,0x80,stdin);
  strcmp("My name is Sir Lancelot of Camelot.",guess);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
So for question 1 we can just put in something that is not `My name is Sir Lancelot of Camelot.`
Yay
Doesn't return anything itself because result of `strcmp()` is going to be in the `RAX` register
### `question2()`
This one is harder
#### Code:
```c
bool question2(void)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = get_number();
  iVar2 = get_number();
  iVar3 = func2(uVar1,0,0x14);
  return iVar2 != iVar3;
}
```

Calls `get_number()` twice
#### `get_number()`
```c
void get_number(void)
{
  long in_FS_OFFSET;
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  fgets(local_98,0x80,stdin);
  strtol(local_98,(char **)0x0,10);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
So this will return a number, or a 0 if the entered string isn't a number
Not sure why it's being called twice tbh

Then it calls `fun2`
#### `fun2()`
```c
int func2(int param_1,int param_2,int param_3)
{
  int iVar1;
  int iVar2;
  
  puts("kek");
  iVar1 = param_2 + (param_3 - param_2) / 2;
  if (param_1 < iVar1) {
    iVar2 = func2(param_1,param_2,iVar1 + -1);
    iVar1 = iVar2 + iVar1;
  }
  else if (iVar1 < param_1) {
    iVar2 = func2(param_1,iVar1 + 1,param_3);
    iVar1 = iVar2 + iVar1;
  }
  return iVar1;
}
```
We're gonna want to take a look at this with a solver I think
### `question3()`
```c
Too much code
```

# Solvering
## Question 2
#### Code:
```c
bool question2(void)

{
  undefined4 guess1;
  int guess2;
  int f;
  
  guess1 = get_number();
  guess2 = get_number();
  f = func2(guess1,0,0x14);
  return guess2 != f;
}
```
### `fun_2()`
Python Interpretation: ( had this wrong so now I basically have to start again)
```python
def fun2(p1, p2, p3):
	v1 = p2 + (p3 - p2)/2
	if p1 < v1:
		v2 = fun2(p1, p2, v1 -1)
		v1 = v2 + v1
	elif v1 < p1:
		v2 = fun2(p1, v1, p3)
		v1 = v2 + v1
	return v1
```
To keep recursing, `a` must be less than `b + (c-b)/2`
```python
a = Int('a')
b, c = Reals('b, c')
s = Solver()
s.add(b == 0)
s.add(c == 20)
s.add(a < b + (c-b)/2)
print(s.check())
print(s.model())

>> sat
>> [a = 0, c = 20, b, = 0]
```
And to return, they must be equal
```python
a = Int('a')
b, c = Reals('b, c')
#g = Int('g')
s = Solver()
s.add(b == 0)
s.add(c == 20)
s.add(a == b + (c-b)/2)
print(s.check())
print(s.model())

>> sat
>> [a = 10, c = 20, b, = 0]
```

Yay, `10 10` works as a guess!
```
What is your name?
Juneau
What is your quest?
10
10
kek
What is the air-speed velocity of an unladen swallow?
I have no clue

Auuuuuuuugh!
```

## Question 3
#### Code:
```c
undefined8 question3(void)

{
  long lVar1;
  uint guess1;
  uint guess2;
  undefined8 uVar4;
  long in_FS_OFFSET;
  int local_a4;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  local_a4 = 1;
  do {
    if (9 < local_a4) {
      uVar4 = 0;
LAB_0010159d:
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return uVar4;
    }
    guess1 = get_number();
    guess2 = get_number();
    if ((0xff < guess1) || (0xff < guess2)) {
      uVar4 = 1;
      goto LAB_0010159d;
    }
    if (local_a4 != (char)forestOfEwing[(ulong)guess2 + (ulong)guess1 * 0x100]) {
      uVar4 = 1;
      goto LAB_0010159d;
    }
    local_a4 = local_a4 + 1;
  } while( true );
}
```

#### Nicer Code:
```c
undefined8 question3(void)

{
  long lVar1;
  uint guess1;
  uint guess2;
  undefined8 flag;
  long in_FS_OFFSET;
  int counter;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  counter = 1;
  do {
    if (9 < counter) {
      flag = 0;
LAB_0010159d:
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return flag;
    }
    guess1 = get_number();
    guess2 = get_number();
    if ((0xff < guess1) || (0xff < guess2)) {
      flag = 1;
      goto LAB_0010159d;
    }
    if (counter != (char)forestOfEwing[(ulong)guess2 + (ulong)guess1 * 0x100]) {
      flag = 1;
      goto LAB_0010159d;
    }
    counter = counter + 1;
  } while( true );
}
```

Gets two numbers, `guess1` and `guess2`
It seems like either if condition will get us a success
So guess 1 or two can be greater than 255?
The goto should mean we don't have to worry about the second and more confusing condition....this does not seem right (It was not)
```
What is the air-speed velocity of an unladen swallow?
270
3
Auuuuuuuugh!
```
I am confused as to what is causing the fail. I feel like it keeps calling get number if the counter is less than 9. Oh, we WANT this one to return 0

So this one is going to be a lot like [[Strops]]
```c
if (counter != (char)forestOfEwing[(ulong)guess2 + (ulong)guess1 * 0x100]) {
  flag = 1;
  goto LAB_0010159d;
}
```
At each iteration of the loop, it compares the counter to a character stored...somewhere. And those guesses help determine the location of that character

Char location = `guess1 + guess2 * 0x100` (Oh boy...how do the order of operations play out here)
Here's the assembly that makes up this if statement
```
MOV        EDX,dword ptr [RBP + local_9c]
MOV        EAX,dword ptr [RBP + local_a0]
SHL        RAX,0x8
ADD        RDX,RAX
LEA        RAX,[forestOfEwing]
ADD        RAX,RDX
MOVZX      EAX,byte ptr [RAX]=>forestOfEwing
MOVSX      EAX,AL
CMP        dword ptr [RBP + local_a4],EAX
JZ         LAB_00101584
```
### Assembly Walkthrough
Now I also have it from EDB
Okay, looking at this in edb kinda helps because it shows some of these offsets better
![[Pasted image 20240212122405.png]]
##### 1) `MOV EDX,dword ptr [RBP + local_9c]`
This puts the dword value at `[RBP + local_9c]` in the `EDX` register
rbp - 0x94
##### 2) `MOV EAX,dword ptr [RBP + local_a0]]`
puts the dword value at `[RBP + local_a0]` in `EAX`, which is where the guess should be
rbp - 0x98
##### 3) `SHL RAX,0x8`
Shifts the value in `RAX` left by two bits
#### 4) `ADD RDX,RAX`
Adds the values of `RAX` and `RDX` and stores them in `RDX`
##### 5) `LEA RAX,[forestOfEwing]`
Loads whatever is in `[forestOfEwing]` into the `RAX` register
##### 6) `ADD RAX,RDX`
Ads the values of `rax` and `rdx` then saves in `rax`
##### 7) `MOVZX EAX,byte ptr [RAX]=>forestOfEwing`
Copies the first byte from wherever `RAX` is pointing into `EAX`?
Then "zero extends" so fills in all leading space with 0's
##### 8) `MOVZX EAX,AL`
Moves the lower `8` bits of `EAX` into `EAX` again
##### 9) `CMP dword ptr [RBP + local_a4],EAX`
Compares the double word at `[RBP + counter]` to the value of `eax`

So everything in the registers is zeroed-out until after move 5, when data is moved into rax
```
(gdb) info registers rax
rax            0x555555558020      93824992247840
```
But somehow EAX got a value?
but it was zeroed out again by line 8,q


Before first one
![[Pasted image 20240212122710.png]]
![[Pasted image 20240212122741.png]]
Before second
![[Pasted image 20240212122839.png]]
![[Pasted image 20240212122851.png]]

Third:
![[Pasted image 20240212122925.png]]
![[Pasted image 20240212122944.png]]
And `rdx` now equals 0x00000101

Fourth:
![[Pasted image 20240212123110.png]]
And RAX is now 
![[Pasted image 20240212123157.png]]

Fifth
![[Pasted image 20240212123217.png]]
And RAX is now 0x000055b57e64b121

Sixth
![[Pasted image 20240212123321.png]]
Eax is now 0

Seventh
![[Pasted image 20240212123402.png]]


Damn and then I DIDIN'T SEE THE COMPARE
Right before compare for another one where I entered 1 and 10
![[Pasted image 20240212132057.png]]


Hmm


(gdb) break *0x000055555555554b
Breakpoint 2 at 0x55555555554b
(gdb) break *0x0000555555555551
Breakpoint 3 at 0x555555555551
(gdb) break *0x0000555555555557
Breakpoint 4 at 0x555555555557
(gdb) break *0x000055555555555b
Breakpoint 5 at 0x55555555555b
(gdb) break *0x000055555555555e
Breakpoint 6 at 0x55555555555e
(gdb) break *0x0000555555555565
Breakpoint 7 at 0x555555555565
(gdb) break *0x0000555555555568
Breakpoint 8 at 0x555555555568
(gdb) break *0x000055555555556b
Breakpoint 9 at 0x55555555556b
(gdb) break *0x000055555555556e
Breakpoint 10 at 0x55555555556e
(gdb) break *0x0000555555555574
Breakpoint 11 at 0x555555555574



```
   0x000055555555554b <+98>:    mov    -0x94(%rbp),%edx
   0x0000555555555551 <+104>:   mov    -0x98(%rbp),%eax
   0x0000555555555557 <+110>:   shl    $0x8,%rax
   0x000055555555555b <+114>:   add    %rax,%rdx
   0x000055555555555e <+117>:   lea    0x2abb(%rip),%rax #0x555555558020 <forestOfEwing>
   0x0000555555555565 <+124>:   add    %rdx,%rax
   0x0000555555555568 <+127>:   movzbl (%rax),%eax
   0x000055555555556b <+130>:   movsbl %al,%eax
   0x000055555555556e <+133>:   cmp    %eax,-0x9c(%rbp)
   0x0000555555555574 <+139>:   je     0x555555555584 <question3+155>

```

Does the location it pulls from work every time?
0x561a107ea020



It seems like the good ol' copy and paste did not work for me this tiem
```
(gdb) break *0x000055555555556e
Breakpoint 1 at 0x55555555556e
(gdb) r
Starting program: /home/kali/Desktop/2-Week/bridge_of_death 
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.

What is your name?
Juneau
What is your quest?
10
10
kek
What is the air-speed velocity of an unladen swallow?
20
20

Breakpoint 1, 0x000055555555556e in question3 ()
(gdb) info registers rax
rax            0x0                 0
(gdb) info registers rdx
rdx            0x1414              5140
(gdb) info registers eax
eax            0x0                 0
(gdb) info refisters edx
Undefined info command: "refisters edx".  Try "help info".
(gdb) info registers edx
edx            0x1414              5140
(gdb) p $rbp-0x9c
$1 = (void *) 0x7fffffffdd24
(gdb) set $eax = $rbp-0x9c
(gdb) info registers rax
rax            0xffffdd24          4294958372
(gdb) info registers rdx
rdx            0x1414              5140
(gdb) info registers eax
eax            0xffffdd24          -8924
(gdb) info registers edx
edx            0x1414              5140
(gdb) c
Continuing.
Auuuuuuuugh!
[Inferior 1 (process 198272) exited normally]
(gdb) 

```


Oh right, because that's the pointer, so I bet if I set it to the value at that location maybe

Well, I got a continue!

So doing `set $eax = *0x7fffffffdd24` every time will do it, but that doesn't ACTUALLY help me yet


So 

RAX
Gets second guess
Shifts left by 0x8

Then that value is added to the guess 1 (which is stored in RDX) and saved in RDX

So it brings in the memory location of the answer, I think
They add the value of RDX/EDX to both RAX and RDX

Then I THINK it moves the first byte at that memory location

So I think at that point, we want the value of RAX to be the same as the location


So
(b << 0x8)+a+MEM SHOULD EQUAL 0x7fffffffdd2?

```
0x7fffffffdd2 == 8796093021650
(b << 0x8) + a + 93824992222496 = 8796093021650
```


```
   0x000055555555554b <+98>:    mov    -0x94(%rbp),%edx
   0x0000555555555551 <+104>:   mov    -0x98(%rbp),%eax
   0x0000555555555557 <+110>:   shl    $0x8,%rax
   0x000055555555555b <+114>:   add    %rax,%rdx
   0x000055555555555e <+117>:   lea    0x2abb(%rip),%rax #0x555555558020 <forestOfEwing>
   0x0000555555555565 <+124>:   add    %rdx,%rax
   0x0000555555555568 <+127>:   movzbl (%rax),%eax
   0x000055555555556b <+130>:   movsbl %al,%eax
   0x000055555555556e <+133>:   cmp    %eax,-0x9c(%rbp)
   0x0000555555555574 <+139>:   je     0x555555555584 <question3+155>

```

`0x000055555555554b` is gonna put guess 2 into edx
`0x0000555555555551` puts guess 1 in eax
`0x0000555555555557` performs a shift and shifts the value in rax by 0x8
`0x000055555555555b` Will add that value in `RAX` to the value in `RDX` (guess 2) and save it in `rdx`
`0x000055555555555e` Puts the address `0x000055b57e64b121` in `rax`?
`0x0000555555555565` Ads `RDX `to the address value stored in `rax`
`0x0000555555555568` Moves the value in the address `RAX` has into `eax`


So I think
```
edx = b
eax = a

(somehow also)
rdx = b
rax = a

rax = (a << 8)
rdx = rdx + rax = b + (a << 8)

rax = 0x000055b57e64b121
rax = rax + rdx = 0x000055b57e64b121 + (b + (a << 8))

and then the value at the location specified there is our character
```
So
```
b + (a << 8) = SOMETHING
```


I think it will need to be equal to that -0x9c(%rbp) location maybe????

at the time of the compare, `rbp` = `0x0007ffe2e6d6460
![[Pasted image 20240212160206.png]]

So
```
0x0007ffe2e6d6460 - 0x9c
140729677341792 - 156
= 7FFE2E6D63C4
```
Therefore
```
b + (a << 8) = 7FFE2E6D63C4 = 140729677341636
```


Looking in memory
It looks like `0x0007ffe2e6d6460` is holding another address
![[Pasted image 20240212160634.png]]
There doesn't seem to be anything at `7FFE2E6D63C4` though


Although, this is the info edb has
![[Pasted image 20240212161001.png]]
So rather, I think we actually know it needs to equal `0x00007ffe2e6d63c4`, which is what I got in my calculations too

So now to see if there is a good solver solution?

Well this gets us an answer but it isn't correct:
```python
a, b = BitVecs('a b', 16)
#x = BitVec(a, 16)

s = Solver()
s.add(a < 0xff)
s.add(b < 0xff)

s.add(b + (a << 0x8) == 0x00007ffe2e6d63c4)

print(s.check())
print(s.model())

>> sat
>> [a = 99, b = 196]
```
And those values did not work



So I think I had rax and edx backwards here


```
   0x000055555555554b <+98>:    mov    -0x94(%rbp),%edx
   0x0000555555555551 <+104>:   mov    -0x98(%rbp),%eax
   0x0000555555555557 <+110>:   shl    $0x8,%rax
   0x000055555555555b <+114>:   add    %rax,%rdx
   0x000055555555555e <+117>:   lea    0x2abb(%rip),%rax #0x555555558020 <forestOfEwing>
   0x0000555555555565 <+124>:   add    %rdx,%rax
   0x0000555555555568 <+127>:   movzbl (%rax),%eax
   0x000055555555556b <+130>:   movsbl %al,%eax
   0x000055555555556e <+133>:   cmp    %eax,-0x9c(%rbp)
   0x0000555555555574 <+139>:   je     0x555555555584 <question3+155>

```

`0x000055555555554b` is gonna put guess1 into edx
`0x0000555555555551` puts guess2 in eax
`0x0000555555555557` performs a shift and shifts the value in rax by 0x8
`0x000055555555555b` Will add that value in `RAX` to the value in `RDX` (guess 2) and save it in `rdx`
`0x000055555555555e` Puts the address of `forestOfEwig` in `rax`? (which is saved in RIP)
`0x0000555555555565` Ads `RDX `to the address value stored in `rax`
`0x0000555555555568` Moves the value in the address `RAX` has into `eax`

```
eax = b
edx = a

(somehow also)
rax = b
rdx = a

rax = (b << 8)
rdx = rdx + rax = b + (a << 8)

rax = 0x000055b57e64b121
rax = rax + rdx = 0x000055b57e64b121 + (b + (a << 8))

and then the value at the location specified there is our character
```

With 99 and 196 respectively we end up with 0x0000564c4a2363e4
And it looks like the real address is somehow 0x00007fffd6714114
So this is somehow a completely different address
Does it change every time?


SO if we put in 196 and 99 respectively
	We point to 0x00005616c1bcb483 in RAX when we move it into eax
	Our address is 0x00007ffe3b3c8074
Something is causing that address to change
I guess it's just the stack size maybe but....grrrr



So guess 1 is stored in `[RBP + dWord2]`
guess 2 is stored in `[RBP + dWord1]`
So they're all stored so close to each other


Right, because this is the counter
`forestOfEwing[a + b * 0x100]` must equal the counter
So if I can set `rax` at the address of the counter `RBP + counter` then it should work
but RBP changes every time

It kind of seems like forest of ewig is an array of 0's
![[Pasted image 20240213141211.png]]

So
`RAX` = `[forestOfEwig] +(b + (a << 8))`
So if I 


![[Pasted image 20240213142332.png]]
Old

So in this example
```
(gdb) p $rbp
$1 = (void *) 0x7fffffffddc0
(gdb) p $rbp-0x9c
$2 = (void *) 0x7fffffffdd24
```

it's set at `0x7fffffffddd0` right before question 3
```
Breakpoint 2, 0x0000555555555627 in main ()
(gdb) p $rbp
$2 = (void *) 0x7fffffffddd0
```

Before question:
![[Pasted image 20240213144020.png]]


How do I figure out the offset from where the counter is stored `[rbp - 0x9c]` and where `[forestOfEwig]` starts `[rip + 0x2abb]`

I guess count here
In this iteration
![[Pasted image 20240213145006.png]]
`[rip + 0x2abb]` = `0x000055e3bd3cf020`
And at the `cmp`
`[rbp - 0x9c]` = `[0x00007ffde7282504]`
![[Pasted image 20240213145153.png]]

So
```
fOE = [rip + 0x2abb] = 0x000055e3bd3cf020 = 94436620824608
ans = [rbp - 0x9c] = 0x00007ffde7282504 = 140728481621252

offset = ans - fOE = 140728481621252 - 94436620824608
offset = 46291860796644 = 2A1A29EB34E4
```

```
eax = b
edx = a

(somehow also)
rax = b
rdx = a

rax = (b << 8)
rdx = rdx + rax = a + (b << 8)

rax = fOE
rax = rax + rdx = fOE + a + (b << 8)

fOE + offset = ans
therefore
	if a + (b << 8) == offset
	We should be pointing it to the memory location of the answer
```

Solver time
	Couldn't get a working answer

Trying it with GDB because I trust it better
![[Pasted image 20240213151522.png]]
so the location is (I think) 0x555555558020

`rip` at start = `0x7ffff7fe5360`

Funny, a little off-by-1 issue here
Right before the FoE address is loaded into RAX, this is the value of rip and Foe location
```
Breakpoint 3, 0x000055555555555e in question3 ()
(gdb) p $rip
$4 = (void (*)()) 0x55555555555e <question3+117>
(gdb) p $rip+0x2abb
$5 = (void (*)()) 0x555555558019

```

In case it maters, I entered `1 2` for my numbers

But somehow, by the next break, it's all equal to `0x555555558020`
```
Breakpoint 5, 0x0000555555555565 in question3 ()
(gdb) info registers rax
rax            0x555555558020      93824992247840
(gdb) p $rax
$6 = 93824992247840
(gdb) p/x $rax
$7 = 0x555555558020
(gdb) p $rip+0x2abb
$8 = (void (*)()) 0x555555558020 <forestOfEwing>
(gdb) info registers rdx
rdx            0x102               258
```

`rdx = 102 = 100*a + b`

So the next move should add that to the value in `rax` and store it there
```
Breakpoint 6, 0x0000555555555568 in question3 ()
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) info registers rdx
rdx            0x102               258
```

And, at the compare
```
(gdb) info registers eax
eax            0x0                 0
(gdb) 
$9 = (void *) 0x7fffffffdd24
(gdb) x/s 0x7fffffffdd24
0x7fffffffdd24: "\001"

```

AND IT TREATS THAT 102 as a HEX value of 0x102

So math
```
fOE = [rip + 0x2abb] = 0x555555558020
ans = [rbp - 0x9c] = 0x7fffffffdd24

offset = ans - fOE = 0x7fffffffdd24 - 0x555555558020
	= 140737488346404 - 93824992247840
offset = 46912496098564 = 2AAAAAAA5D04
```

```
eax = b
edx = a

(somehow also)
rax = b
rdx = a

rax = (b << 8)
rdx = rdx + rax = a + (b << 8)

rax = fOE
rax = rax + rdx = fOE + a + (b << 8)

fOE + offset = ans
therefore
	if a + (b << 8) == offset
	We should be pointing it to the memory location of the answer
```

So setting the value of RAX to the value of rbp-0x9c works to get a continue
#### Long-ass output
```
gdb ./bridge_of_death

Starting program: /home/kali/Desktop/2-Week/bridge_of_death 

Breakpoint 1.2, 0x00007ffff7fe5360 in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) break *0x000055555555555e 
Breakpoint 2 at 0x55555555555e
(gdb) break *0x0000555555555565
Breakpoint 3 at 0x555555555565
(gdb) break *0x0000555555555568
Breakpoint 4 at 0x555555555568
(gdb) c
Continuing.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1.1, 0x0000555555555160 in _start ()
(gdb) c
Continuing.
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.

What is your name?
Juneau
What is your quest?
10
10
kek
What is the air-speed velocity of an unladen swallow?
1
2

Breakpoint 2, 0x000055555555555e in question3 ()
(gdb) info registers rdx
rdx            0x102               258
(gdb) $rip+0x2abb
Undefined command: "$rip+0x2abb".  Try "help".
(gdb) p $rip+0x2abb
$1 = (void (*)()) 0x555555558019
(gdb) x/s 0x555555558020
0x555555558020 <forestOfEwing>: ""
(gdb) x/s 0x555555558019
0x555555558019: ""
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555555565 in question3 ()
(gdb) info registers rdx
rdx            0x102               258
(gdb) info registers rax
rax            0x555555558020      93824992247840
(gdb) x/s 0x555555558020
0x555555558020 <forestOfEwing>: ""
(gdb) p 0x555555558020
$2 = 93824992247840
(gdb) p/x 0x555555558020
$3 = 0x555555558020
(gdb) p/x/s 0x555555558020
A syntax error in expression, near `/s 0x555555558020'.
(gdb) c
Continuing.

Breakpoint 4, 0x0000555555555568 in question3 ()
(gdb) info registers rdx
rdx            0x102               258
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) p/x 0x555555558122
$4 = 0x555555558122
(gdb) x/s 0x555555558122
0x555555558122 <forestOfEwing+258>:     ""
(gdb) p $rbp-0x9c
$5 = (void *) 0x7fffffffdd24
(gdb) set $rax $rbp-0x9c
A syntax error in expression, near `$rbp-0x9c'.
(gdb) set $rax=$rbp-0x9c
(gdb) info registers rax
rax            0x7fffffffdd24      140737488346404
(gdb) c
Continuing.
1
2

Breakpoint 2, 0x000055555555555e in question3 ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555555565 in question3 ()
(gdb) c
Continuing.

Breakpoint 4, 0x0000555555555568 in question3 ()
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) set $rax=$rbp-0x9c
(gdb) info registers rax
rax            0x7fffffffdd24      140737488346404
(gdb) c
Continuing.
1
2

Breakpoint 2, 0x000055555555555e in question3 ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555555565 in question3 ()
(gdb) c
Continuing.

Breakpoint 4, 0x0000555555555568 in question3 ()
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) set $rax=$rbp-0x9c
(gdb) info registers rax
rax            0x7fffffffdd24      140737488346404
(gdb) c
Continuing.
1
2

Breakpoint 2, 0x000055555555555e in question3 ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555555565 in question3 ()
(gdb) c
Continuing.

Breakpoint 4, 0x0000555555555568 in question3 ()
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) set $rax=$rbp-0x9c
(gdb) info registers rax
rax            0x7fffffffdd24      140737488346404
(gdb) c
Continuing.
1
2

Breakpoint 2, 0x000055555555555e in question3 ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555555565 in question3 ()
(gdb) c
Continuing.

Breakpoint 4, 0x0000555555555568 in question3 ()
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) set $rax=$rbp-0x9c
(gdb) info registers rax
rax            0x7fffffffdd24      140737488346404
(gdb) c
Continuing.
1
2

Breakpoint 2, 0x000055555555555e in question3 ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555555565 in question3 ()
(gdb) c
Continuing.

Breakpoint 4, 0x0000555555555568 in question3 ()
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) set $rax=$rbp-0x9c
(gdb) set $rax=$rbp-0x9c
(gdb) info registers rax
rax            0x7fffffffdd24      140737488346404
(gdb) c
Continuing.
1
2

Breakpoint 2, 0x000055555555555e in question3 ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555555565 in question3 ()
(gdb) c
Continuing.

Breakpoint 4, 0x0000555555555568 in question3 ()
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) set $rax=$rbp-0x9c
(gdb) info registers rax
rax            0x7fffffffdd24      140737488346404
(gdb) c
Continuing.
1
2

Breakpoint 2, 0x000055555555555e in question3 ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555555565 in question3 ()
(gdb) c
Continuing.

Breakpoint 4, 0x0000555555555568 in question3 ()
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) set $rax=$rbp-0x9c
(gdb) info registers rax
rax            0x7fffffffdd24      140737488346404
(gdb) c
Continuing.
1
2

Breakpoint 2, 0x000055555555555e in question3 ()
(gdb) c
Continuing.

Breakpoint 3, 0x0000555555555565 in question3 ()
(gdb) c
Continuing.

Breakpoint 4, 0x0000555555555568 in question3 ()
(gdb) info registers rax
rax            0x555555558122      93824992248098
(gdb) set $rax=$rbp-0x9c
(gdb) info registers rax
rax            0x7fffffffdd24      140737488346404
(gdb) c
Continuing.
Right. Off you go.
ERROR: no flag found. If you're getting this error on the remote system, please message the admins. If you're seeing this locally, run it on the remote system! You solved the challenge, and need to get the flag from there!

```

So the values of both addresses stay the same assuming you input the same things each iteration

```
a * 0x100 + b + F0E = location

Really though:
dec(hex(100*a + b)) = dec(offset)

1 and 2
	becomes 0x102
	then 258
	
The problem is, I feel like the offset is far too large to be able to use two numbers < 256 for


```

New Math
```
Hex value:  
7fffffffdd24 – 555555558020 = 2AAAAAAA5D04
So if A was 2AAAAAAA5D and b was 04. thhat would work BUT a > 0xff now
a + b
a = 256*x + 26*y + z
```


So what if I use my name to put the string 123456789 on the stack?
It's stored at `[RBP + local_10]` which is a quad word of length 8

# What if I save it where my name goes
0x7fffffffddb8 ....this is right next to where the counter is saved actually....grrrr

Wait no, it's `[rbp]-0x90` which is still `0x7fffffffdd30
This is the highest I can get with legal input
```
What is the air-speed velocity of an unladen swallow?
255
255

Breakpoint 2, 0x0000555555555568 in question3 ()
(gdb) info registers rdx
rdx            0xffff              65535
(gdb) info registers rax
rax            0x55555556801f      93824992313375
```

OH FUCK ME
The value are stored in the EoD array, there's just 99% 0's
so if I can find their locations, I should be golden

Silly script to find and locate the values i need
`a = i//256`
`b = i%256`
```python
eof = [0x00, 0x00, ...omitted for brevity]
i = 0
index = [[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]]
for value in eof:
	if value == 0x1:
		index[0][0] = i//256
		index[0][1] = i%256
	elif value == 0x2:
		index[1][0] = i//256
		index[1][1] = i%256
	elif value == 0x3:
		index[2][0] = i//256
		index[2][1] = i%256
	elif value == 0x4:
		index[3][0] = i//256
		index[3][1] = i%256
	elif value == 0x5:
		index[4][0] = i//256
		index[4][1] = i%256
	elif value == 0x6:
		index[5][0] = i//256
		index[5][1] = i%256
	elif value == 0x7:
		index[6][0] = i//256
		index[6][1] = i%256
	elif value == 0x8:
		index[7][0] = i//256
		index[7][1] = i%256
	elif value == 0x9:
		index[8][0] = i//256
		index[8][1] = i%256
	i +=1

print(index)
```
which gets us:
```bash
python3 list-lookup.py
[[64, 234], [4, 44], [132, 146], [14, 148], [41, 138], [170, 133], [173, 99], [12, 9], [73, 199]]
```

And then gets us:
```
gdb ./bridge_of_death
GNU gdb (Debian 13.2-1) 13.2
...omitted for brevity...
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.

What is your name?
l
What is your quest?
10
10
kek
What is the air-speed velocity of an unladen swallow?
64
234
4
44
132
146
14
148
41
138
170
133
173
99
12
9
73
199
Right. Off you go.
ERROR: no flag found. If you're getting this error on the remote system, please message the admins. If you're seeing this locally, run it on the remote system! You solved the challenge, and need to get the flag from there!
[Inferior 1 (process 614735) exited normally]

```


I WIN SCREW YOU ASSIGNMENT
```
└─$ nc offsec-chalbroker.osiris.cyber.nyu.edu 8005
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.

What is your name?
Juneau
What is your quest?
10
10
kek
What is the air-speed velocity of an unladen swallow?
64
234
4
44
132
146
14
148
41
138
170
133
173
99
12
9
73
199
Right. Off you go.
Here's your flag, friend: flag{@_W1tch_W3'v3_G0t_@_W1tch!!!!!!!!!}

```

```
python3 BoD_Remote.py 
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 8005: Done
Answering Question 1
/home/kali/Desktop/2-Week/BoD_Remote.py:23: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  p.sendline(msg)
Juneau
Answering Question 2
['10', '10']
Answering Question 3
[[64, 234], [4, 44], [132, 146], [14, 148], [41, 138], [170, 133], [173, 99], [12, 9], [73, 199]]
b"@_W1tch_W3'v3_G0t_@_W1tch!!!!!!!!!}\n"
[*] Closed connection to offsec-chalbroker.osiris.cyber.nyu.edu port 8005

```