WRiteup for [[Bridge of Death]]
## Heading Info
150 Points
Flag: `flag{@_W1tch_W3'v3_G0t_@_W1tch!!!!!!!!!}`
Location: `nc offsec-chalbroker.osiris.cyber.nyu.edu 8005`
Lore:
	Monty Python Reference, challenge and response
## Overview
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
### Main Method:
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
## Question 1
```
strings bridge_of_death| grep -i "Lancelot"
strings bridge_of_death| grep -i "Lancelot"
My name is Sir Lancelot of Camelot.
```
### Code:
```python
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

Can put in anything in for some reason
```
nc offsec-chalbroker.osiris.cyber.nyu.edu 8005
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.

What is your name?
My name is Sir Lancelot of Camelot.
What is your quest?
...omitted for brevity...

nc offsec-chalbroker.osiris.cyber.nyu.edu 8005
Stop! Who would cross the Bridge of Death must answer me these questions three, ere the other side he see.
What is your name?
Juneau
What is your quest?

```
## Question 2
This one is a a bit trickier
### Code
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
Two calls to get number, which is very similar to the function is Strops (put Strops in appendix)
Takes in a number, will return 0 if the number isn't a valid int ...etc
Then it calls `func2` and checks to see if the return value == guess 2
### `func2`
```c
int func2(int p1,int p2,int p3)
{
  int v1;
  int v2;
  
  puts("kek");
  v1 = p2 + (p3 - p2) / 2;
  if (p1 < v1) {
    v2 = func2(p1,p2,v1 + -1);
    v1 = v2 + v1;
  }
  else if (v1 < p1) {
    v2 = func2(p1,v1 + 1,p3);
    v1 = v2 + v1;
  }
  return v1;
}
```
Recursing is a red herring.
If  `p1 == p2 + (p3 - p2) / 2` then we return that value
Use a solver to figure out what values will make that equal with the input we have
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

So guess 10, 10
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
This one made me question my whole life istg
### Code:
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
Meat is in that if statement, simplified below:
```c
if (counter != forestOfEwing[)guess2 + guess1 * 0x100]) {
  flag = 1;
  goto LAB_0010159d;
}
```
At each iteration of the loop, it compares 
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

```
gdb ./bridge_of_death
(gdb) break *0x000055555555555e 
Breakpoint 2 at 0x55555555555e
(gdb) break *0x0000555555555565
Breakpoint 3 at 0x555555555565
(gdb) break *0x0000555555555568
Breakpoint 4 at 0x555555555568
(gdb) c
...omitted for brevity...
What is the air-speed velocity of an unladen swallow?
1
2

...omitted for brevity...
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
...omitted for brevity...
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




```
MOVZX EAX,byte ptr [RAX]
```


```python
def question3(p):
	i = 0
	index = [[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0],[0,0]]
	for value in f0e:
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
	i = 0
	while i < 9:
		msg = str(index[i][0]).encode()
		p.sendline(msg)
		msg = str(index[i][1]).encode()
		p.sendline(msg)
		i += 1
	return index
```

```bash
python3 Q3-search.py
[[64, 234], [4, 44], [132, 146], [14, 148], [41, 138], [170, 133], [173, 99], [12, 9], [73, 199]]
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
