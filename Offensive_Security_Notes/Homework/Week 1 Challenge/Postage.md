200 POints
Flag: `flag{i_hope_ur_ready_4_some_pwning_in_a_few_weeks}`


Main Method:
```
bool main(void)

{
  long lVar1;
  long *plVar2;
  
  init();
  puts(&UNK_00498118);
  plVar2 = (long *)get_number();
  lVar1 = *plVar2;
  if (lVar1 != 0xd000dfaceee) {
    puts(&UNK_00498170);
  }
  else {
    puts(&UNK_00498148);
    print_flag();
  }
  return lVar1 != 0xd000dfaceee;
}
```


It looks like, if I can set `lvar` to `0xd000dfaceee` if I find the right point to break
![[Pasted image 20240206093232.png]]

Find this compare and break


Okay that's weird, maybe it was still analyzing? Because NOW this is the main it has for me
```

bool main(EVP_PKEY_CTX *param_1)

{
  long lVar1;
  long *plVar2;
  
  init(param_1);
  puts("Can you tell me where to mail this postage?");
  plVar2 = (long *)get_number();
  lVar1 = *plVar2;
  if (lVar1 != 0xd000dfaceee) {
    puts("That doesn\'t look right... try again later, friend!");
  }
  else {
    puts("Got it! That\'s the right number!");
    print_flag();
  }
  return lVar1 != 0xd000dfaceee;
}
```


But it is still that line in memory


## Step 1
* start debugger
* Add break point
* disassemble main
* Find cmp for breakpoint
```
└─$ gdb ./postage                                           
GNU gdb (Debian 13.2-1) 13.2
	...omitted for brevity...
Reading symbols from ./postage...
(No debugging symbols found in ./postage)
(gdb) break _start
Breakpoint 1 at 0x4016c0
(gdb) r
Starting program: /home/kali/Desktop/1-Week/postage 

Breakpoint 1, 0x00000000004016c0 in _start ()
(gdb) disas main
Dump of assembler code for function main:
	...omitted for brevity...
   0x0000000000401961 <+66>:    movabs $0xd000dfaceee,%rdx
   0x000000000040196b <+76>:    cmp    %rdx,%rax
   0x000000000040196e <+79>:    jne    0x401990 <main+113>
	...omitted for brevity...
End of assembler dump.

```





Actually, I can just put the correct value in maybe
Using hex: `segfault`
```
└─$ gdb ./postage
GNU gdb (Debian 13.2-1) 13.2
	...omitted for brevity...
Reading symbols from ./postage...
(No debugging symbols found in ./postage)
(gdb) r
Starting program: /home/kali/Desktop/1-Week/postage 
Can you tell me where to mail this postage?
0xd000dfaceee

Program received signal SIGSEGV, Segmentation fault.
0x000000000040195e in main ()
(gdb) q
A debugging session is active.

        Inferior 1 [process 2128061] will be killed.

Quit anyway? (y or n) y

```

This is `14293885701870` in dec
Still a segfault! yay, back to the other way!

## Step 2
* Set breakpoint at `0x000000000040196b`
* remove breakpoint at start
* continue
* set $rax = $rddx
* continue

Wait, is any  input a segfault?!?!?


Okay, I think the segfault is at this line:
![[Pasted image 20240206101917.png]]

Which is here:
![[Pasted image 20240206101934.png]]


so breaking down that command
## `MOV RAX, qword ptr [RAX]`
### `MOV`
The opcode telling the CPU to copy data from the first operand to the second
### `RAX`
This is the location where the data will be saved
### `qword ptr [RAX]`
#### `qword`
Indicates a 'quad word' size address aka 8 bytes
#### `ptr`
Indicates that the next piece of data should be treated as an address
#### `[RAX]`
The address of the RAX register
Together with `ptr`, this indicates that the address is being "dereferenced," ie: the value is being used to calculate the target address
	So essentially, RAX should point to a memory structure of some sort

So ultimately, this operand is moving the first 8 bytes of data of the memory structure RAX is pointing to


So actually, now that I see that, I think I can break this part down a bit more
The five move commands here:
![[Pasted image 20240206103109.png]]
Really cover this whole line of code
![[Pasted image 20240206103207.png]]


So what is happening?!?
```
MOV qword ptr [RBP + local_18],RAX
MOV RAX,qword ptr [RBP + local_18]
MOV qword ptr [RBP + local_10],RAX
MOV RAX,qword ptr [RBP + local_10]
MOV RAX,qword ptr [RAX]
```

### `MOV qword ptr [RBP + local_18],RAX`
Moving the value at `RAX` into a *quadword* that starts `n` bits into the memory structure `RBP` points to
	Not sure what local 18 is in this case
### `MOV RAX,qword ptr [RBP + local_18]`
This seems to reverse the last move
Moves a *quadword* located `n` bits into the memory structure that `RBP` points to into `RAX`
### `MOV qword ptr [RBP + local_10],RAX`
Now we're doing the same silly switching around but with a slightly different offset
	Moving the value at `RAX` into a *quadword* that starts `m` bits into the memory structure `RBP` points to
### `MOV RAX,qword ptr [RBP + local_10]`
Reverse that
	Moves a *quadword* located `m` bits into the memory structure that `RBP` points to into `RAX`
Then once everything else is all confusing, we do our last move
### `MOV RAX,qword ptr [RAX]`
This still moves 8 bytes of data stored wherever `RAX` is pointing into RAX
and at this point, RAX should be storing 8 bytes of...maybe random data


Looking at it in gdb:
```
call   0x4018b7 <get_number>
mov    %rax,-0x10(%rbp)
mov    -0x10(%rbp),%rax
mov    %rax,-0x8(%rbp)
mov    -0x8(%rbp),%rax
mov    (%rax),%rax
movabs $0xd000dfaceee,%rdx
cmp    %rdx,%rax
```
Maybe this is a little clearer
Looks like local 18 is offset by 10 and local 10 is offset by 8?
Note, I think these are backwards from how they are in Ghidra...yay

Okay, I put a break at each of the lines:
```
$ gdb ./postage
GNU gdb (Debian 13.2-1) 13.2
	...omitted for brevity
Reading symbols from ./postage...
(No debugging symbols found in ./postage)
(gdb) break _start
Breakpoint 1 at 0x4016c0
(gdb) r
Starting program: /home/kali/Desktop/1-Week/postage 

Breakpoint 1, 0x00000000004016c0 in _start ()
(gdb) disas main
Dump of assembler code for function main:
(gdb) disas main
Dump of assembler code for function main:
   0x000000000040191f <+0>:     endbr64
   0x0000000000401923 <+4>:     push   %rbp
   0x0000000000401924 <+5>:     mov    %rsp,%rbp
   0x0000000000401927 <+8>:     sub    $0x10,%rsp
   0x000000000040192b <+12>:    mov    $0x0,%eax
   0x0000000000401930 <+17>:    call   0x40188e <init>
   0x0000000000401935 <+22>:    lea    0x967dc(%rip),%rax        # 0x498118
   0x000000000040193c <+29>:    mov    %rax,%rdi
   0x000000000040193f <+32>:    call   0x412c60 <puts>
   0x0000000000401944 <+37>:    mov    $0x0,%eax
   0x0000000000401949 <+42>:    call   0x4018b7 <get_number>
   0x000000000040194e <+47>:    mov    %rax,-0x10(%rbp)
   0x0000000000401952 <+51>:    mov    -0x10(%rbp),%rax
   0x0000000000401956 <+55>:    mov    %rax,-0x8(%rbp)
   0x000000000040195a <+59>:    mov    -0x8(%rbp),%rax
   0x000000000040195e <+63>:    mov    (%rax),%rax
   0x0000000000401961 <+66>:    movabs $0xd000dfaceee,%rdx
   0x000000000040196b <+76>:    cmp    %rdx,%rax
   0x000000000040196e <+79>:    jne    0x401990 <main+113>
   0x0000000000401970 <+81>:    lea    0x967d1(%rip),%rax        # 0x498148
   0x0000000000401977 <+88>:    mov    %rax,%rdi
   0x000000000040197a <+91>:    call   0x412c60 <puts>
   0x000000000040197f <+96>:    mov    $0x0,%eax
   0x0000000000401984 <+101>:   call   0x4017e5 <print_flag>
   0x0000000000401989 <+106>:   mov    $0x0,%eax
   0x000000000040198e <+111>:   jmp    0x4019a4 <main+133>
   0x0000000000401990 <+113>:   lea    0x967d9(%rip),%rax        # 0x498170
   0x0000000000401997 <+120>:   mov    %rax,%rdi
   0x000000000040199a <+123>:   call   0x412c60 <puts>
   0x000000000040199f <+128>:   mov    $0x1,%eax
   0x00000000004019a4 <+133>:   leave
   0x00000000004019a5 <+134>:   ret
End of assembler dump.
(gdb) break *0x000000000040194e
Breakpoint 2 at 0x40194e
(gdb) break *0x0000000000401952
Breakpoint 3 at 0x401952
(gdb) break *0x0000000000401956
Breakpoint 4 at 0x401956
(gdb) break *0x000000000040195a
Breakpoint 5 at 0x40195a
(gdb) break *0x000000000040195e
Breakpoint 6 at 0x40195e
(gdb) break *0x0000000000401961
Breakpoint 8 at 0x401961
(gdb) break *0x000000000040196b
Breakpoint 9 at 0x40196b
(gdb) break *0x0000000000401949
Breakpoint 10 at 0x401949
(gdb) info break
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x00000000004016c0 <_start>
        breakpoint already hit 1 time
2       breakpoint     keep y   0x000000000040194e <main+47>
3       breakpoint     keep y   0x0000000000401952 <main+51>
4       breakpoint     keep y   0x0000000000401956 <main+55>
5       breakpoint     keep y   0x000000000040195a <main+59>
6       breakpoint     keep y   0x000000000040195e <main+63>
8       breakpoint     keep y   0x0000000000401961 <main+66>
9       breakpoint     keep y   0x000000000040196b <main+76>
10      breakpoint     keep y   0x0000000000401949 <main+42>
```

| Breakpoint | Location | Line |
| ---- | ---- | ---- |
| 1 | Start | ` _start` |
| 2 | `MOV` 1 | `main+47` |
| 3 | `MOV` 2 | `main+51` |
| 4 | `MOV` 3 | `main+55` |
| 5 | `MOV` 4 | `main+59` |
| 6 | `MOV` 5 | `main+63` |
| 8 | `MOV RDX, 0xd00dfaceee` | `main+66` |
| 9 | `CMP RAX, RDX` | `main+76` |
| 10 | `CALL get_number` | `main+42` |

Run 1, didn't look at stack or anything:
```
(gdb) c
Continuing.
Can you tell me where to mail this postage?

Breakpoint 10, 0x0000000000401949 in main ()
(gdb) c
Continuing.
Breakpoint 2, 0x000000000040194e in main ()
(gdb) c
Continuing.
Breakpoint 3, 0x0000000000401952 in main ()
(gdb) c
Continuing.
Breakpoint 4, 0x0000000000401956 in main ()
(gdb) c
Continuing.
Breakpoint 5, 0x000000000040195a in main ()
(gdb) c
Continuing.
Breakpoint 6, 0x000000000040195e in main ()
(gdb) c
Continuing.
Program received signal SIGSEGV, Segmentation fault.
0x000000000040195e in main ()
(gdb) c
Continuing.
Program terminated with signal SIGSEGV, Segmentation fault.
The program no longer exists.
(gdb) q
```

So we got our `segfault` after breakpoint 6, which was expected

Now to look at all of the values at this point
I guess it's worth noting that in this one, I do actually have a break 7
```
Num     Type           Disp Enb Address            What
1       breakpoint     keep y   0x00000000004016c0 <_start>
        breakpoint already hit 1 time
2       breakpoint     keep y   0x000000000040194e <main+47>
3       breakpoint     keep y   0x0000000000401952 <main+51>
4       breakpoint     keep y   0x0000000000401956 <main+55>
5       breakpoint     keep y   0x000000000040195a <main+59>
6       breakpoint     keep y   0x000000000040195e <main+63>
7       breakpoint     keep y   0x0000000000401961 <main+66>
8       breakpoint     keep y   0x000000000040196b <main+76>
9       breakpoint     keep y   0x0000000000401949 <main+42>
```

| Breakpoint | Location | Line |
| ---- | ---- | ---- |
| 1 | Start | ` _start` |
| 2 | `MOV` 1 | `main+47` |
| 3 | `MOV` 2 | `main+51` |
| 4 | `MOV` 3 | `main+55` |
| 5 | `MOV` 4 | `main+59` |
| 6 | `MOV` 5 | `main+63` |
| 7 | `MOV RDX, 0xd00dfaceee` | `main+66` |
| 8 | `CMP RAX, RDX` | `main+76` |
| 9 | `CALL get_number` | `main+42` |
### Break 9
```
Can you tell me where to mail this postage?

Breakpoint 9, 0x0000000000401949 in main ()
(gdb) info registers 
rax            0x0                 0
rbx            0x7fffffffdf18      140737488346904
rcx            0x1                 1
rdx            0x1                 1
rsi            0x4c64c3            5006531
rdi            0x4c92b0            5018288
rbp            0x7fffffffdd20      0x7fffffffdd20
rsp            0x7fffffffdd10      0x7fffffffdd10
r8             0x4c92b0            5018288
r9             0x4                 4
r10            0x80                128
r11            0x246               582
r12            0x1                 1
r13            0x7fffffffdf08      140737488346888
r14            0x4c27d0            4990928
r15            0x1                 1
rip            0x401949            0x401949 <main+42>
eflags         0x206               [ PF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) info registers rbp
rbp            0x7fffffffdd20      0x7fffffffdd20
(gdb) info registers rsp
rsp            0x7fffffffdd10      0x7fffffffdd10
(gdb) info registers eax
eax            0x0                 0
(gdb) info registers rax
rax            0x0                 0
(gdb) info registers rdi
rdi            0x4c92b0            5018288
```


Anyways, I have a spreadsheet tracking the registry values at each breakpoint

| Breakpoint | Command | Line | Change |
| ---- | ---- | ---- | ---- |
| 1 | Start | ` _start` |  |
| 9 | `CALL get_number` | `main+42` | `rbx` = `0x7fffffffdf18`<br>`rcx` = `0x1`<br>`rdx` = `0x1`<br>`rsi` = `0x4c64c3`<br>`rdi` = `0x4c92b0`<br>`rbp` = `0x7fffffffdd20`<br>`rsp` = `0x7fffffffdd10`<br>`r8` = `0x4c92b0`<br>`r9` = `0x4`<br>`r10` = `0x80`<br>`r11` = `0x246`<br>`r12` = `0x1`<br>`r13` = `0x7fffffffdf08`<br>`r14` = `0x4c27d0`<br>`r15` = `0x1`<br>`rip` = `0x401949`<br>`eflags` = `0x206` |
| 2 | `MOV qword ptr [RBP + local_18],RAX` | `main+47` | `rcx` = `0x0`<br>`rdx` = `0x0`<br>`rsi` = `0x0`<br>`rdi` = `0xa`<br>`r8` = `0x4c7aa0`<br>`r9` = `0x4cf780`<br>`r10` = `0x6e`<br>`rip` = `0x40194e`<br>`eflags` = `0x246` |
| 3 | `MOV RAX,qword ptr [RBP + local_18]` | `main+51` | `rip` = `0x401952` |
| 4 | `MOV qword ptr [RBP + local_10],RAX` | `main+55` | `rip` = `0x401956` |
| 5 | `MOV RAX,qword ptr [RBP + local_10]` | `main+59` | `rip` = `0x40195a` |
| 6 | `MOV RAX,qword ptr [RAX]` | `main+63` | `rip` = `0x40195e` |
| SEGFAULT |  |  | `eflags` = `0x10246` |


Decided to use a different debugger, saw this on Segfault:
![[Pasted image 20240206115839.png]]

So we gotta see where and why it's geting that address




## Mov 1
`mov [rbp-0x10], rax`
`rax` = `0x0`

So this was shown at the bottom of the screen...I am not yet sure what it means
	`qword ptr [rbp - 0x10] = [0x0007fffe2e64ea0] = 0x0000000062d333230`
## Mov 2
`mov rax, [rbp-0x10]`
Similar thing here:
	![[Pasted image 20240206121119.png]]
	`qword ptr [rbp - 0x10] = [0x0007fffe2e64ea0] = 0x000000000000000`
	`rax = 0x0`
## Mov 3
`mov [rbp-8], rax`
![[Pasted image 20240206121411.png]]

## Mov 4
`mov rax, [rbp-8]`
![[Pasted image 20240206121513.png]]

## Mov 5
Must be the segfault?
`mov rax, [rax]`
![[Pasted image 20240206121556.png]]

And it crashed here?
![[Pasted image 20240206121741.png]]

Right before get number
![[Pasted image 20240206122830.png]]
![[Pasted image 20240206122839.png]]

Next:
![[Pasted image 20240206122916.png]]

In get number:
![[Pasted image 20240206122958.png]]

1: ![[Pasted image 20240206123027.png]]

2: ![[Pasted image 20240206123050.png]]

3: ![[Pasted image 20240206123109.png]]

4: ![[Pasted image 20240206123129.png]]

5: ![[Pasted image 20240206123153.png]]

6: ![[Pasted image 20240206123220.png]]

7: ![[Pasted image 20240206123237.png]]

8: ![[Pasted image 20240206123325.png]]

And we've stopped here somehow


Restarted
8: ![[Pasted image 20240206124941.png]]

It just dies at that break maube?
Just entered my mailing address

9: ![[Pasted image 20240206125137.png]]

10:![[Pasted image 20240206125202.png]]

11: ![[Pasted image 20240206125216.png]]

12: ![[Pasted image 20240206125231.png]]

13: ![[Pasted image 20240206125303.png]]

14: ![[Pasted image 20240206125351.png]]
15: ![[Pasted image 20240206125416.png]]
Skipped the fail and am returning successfully


![[Pasted image 20240206125447.png]]
![[Pasted image 20240206125502.png]]
![[Pasted image 20240206125515.png]]
![[Pasted image 20240206125532.png]]
![[Pasted image 20240206125552.png]]
And then a seg fault after that I believe


Gonna step through and figure out where exactly RAX gets set to 0
0 here at the start of main
	![[Pasted image 20240206130117.png]]
Set here:
![[Pasted image 20240206130152.png]]
That value is part of the ascii for the "can you ...etc" - or rather it's the point in memory where that text is if I had to guess
![[Pasted image 20240206130322.png]]

RAX back to zero: ![[Pasted image 20240206130618.png]]

Has a value now ![[Pasted image 20240206130641.png]]

Two more moves and then it was set to 0 again
![[Pasted image 20240206130742.png]]
I'm not sure how because it was the same in the last one
And I did verify that it was set to 0 there

Certianly reset to 0 here:
![[Pasted image 20240206130906.png]]
![[Pasted image 20240206130940.png]]
And somehow HERE rax was written again, I guess this is where it was written from the previous move
![[Pasted image 20240206131018.png]]
Same values going into this move:
![[Pasted image 20240206131145.png]]
And it broke here again somehow


OKAY OKAY OKAY
RIGHT AFTER we call fgets, it puts my entered text into RAX
![[Pasted image 20240206131910.png]]
![[Pasted image 20240206131927.png]]
And that is the memory address of where it is in the stack:
![[Pasted image 20240206132103.png]]

So somewhere in strtoq we overwrite RAX
![[Pasted image 20240206132232.png]]
![[Pasted image 20240206132250.png]]



New run:
stuff in the stack: ![[Pasted image 20240206132612.png]]

OKAY OKAY OKAYYYY
![[Pasted image 20240206140053.png]]
So with this information, we can assume that the string function is returning 0's...possibly because there isn't an int
Oh shit, when I put 300 in, this was the value of RAX:
![[Pasted image 20240206140301.png]]
OHHH FUCK `0x12c` = `300`
So I have to give it the number that points at the registry value where that number is found
Or maybe I can just give it the address of `print_flag`



## Attempt with print flag address:
It was not a success but we didn't segfault
```
┌──(kali㉿kali)-[~/Desktop/1-Week]
└─$ gdb ./postage 
	...omitted for brevity...
Reading symbols from ./postage...
(No debugging symbols found in ./postage)
(gdb) break _start
Breakpoint 1 at 0x4016c0
(gdb) r
Starting program: /home/kali/Desktop/1-Week/postage 
Breakpoint 1, 0x00000000004016c0 in _start ()
(gdb) disas main
Dump of assembler code for function main:
...omitted for brevity...
   0x0000000000401961 <+66>:    movabs $0xd000dfaceee,%rdx
   0x000000000040196b <+76>:    cmp    %rdx,%rax
   0x000000000040196e <+79>:    jne    0x401990 <main+113>
   0x0000000000401970 <+81>:    lea    0x967d1(%rip),%rax        # 0x498148
   0x0000000000401977 <+88>:    mov    %rax,%rdi
   0x000000000040197a <+91>:    call   0x412c60 <puts>
   0x000000000040197f <+96>:    mov    $0x0,%eax
   0x0000000000401984 <+101>:   call   0x4017e5 <print_flag>
   0x0000000000401989 <+106>:   mov    $0x0,%eax
...omitted for brevity...
End of assembler dump.
(gdb) c
Continuing.
Can you tell me where to mail this postage?
4200836
That doesn't look right... try again later, friend!
[Inferior 1 (process 2259206) exited with code 01]
```
Can still try again and see where it was put on the stack


Segfault is different if I use the dev of 0xd000dfaceee
![[Pasted image 20240206142204.png]]

0x401984 = 4200836


Put in 4200836
After getNumber, RAX = 0000000000401984 (which is the hex value)

And it gets the value written there, which is our print flag command
![[Pasted image 20240206145055.png]]
So maybe if I can point it to the line of code where the hardcoded value is set?
Like right here: ![[Pasted image 20240206145300.png]]
IT's 420803

WE can all go home now

![[Pasted image 20240206151535.png]]

![[Pasted image 20240206151845.png]]
![[Pasted image 20240206151904.png]]

![[Pasted image 20240206151921.png]]
![[Pasted image 20240206152014.png]]

Now, will it work IRL?


Fuck you I win
![[Pasted image 20240206152217.png]]

```
$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1247
Can you tell me where to mail this postage?
4200803
Got it! That's the right number!
Here's your flag, friend: flag{i_hope_ur_ready_4_some_pwning_in_a_few_weeks}
```

