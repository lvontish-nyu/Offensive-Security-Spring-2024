Writeuo for [[Postage]]
Downloaded executable and run -> get segfault
Segfault image
```
$ gdb ./postage
(gdb) r
Starting program: /home/kali/Desktop/1-Week/postage 
Can you tell me where to mail this postage?
No

Program received signal SIGSEGV, Segmentation fault.
0x000000000040195e in main ()
```

Look at disassembled main, describe what it's doing
```
bool main(EVP_PKEY_CTX *param_1)

{
  long *pointer;
  long val;
  
  init(param_1);
  puts("Can you tell me where to mail this postage?");
  pointer = (long *)get_number();
  val = *pointer;
  if (val != 0xd000dfaceee) {
    puts("That doesn\'t look right... try again later, friend!");
  }
  else {
    puts("Got it! That\'s the right number!");
    print_flag();
  }
  return val != 0xd000dfaceee;
}
```


Get number function reveals what good input looks like
```
void get_number(void)

{
  long in_FS_OFFSET;
  char input [136];
  long check;
  
  check = *(long *)(in_FS_OFFSET + 0x28);
  fgets(input,0x80,(FILE *)stdin);
  strtol(input,(char **)0x0,10);
  if (check != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```


Seg fault all 0's error
![[Pasted image 20240206115839.png]]


Register before call
![[Pasted image 20240206172220.png]]
Registers after `get_number`:
![[Pasted image 20240206172317.png]]

Doing it again but with a not correct answer lol
Before
![[Pasted image 20240206174917.png]]
After
![[Pasted image 20240206175004.png]]

![[Pasted image 20240206175032.png]]
0000000000401984

Figure out where this is happening
* show each MOV line and what it does

Show it's trying to open the memory location specified by the value of RAX
* RAX takes DEC input, uses to open memory
* Must set RAX memory value to the location of the secret code


SO attempt

Here's what we're trying to get around:
```
bool main(EVP_PKEY_CTX *param_1)

{
  long *pointer;
  long val;
  
  init(param_1);
  puts("Can you tell me where to mail this postage?");
  pointer = (long *)get_number();
  val = *pointer;
  if (val != 0xd000dfaceee) {
    puts("That doesn\'t look right... try again later, friend!");
  }
  else {
    puts("Got it! That\'s the right number!");
    print_flag();
  }
  return val != 0xd000dfaceee;
}
```

```
00401949 e8 69 ff        CALL       get_number                                    
         ff ff
0040194e 48 89 45 f0     MOV        qword ptr [RBP + local_18],RAX
00401952 48 8b 45 f0     MOV        RAX,qword ptr [RBP + local_18]
00401956 48 89 45 f8     MOV        qword ptr [RBP + local_10],RAX
0040195a 48 8b 45 f8     MOV        RAX,qword ptr [RBP + local_10]
0040195e 48 8b 00        MOV        RAX,qword ptr [pointer]
00401961 48 ba ee        MOV        RDX,0xd000dfaceee
         ce fa 0d 
         00 0d 00 00
0040196b 48 39 d0        CMP        RAX,RDX
0040196e 75 20           JNZ        LAB_00401990
00401970 48 8d 05        LEA        RAX,[s_Got_it!_That's_the_right_number!_00   = "Got it! ...omitted for brevity...
         d1 67 09 00
00401977 48 89 c7        MOV        RDI=>s_Got_it!_That's_the_right_number!_004981   = "Got it! That's the right numb
0040197a e8 e1 12        CALL       puts                                             int puts(char * __s)
         01 00
0040197f b8 00 00        MOV        RAX,0x0
         00 00
00401984 e8 5c fe        CALL       print_flag                                       undefined print_flag()
         ff ff
00401989 b8 00 00        MOV        RAX,0x0
         00 00
0040198e eb 14           JMP        LAB_004019a4
                     LAB_00401990                                    XREF[1]:     0040196e(j)  
00401990 48 8d 05        LEA        RAX,[s_That_doesn't_look_right..._try_a_00   = "That doesn't look right... tr
         d9 67 09 00
```



Here's my attempt to bypass compare
```
$ gdb ./postage
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
   0x0000000000401949 <+42>:    call   0x4018b7 <get_number>
   0x000000000040194e <+47>:    mov    %rax,-0x10(%rbp)
   0x0000000000401952 <+51>:    mov    -0x10(%rbp),%rax
   0x0000000000401956 <+55>:    mov    %rax,-0x8(%rbp)
   0x000000000040195a <+59>:    mov    -0x8(%rbp),%rax
   0x000000000040195e <+63>:    mov    (%rax),%rax
   0x0000000000401961 <+66>:    movabs $0xd000dfaceee,%rdx
   0x000000000040196b <+76>:    cmp    %rdx,%rax
   0x000000000040196e <+79>:    jne    0x401990 <main+113>
...omitted for brevity...
End of assembler dump.
(gdb) break *0x000000000040196b
Breakpoint 2 at 0x40196b
(gdb) c
Continuing.
Can you tell me where to mail this postage?
4200836

Breakpoint 2, 0x000000000040196b in main ()
(gdb) info registers rax
rax            0xb8fffffe5ce8      203409651031272
(gdb) info registers rdx
rdx            0xd000dfaceee       14293885701870
(gdb) set $rax = $rdx
(gdb) info registers rax
rax            0xd000dfaceee       14293885701870
(gdb) info registers rax
rax            0xd000dfaceee       14293885701870
(gdb) c
Continuing.
Got it! That's the right number!
ERROR: no flag found. If you're getting this error on the remote system, please message the admins. If you're seeing this locally, run it on the remote system! You solved the challenge, and need to get the flag from there!
[Inferior 1 (process 2396665) exited normally]

```


Get the answer the right way
Need to enter a location in memory where the value is, is it in memory anywhere?
Value is stored as a part of the command