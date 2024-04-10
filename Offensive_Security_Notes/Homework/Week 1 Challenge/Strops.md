100 Points
Flag: `flag{l00ps_and_x0rs_and_reads_o_my}`
Prompt:
![[Pasted image 20240205103542.png]]

Unedited Decompiled `main`:
```
undefined8 main(void)

{
  long in_FS_OFFSET;
  uint local_5c;
  byte local_58 [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  printf("Enter your flag: ");
  read(1,local_58,0x40);
  local_5c = 0;
  do {
    if (0x22 < local_5c) {
      puts("Correct!");
LAB_001012c6:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    if ((byte)~flag[(int)local_5c] != local_58[(int)local_5c]) {
      puts("Nope.");
      goto LAB_001012c6;
    }
    local_5c = local_5c + 1;
  } while( true );
}
```


So it looks like it's comparing each byte of what you entered to a flag, but I'm not entirely sure how it got the flag value

Code with new variables:
```
undefined8 main(void)

{
  long in_FS_OFFSET;
  uint counter;
  byte flagGuess [72];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  printf("Enter your flag: ");
  read(1,flagGuess,0x40);
  counter = 0;
  do {
    if (0x22 < counter) {
      puts("Correct!");
LAB_001012c6:
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    if ((byte)~flag[(int)counter] != flagGuess[(int)counter]) {
      puts("Nope.");
      goto LAB_001012c6;
    }
    counter = counter + 1;
  } while( true );
}
```


And that while loop essentially:
```
counter = 0;
do {
	# Checks to see if the counter is greater than 34 
    if (0x22 < counter) {
      puts("Correct!");
LAB_001012c6:
	# This is the jump point
      if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
	      # This checks the variable against the value it was initialized at
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    if ((byte)~flag[(int)counter] != flagGuess[(int)counter]) {
	    #if flag[counter] != flagGuess[counter] essentially
	    # Where are they getting that flag value
      puts("Nope.");
      goto LAB_001012c6;
    }
    # So we want it to be equal so they can iterate through
    counter = counter + 1;
  } while( true );
```

![[Pasted image 20240205111150.png]]
`0010126d` 
	I'm not sure where `0010126d` is in the main method code
	It puts the address of `[flag]` in the `RDX` register
`00101274`
	Matches with `(byte)~flag[(int)counter]` in the if statement *I think*
	
So maybe if I can set a breakpoint somewhere and get it to print the value of RDX and then the value in that memory spot...do I know how to do that...no but...whatever

### It's not a solution, but here's how I was able to at least get it to tell me I was correct:
1) Figure out the address in actual memory for that counter compare:
	   ![[Pasted image 20240205115419.png]]
	And actually, let me make that pretty:
```
(gdb) disas main
Dump of assembler code for function main:
	...omitted for brevity...
   0x00005555555552a6 <+150>:   addl   $0x1,-0x54(%rbp)
   0x00005555555552aa <+154>:   mov    -0x54(%rbp),%eax
   0x00005555555552ad <+157>:   cmp    $0x22,%eax
   0x00005555555552b0 <+160>:   jbe    0x555555555268 <main+88>
 >	...omitted for brevity...
   0x00005555555552da <+202>:   leave
   0x00005555555552db <+203>:   ret
```


2) Set a breakpoint there:
```
$ gdb ./strops.bin
	...omitted for brevity
(gdb) b *0x00005555555552ad
Breakpoint 1 at 0x5555555552ad
(gdb) run
Starting program: /home/kali/Desktop/1-Week/strops.bin 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter your flag: test

Breakpoint 1, 0x00005555555552ad in main ()
(gdb) info registers
rax            0x0                 0
rbx            0x7fffffffdef8      140737488346872
rcx            0x7ffff7ec2a5d      140737352837725
rdx            0x40                64
rsi            0x7fffffffdd90      140737488346512
rdi            0x1                 1
rbp            0x7fffffffdde0      0x7fffffffdde0
rsp            0x7fffffffdd80      0x7fffffffdd80
r8             0x0                 0
r9             0x7ffff7fcfb10      140737353939728
r10            0x7ffff7fcb858      140737353922648
r11            0x246               582
r12            0x0                 0
r13            0x7fffffffdf08      140737488346888
r14            0x555555557da0      93824992247200
r15            0x7ffff7ffd000      140737354125312
rip            0x5555555552ad      0x5555555552ad <main+157>
eflags         0x207               [ CF PF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) info registers eax
eax            0x0                 0
(gdb) set $eax = 0x23
(gdb) c
Continuing.
Correct!
[Inferior 1 (process 1898941) exited normally]

```

set the eax register value to something greater than 0x23 and profit



### Can I use the same thing to get the flag?
Put a breakpoint, print each char and then set my character the same lol
That's gotta be the other compare: `0x000055555555528c <+124>:   cmp    %eax,%edx`

```
(gdb) disas main
Dump of assembler code for function main:
	...omitted for brevity...
   0x0000555555555284 <+116>:   movzbl -0x50(%rbp,%rax,1),%eax
   0x0000555555555289 <+121>:   movsbl %al,%eax
   0x000055555555528c <+124>:   cmp    %eax,%edx
   0x000055555555528e <+126>:   je     0x5555555552a6 <main+150>
	 ...omitted for brevity...
   0x00005555555552da <+202>:   leave
   0x00005555555552db <+203>:   ret
```


Starting program and setting my flag as a bunch of a's (so I know for sure which register has my char)
```
└─$ gdb ./strops.bin
	...omitted for brevity...
(gdb) break *0x000055555555528c
Breakpoint 1 at 0x55555555528c
(gdb) run
Starting program: /home/kali/Desktop/1-Week/strops.bin 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter your flag: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Hitting breakpoint,
	We can tell that my data is in `eax` because `0x61` is the Hex for "a"
	So we'll set `eax` to `0x66`
```
(gdb) info registers edx
edx            0x66                102
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = 0x66
(gdb) info registers eax
eax            0x66                102
(gdb) c
Continuing.

Breakpoint 1, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x6c                108
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = 0x6c
(gdb) info registers eax
eax            0x6c                108
(gdb) c
Continuing.
```

This will keep going, but I want to see if I can script it with pwntools

Fuck it, scripting it is a pain...doing it manually so that it's DONE

Starting the program, setting the break at start, and finding my cmp in memory and setting my breakpoint there
```
$ gdb ./strops.bin
	...omitted for brevity...
(gdb) break _start
Breakpoint 1 at 0x10e0
(gdb) r
Starting program: /home/kali/Desktop/1-Week/strops.bin 

Breakpoint 1.2, 0x00007ffff7fe5360 in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) disas main
Dump of assembler code for function main:
	...omitted for brevity...
   0x000055555555528c <+124>:   cmp    %eax,%edx
	...omitted for brevity...
End of assembler dump.
(gdb) break *0x000055555555528c
Breakpoint 2 at 0x55555555528c
```

Comparing and resetting the register values



# Trying again
## Manually getting the flag with GDB
### Long-ass terminal output
```
gdb ./strops.bin
GNU gdb (Debian 13.2-1) 13.2
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from ./strops.bin...
(No debugging symbols found in ./strops.bin)
(gdb) break _start
Breakpoint 1 at 0x10e0
(gdb) r
Starting program: /home/kali/Desktop/1-Week/strops.bin 

Breakpoint 1.2, 0x00007ffff7fe5360 in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) disas main
Dump of assembler code for function main:
   0x0000555555555210 <+0>:     endbr64
   0x0000555555555214 <+4>:     push   %rbp
   0x0000555555555215 <+5>:     mov    %rsp,%rbp
   0x0000555555555218 <+8>:     sub    $0x60,%rsp
   0x000055555555521c <+12>:    mov    %fs:0x28,%rax
   0x0000555555555225 <+21>:    mov    %rax,-0x8(%rbp)
   0x0000555555555229 <+25>:    xor    %eax,%eax
   0x000055555555522b <+27>:    mov    $0x0,%eax
   0x0000555555555230 <+32>:    call   0x5555555551c9 <setup>
   0x0000555555555235 <+37>:    lea    0xdc8(%rip),%rax        # 0x555555556004
   0x000055555555523c <+44>:    mov    %rax,%rdi
   0x000055555555523f <+47>:    mov    $0x0,%eax
   0x0000555555555244 <+52>:    call   0x5555555550b0 <printf@plt>
   0x0000555555555249 <+57>:    lea    -0x50(%rbp),%rax
   0x000055555555524d <+61>:    mov    $0x40,%edx
   0x0000555555555252 <+66>:    mov    %rax,%rsi
   0x0000555555555255 <+69>:    mov    $0x1,%edi
   0x000055555555525a <+74>:    call   0x5555555550c0 <read@plt>
   0x000055555555525f <+79>:    movl   $0x0,-0x54(%rbp)
   0x0000555555555266 <+86>:    jmp    0x5555555552aa <main+154>
   0x0000555555555268 <+88>:    mov    -0x54(%rbp),%eax
   0x000055555555526b <+91>:    cltq
   0x000055555555526d <+93>:    lea    0x2dac(%rip),%rdx        # 0x555555558020 <flag>
   0x0000555555555274 <+100>:   movzbl (%rax,%rdx,1),%eax
   0x0000555555555278 <+104>:   movsbl %al,%eax
   0x000055555555527b <+107>:   not    %eax
   0x000055555555527d <+109>:   mov    %eax,%edx
   0x000055555555527f <+111>:   mov    -0x54(%rbp),%eax
   0x0000555555555282 <+114>:   cltq
   0x0000555555555284 <+116>:   movzbl -0x50(%rbp,%rax,1),%eax
   0x0000555555555289 <+121>:   movsbl %al,%eax
   0x000055555555528c <+124>:   cmp    %eax,%edx
   0x000055555555528e <+126>:   je     0x5555555552a6 <main+150>
   0x0000555555555290 <+128>:   lea    0xd7f(%rip),%rax        # 0x555555556016
   0x0000555555555297 <+135>:   mov    %rax,%rdi
   0x000055555555529a <+138>:   call   0x555555555090 <puts@plt>
   0x000055555555529f <+143>:   mov    $0x0,%eax
   0x00005555555552a4 <+148>:   jmp    0x5555555552c6 <main+182>
   0x00005555555552a6 <+150>:   addl   $0x1,-0x54(%rbp)
   0x00005555555552aa <+154>:   mov    -0x54(%rbp),%eax
   0x00005555555552ad <+157>:   cmp    $0x22,%eax
   0x00005555555552b0 <+160>:   jbe    0x555555555268 <main+88>
   0x00005555555552b2 <+162>:   lea    0xd63(%rip),%rax        # 0x55555555601c
   0x00005555555552b9 <+169>:   mov    %rax,%rdi
   0x00005555555552bc <+172>:   call   0x555555555090 <puts@plt>
   0x00005555555552c1 <+177>:   mov    $0x0,%eax
   0x00005555555552c6 <+182>:   mov    -0x8(%rbp),%rdx
   0x00005555555552ca <+186>:   sub    %fs:0x28,%rdx
   0x00005555555552d3 <+195>:   je     0x5555555552da <main+202>
   0x00005555555552d5 <+197>:   call   0x5555555550a0 <__stack_chk_fail@plt>
   0x00005555555552da <+202>:   leave
   0x00005555555552db <+203>:   ret
End of assembler dump.
(gdb) break *0x000055555555528c
Breakpoint 2 at 0x55555555528c
(gdb) c
Continuing.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1.1, 0x00005555555550e0 in _start ()
(gdb) c
Continuing.
Enter your flag: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Breakpoint 2, 0x000055555555528c in main ()
(gdb) aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Undefined command: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".  Try "help".
(gdb) info registers edx
edx            0x66                102
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax $rax
A syntax error in expression, near `$rax'.
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x66                102
(gdb) info registers eax
eax            0x66                102
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x6c                108
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x6c                108
(gdb) info registers eax
eax            0x6c                108
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x61                97
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x61                97
(gdb) info registers eax
eax            0x61                97
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x67                103
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x67                103
(gdb) info registers eax
eax            0x67                103
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x7b                123
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x7b                123
(gdb) info registers eax
eax            0x7b                123
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x6c                108
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x6c                108
(gdb) info registers eax
eax            0x6c                108
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x30                48
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x30                48
(gdb) info registers eax
eax            0x30                48
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x30                48
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x30                48
(gdb) info registers eax
eax            0x30                48
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x70                112
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x70                112
(gdb) info registers eax
eax            0x70                112
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x73                115
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x73                115
(gdb) info registers eax
eax            0x73                115
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x5f                95
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x61                97
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x61                97
(gdb) info registers eax
eax            0x61                97
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x6e                110
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x6e                110
(gdb) info registers eax
eax            0x6e                110
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x64                100
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x64                100
(gdb) info registers eax
eax            0x64                100
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x5f                95
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x78                120
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x78                120
(gdb) info registers eax
eax            0x78                120
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x30                48
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x30                48
(gdb) info registers eax
eax            0x30                48
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x72                114
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x72                114
(gdb) info registers eax
eax            0x72                114
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x73                115
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x73                115
(gdb) info registers eax
eax            0x73                115
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x5f                95
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x61                97
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x61                97
(gdb) info registers eax
eax            0x61                97
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x6e                110
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x6e                110
(gdb) info registers eax
eax            0x6e                110
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x64                100
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x64                100
(gdb) info registers eax
eax            0x64                100
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x5f                95
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x72                114
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x72                114
(gdb) info registers eax
eax            0x72                114
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x65                101
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x65                101
(gdb) info registers eax
eax            0x65                101
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x61                97
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x61                97
(gdb) info registers eax
eax            0x61                97
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x64                100
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x64                100
(gdb) info registers eax
eax            0x64                100
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x73                115
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x73                115
(gdb) info registers eax
eax            0x73                115
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x5f                95
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x6f                111
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x6f                111
(gdb) info registers eax
eax            0x6f                111
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x5f                95
(gdb) info registers eax
eax            0x5f                95
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x6d                109
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x6d                109
(gdb) info registers eax
eax            0x6d                109
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x79                121
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x79                121
(gdb) info registers eax
eax            0x79                121
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x7d                125
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x7d                125
(gdb) info registers eax
eax            0x7d                125
(gdb) c
Continuing.
Correct!
[Inferior 1 (process 2849417) exited normally]
(gdb) q

```
### Edited terminal output
```
gdb ./strops.bin

(No debugging symbols found in ./strops.bin)
(gdb) break _start
Breakpoint 1 at 0x10e0
(gdb) r
Starting program: /home/kali/Desktop/1-Week/strops.bin 
Breakpoint 1.2, 0x00007ffff7fe5360 in _start () from /lib64/ld-linux-x86-64.so.2
(gdb) disas main
Dump of assembler code for function main:
...omitted for brevity...
   0x0000555555555289 <+121>:   movsbl %al,%eax
   0x000055555555528c <+124>:   cmp    %eax,%edx
   0x000055555555528e <+126>:   je     0x5555555552a6 <main+150>
...omitted for brevity...
End of assembler dump.
(gdb) break *0x000055555555528c
Breakpoint 2 at 0x55555555528c
(gdb) c
Continuing.
Enter your flag: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x66                102
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax $rax
A syntax error in expression, near `$rax'.
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x66                102
(gdb) info registers eax
eax            0x66                102
(gdb) c
Continuing.

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x6c                108
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x6c                108
(gdb) info registers eax
eax            0x6c                108
(gdb) c
Continuing.

...omitted for brevity...

Breakpoint 2, 0x000055555555528c in main ()
(gdb) info registers edx
edx            0x7d                125
(gdb) info registers eax
eax            0x61                97
(gdb) set $eax = $edx
(gdb) info registers edx
edx            0x7d                125
(gdb) info registers eax
eax            0x7d                125
(gdb) c
Continuing.
Correct!
[Inferior 1 (process 2849417) exited normally]
(gdb) q

```

## We got the flag bitches!!!
Flag: `flag{l00ps_and_x0rs_and_reads_o_my}`


And My code worked!
```
python3 stropsploit.py
[+] Starting local process '/bin/bash': pid 2895274
...omitted for brevity...
@@flag{l00ps_and_x0rs_and_reads_o_my}
[*] Stopped process '/bin/bash' (pid 2895274)
```

# Code:
```
from pwn import *
import re

#############################################################
#	stropsploit.py											#
#	Lindsay Von Tish (lmv9443@nyu.edu)						#
#	Reverse Engineering 1: Strops Challenge Solver Script	#
#	02/07/2024												#
#############################################################

# A function to send a line and receive the response
#	Input: Message String, Connection
#	Output: Recieved message
def sendRecv(msg, dst):
	dst.sendline()
	#ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	r = dst.recv()
	return r

# A function to convert encoded input to a string and remove text format characters
#	Input: Encoded string
#	Output: Unencoded string
def cleanLine(ln):
	ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
	l = ansi_escape.sub('', str(ln, encoding='utf-8'))
	return l

# A function to find the memory location of the CMP function that strops uses to compare the guess to the flag
#	Input: Connection
#	Output: Memory location in hex string
def findCMP(p):
	m = open("mainDisas.txt", "a")
	m.write("Main Method Disasembly:" + "\n")

	p.sendline("disas main")
	#ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

	n = 0

	while True:
		#l = p.recvline()
		#ln = ansi_escape.sub('', str(l, encoding='utf-8'))
		#z = ansi_escape.sub('', ln)
		ln = cleanLine(p.recvline())
		m.write(ln)
		if re.search("End of assembler dump.", ln):
			break
		elif re.search("cmp.*eax.*edx", ln):
			cline = ln
		elif(n == 20):
			# Must page through disassembly for some reason
			p.sendline("c")
		n+=1

	m.write("Found the memory location: [")
	c = re.split("\s+", cline)
	m.write(c[1])
	m.write("]")
	return c[1]

# A function to iterate through interactions with the strops binary
# 	Sends a guess to the program
#	Waits until strops reaches the set breakpoint
#		Sends debug command to set the value of EAX to that of EDX
#		Saves current state of EAX register
#	Input: Connection
#	Output: None
def getFlag(p):
	#infoEAX = [0] * 40
	#r = sendRecv("c")
	#print(r)
	log = open("Strop.txt", "a")
	p.sendline("c")

	# Wait for the enter flag prompt and send a guess
	while True:
		r = cleanLine(p.recvline())
		# print(r)
		if re.search("Enter your flag:", r):
			guess = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			p.sendline(guess.encode())
			#print(p.recv())
			print("Sending flag!")
			break

	# Loops through as strops reaches the breakpoint at CMP
	for i in range(40):
		# Save debugger response in log
		r = cleanLine(p.recv())
		log.write(r)
		# Save EDX value in EAX value then write EAX information to log
		p.sendline("set $eax = $edx")
		p.sendline("info registers eax")
		r = cleanLine(p.recv())
		log.write(r)

		# Break once we get "correct" response
		if re.search("Correct", r):
			print("Correct!!")
			break
		# Send debugger continue command
		p.sendline("c")
	log.close()
	return 0

# A function to retreive the flag data from the log file
#	Input: None
#	Output: Decoded Flag
def parseFlag():
	log = open("Strop.txt", "r")
	f = ""
	i = 0
	for line in log:
		if re.search("eax.*0x.*", line):
			l = re.split("\s+", line)
			n = re.split("x", l[3])
			f += n[1]
	return bytes.fromhex(f).decode('ascii')


def main():
	# Start gdb session
	p =  process("/bin/bash")
	p.sendline("gdb ./strops.bin -q")
	p.recv()
	p.sendline("break _start")
	p.recv() # GDB response with one line indicating that the breakpoint is set
	p.sendline("r")
	print(p.recv())

	# Find location of cmp
	loc =findCMP(p)
	# Set breakpoint at cmp location and delete breakpoint at _start
	cmd = "break *" + loc
	#print(cmd)
	p.sendline(cmd)
	print(p.recv())
	p.sendline("clear _start")
	print(p.recv)

	# Interact with strops and save debugger output
	getFlag(p)
	# Parse the flag from the log file
	print(parseFlag())
	
		

if __name__=="__main__": 
	main()
```