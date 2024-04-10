Points: 200
Location: `nc offsec-chalbroker.osiris.cyber.nyu.edu 7331`

First run:
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ ./heterograms 
Send me some data to get the flag!
No
Na, I don't like that
Too bad
Na, I don't like that
I don't like you
Na, I don't like that
u wut m8
Na, I don't like that

zsh: suspended  ./heterograms
```
Rude AF that one

Beautiful Jesus we have symbols on this one
![[Pasted image 20240221133122.png]]

Wild strings
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ strings heterograms        
That's a nice word!
Meh, I'm not feeling that
Copy that!
Na, I don't like that
Send me some data to get the flag!
./flag.txt
:*3$"
unforgivable
troublemakings
computerizably
hydromagnetics
flamethrowing
copyrightable
undiscoverably
GCC: (Ubuntu 9.4.0-1ubuntu1~20.04.1) 9.4.0

```

Main Method
```c
void main(void)

{
  char cVar1;
  int __fd;
  long in_FS_OFFSET;
  char local_118 [264];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts("Send me some data to get the flag!");
  do {
    do {
      cVar1 = process();
    } while (cVar1 != '\x01');
    __fd = open("./flag.txt",0);
    read(__fd,local_118,0x100);
    puts(local_118);
  } while( true );
}
```
So we want `process` to return `'\x01`
What is Process...Oh she's UGLY
Process starts by taking in data and then checks to ensure that the read method returned 0
```c
sVar6 = read(0,local_30,(ulong)BUFSIZE);
iVar5 = (int)sVar6;
```

```
MOV        EAX,dword ptr [BUFSIZE]               = 00000080h
MOV        EDX,EAX
MOV        RAX,qword ptr [RBP + local_28]
MOV        RSI,RAX
MOV        EDI,0x0
CALL       <EXTERNAL>::read                      ssize_t read(int __fd, void * __
MOV        dword ptr [RBP + local_34],EAX
CMP        dword ptr [RBP + local_34],0x0
JZ         LAB_00101644
```

Only continues if it's not equal to 0, then 
```c
    pbVar7 = local_30 + iVar5;
    bVar2 = *local_30;
    if ((iVar5 - 1U == (uint)bVar2) && (3 < bVar2)) {
```

```
001014c1 48 8b 45 e0     MOV        RAX,qword ptr [RBP + local_28]
001014c5 48 89 45 d8     MOV        qword ptr [RBP + local_30],RAX
001014c9 8b 45 d4        MOV        EAX,dword ptr [RBP + local_34]
001014cc 48 63 d0        MOVSXD     RDX,EAX
001014cf 48 8b 45 e0     MOV        RAX,qword ptr [RBP + local_28]
001014d3 48 01 d0        ADD        RAX,RDX
001014d6 48 89 45 e8     MOV        qword ptr [RBP + local_20],RAX
001014da 48 8b 45 e0     MOV        RAX,qword ptr [RBP + local_28]
001014de 0f b6 00        MOVZX      EAX,byte ptr [RAX]
001014e1 88 45 ca        MOV        byte ptr [RBP + local_3e],AL
001014e4 83 6d d4 01     SUB        dword ptr [RBP + local_34],0x1
001014e8 48 83 45        ADD        qword ptr [RBP + local_30],0x1
		 d8 01
001014ed 0f b6 45 ca     MOVZX      EAX,byte ptr [RBP + local_3e]
001014f1 39 45 d4        CMP        dword ptr [RBP + local_34],EAX
```

Gonna disassemble "process" and set a break at every compare
```
(gdb) disas process
Dump of assembler code for function process:
   0x0000555555555462 <+0>:     endbr64
   0x0000555555555466 <+4>:     push   %rbp
   0x0000555555555467 <+5>:     mov    %rsp,%rbp
...omitted for brevity
   0x0000555555555496 <+52>:    call   0x5555555550f0 <memset@plt>
   0x000055555555549b <+57>:    mov    0x2beb(%rip),%eax    # 0x55555555808c <BUFSIZE>
   0x00005555555554a1 <+63>:    mov    %eax,%edx
   0x00005555555554a3 <+65>:    mov    -0x20(%rbp),%rax
   0x00005555555554a7 <+69>:    mov    %rax,%rsi
   0x00005555555554aa <+72>:    mov    $0x0,%edi
   0x00005555555554af <+77>:    call   0x555555555100 <read@plt>
   0x00005555555554b4 <+82>:    mov    %eax,-0x2c(%rbp)
   0x00005555555554b7 <+85>:    cmpl   $0x0,-0x2c(%rbp)
   0x00005555555554bb <+89>:    je     0x555555555644 <process+482>

```

Actually, gonna use a script for that
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ cat ProcessDisas.txt 
Process Method Disasembly:
   0x00005555555554b7 <+85>:    cmpl   $0x0,-0x2c(%rbp)
   0x00005555555554f1 <+143>:   cmp    %eax,-0x2c(%rbp)
   0x00005555555554fa <+152>:   cmpb   $0x3,-0x36(%rbp)
   0x000055555555552e <+204>:   cmp    %al,-0x35(%rbp)
   0x0000555555555572 <+272>:   cmp    $0x2,%eax
   0x000055555555557b <+281>:   cmp    $0x2,%eax
   0x0000555555555588 <+294>:   cmp    $0x1,%eax
   0x00005555555555c1 <+351>:   cmp    %rax,-0x18(%rbp)
   0x00005555555555e3 <+385>:   cmpb   $0x19,-0x31(%rbp)
   0x0000555555555602 <+416>:   cmp    %eax,-0x30(%rbp)
   0x000055555555562c <+458>:   cmp    %rax,-0x18(%rbp)             
```

```
break *0x00005555555554b7
break *0x00005555555554f1
break *0x00005555555554fa
break *0x000055555555552e
break *0x0000555555555572
break *0x000055555555557b
break *0x0000555555555588
break *0x00005555555555c1
break *0x00005555555555e3
break *0x0000555555555602
break *0x000055555555562c
```

If statements
```
if (iVar5 != 0) {
if ((iVar5 - 1U == (uint)bVar2) && (3 < bVar2)) {
if (bVar3 == bVar4) {
while( true ) {
while( true ) {
while( true ) {
if (pbVar7 < local_30 + 1) {
if (bVar2 != 2)
if (2 < bVar2)
if (bVar2 != 0)
if (bVar2 != 1) break;
if (pbVar7 < local_30 + bVar2) break
for (local_38 = 0; local_38 < (int)(uint)bVar2; local_38 = local_38 + 1)
if (0x19 < bVar3)
```

| Num | Type | Address | Operation | Statement |
| ---- | ---- | ---- | ---- | ---- |
| 1 | breakpoint | 0x00005555555554b7 | cmpl  $0x0,-0x2c(%rbp) | if (iVar5 != 0) { |
| 2 | breakpoint | 0x00005555555554f1 | cmp  %eax,-0x2c(%rbp) | if ((iVar5 - 1U == (uint)bVar |
| 3 | breakpoint | 0x00005555555554fa | cmpb  $0x3,-0x36(%rbp) | && (3 < bVar2)) { |
| 4 | breakpoint | 0x000055555555552e | cmp  %al,-0x35(%rbp) | if (bVar3 == bVar4) |
| 5 | breakpoint | 0x0000555555555572 | cmp  $0x2,%eax | if (bVar2 != 2) |
| 6 | breakpoint | 0x000055555555557b | cmp  $0x2,%eax | if (2 < bVar2) |
| 7 | breakpoint | 0x0000555555555588 | cmp  $0x1,%eax | while( true ) |
| 8 | breakpoint | 0x00005555555555c1 | cmp  %rax,-0x18(%rbp) | if (pbVar7 < local_30 + bVar2) |
| 9 | breakpoint | 0x00005555555555e3 | cmpb  $0x19,-0x31(%rbp) | if (0x19 < bVar3) |
| 10 | breakpoint | 0x0000555555555602 | cmp  %eax,-0x30(%rbp) | for (local_38 = 0; local_38 < (int)(uint)bVar2; local_38 = local_38 + 1) |
| 11 | breakpoint | 0x000055555555562c | cmp  %rax,-0x18(%rbp) | if (pbVar7 < local_30 + 1) |
That second compare REALLY makes it look like it wants that ASCII 2 again

```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ gdb ./heterograms
(gdb) r
Starting program: /home/kali/Desktop/3-Week/heterograms 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Send me some data to get the flag!
2

Breakpoint 1, 0x00005555555554b7 in process ()
(gdb) p/x $rbp-0x2c
$1 = 0x7fffffffdc84
(gdb) p *0x7fffffffdc84
$2 = 2
(gdb) c
Continuing.

Breakpoint 2, 0x00005555555554f1 in process ()
(gdb) p/x $rbp-0x2c
$3 = 0x7fffffffdc84
(gdb) p *0x7fffffffdc84
$4 = 1
(gdb) info registers eax
eax            0x32                50
(gdb) c
Continuing.
Na, I don't like that

```

So input of 0x2, it does not like still, though it does recognize that as a 2 now
But that second compare compares it to a 1, so maybe I'll try that
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ python3 HGram_Debug_Local.py
Breakpoint!
 1, 0x00005555555554b7 in process ()
(gdb) $1 = 2
(gdb) rax            0x2                 2

Breakpoint!
 2, 0x00005555555554f1 in process ()
(gdb) $2 = 1
(gdb) rax            0x2                 2

(gdb) Continuing.
Na, I don't like that

[*] Stopped process '/bin/bash' (pid 406872)
```

`\x01` Got a continue without an immediate I don't like that
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ python3 HGram_Debug_Local.py
Breakpoint!
 1, 0x00005555555554b7 in process ()
(gdb) $1 = 2
(gdb) rax            0x2                 2

Breakpoint!
 2, 0x00005555555554f1 in process ()
(gdb) $2 = 1
(gdb) rax            0x1                 1

[*] Stopped process '/bin/bash' (pid 407813)

```


I'm gonna go back to inching through the Process method
##### Original Method
```c
undefined8 process(void)

{
  local_30 = (byte *)malloc((ulong)BUFSIZE);
  memset(local_30,0,(ulong)BUFSIZE);
  sVar6 = read(0,local_30,(ulong)BUFSIZE);
  iVar5 = (int)sVar6;
  if (iVar5 != 0) { // Read condition must have returned not 0
    pbVar7 = local_30 + iVar5;
    bVar2 = *local_30;
    if ((iVar5 - 1U == (uint)bVar2) && (3 < bVar2)) { // First val must == length, also must be three bytes
      bVar3 = local_30[1];
      local_30 = local_30 + 2;
      bVar4 = checksum(local_30,pbVar7);
      if (bVar3 == bVar4) {
        pbVar8 = (byte *)malloc(0x24);
        *pbVar8 = bVar2;
        *(uint *)(pbVar8 + 0x20) = (uint)bVar3;
        while( true ) {
          while( true ) {
            while( true ) {
              if (pbVar7 < local_30 + 1) {
                uVar9 = handle(pbVar8);
                return uVar9;
              }
              bVar2 = *local_30;
              pbVar1 = local_30 + 1;
              if (bVar2 != 2) break;
              local_30 = local_30 + 2;
              pbVar8[0x1c] = *pbVar1;
            }
            if (2 < bVar2) goto LAB_00101654;
            if (bVar2 != 0) break;
            pbVar8[1] = *pbVar1;
            local_30 = local_30 + 2;
          }
          if (bVar2 != 1) break;
          bVar2 = *pbVar1;
          local_30 = local_30 + 2;
          if (pbVar7 < local_30 + bVar2) break;
          for (local_38 = 0; local_38 < (int)(uint)bVar2; local_38 = local_38 + 1) {
            bVar3 = *local_30;
            local_30 = local_30 + 1;
            if (0x19 < bVar3) goto LAB_00101654;
            (&DAT_001040b1)[(int)(uint)bVar3] = 1;
          }
        }
      }
    }
  }
LAB_00101654:
  puts("Na, I don\'t like that");
  reset();
  return 0;
}
```
##### Edited Method
```c
undefined8 process(void)

{
  byte cSum;
  int ri;
  ssize_t r;
  byte *rOffset;
  byte *ptr2;
  undefined8 v;
  int count;
  byte *inputPtr;
  byte char1;
  byte data;
  byte *ptr3;
  
  inputPtr = (byte *)malloc((ulong)BUFSIZE);
  memset(inputPtr,0,(ulong)BUFSIZE);
  r = read(0,inputPtr,(ulong)BUFSIZE);
  size = (int)r;
  if (ri != 0) { //Checks for successful read
    rOffset = inputPtr + size;
    data = *inputPtr;
    if ((size - 1U == (uint)data) && (3 < data)) {
    //Is the first value equal to the length of the data?
    // Are there at least three bytes of data
      char1 = inputPtr[1];
      inputPtr = inputPtr + 2; // Point to the third byte in the data
      cSum = checksum(inputPtr,rOffset);
      if (char1 == cSum) { // Second byte must be equal to the value of the checksum
        ptr2 = (byte *)malloc(0x24);
        *ptr2 = data; // Saves data into ptr2 memory
        *(uint *)(ptr2 + 0x20) = (uint)char1; //Sets ptr2[8] == char1 (the second byte in the data)
        while( true ) {
          while( true ) {
            while( true ) {
              if (rOffset < inputPtr + 1) { // is offset <= to the address
                v = handle(ptr2);
                return v;
              }
              // Set data value save pointer to next byte
              data = *inputPtr;
              ptr3 = inputPtr + 1;
              if (data != 2) break; // Continue if data == 2
              inputPtr = inputPtr + 2; // Increase pointer by 2 bytes
              ptr2[0x1c] = *ptr3; // Saves that value fo the next byte into ptr2[28]
            }
            if (2 < data) goto LAB_00101654; // if the value is greater than 2, go away
            if (data != 0) break;
            // if byte is 0, save byte value and then point to the byte at i+2
            ptr2[1] = *ptr3;
            inputPtr = inputPtr + 2;
          }
          if (data != 1) break;
          // if data == 1, save the byte and increase pointer 2
          data = *ptr3;
          inputPtr = inputPtr + 2;
          if (rOffset < inputPtr + data) break;
          for (count = 0; count < (int)(uint)data; count = count + 1) {
            char1 = *inputPtr;
            inputPtr = inputPtr + 1;
            if (0x19 < char1) goto LAB_00101654;
            (&globalArray)[(int)(uint)char1] = 1;
          }
        }
      }
    }
  }
LAB_00101654:
  puts("Na, I don\'t like that");
  reset();
  return 0;
}
```


Checksum:
```c
uint checksum(char *v1,char *v2)
{
  char *ptr;
  byte bt;
  bt = 0;
  for (ptr = v1; ptr <= v2; ptr = ptr + 1) {
    bt = bt + *ptr;
  }
  return ~(uint)bt;
}

```
Looks like it sums up the values between the two pointers


While loop from a different perspective
![[Pasted image 20240221162833.png]]

#### If b== 2
First if (red)
```c
// Set data value save pointer to next byte
data = *inputPtr;
ptr3 = inputPtr + 1;
if (data != 2) break; // Continue if data == 2
inputPtr = inputPtr + 2; // Increase pointer by 2 bytes
ptr2[0x1c] = *ptr3;
```
If the byte == 2:
	save the byte at `[addr + 1]`
	Increase the address by 2
	Save the b1 in the new array at point 28? (set up to erase array)
####  If b > 2
Second if (blue)
Breaks if the byte value is greater than 2
```c
if (2 < data) goto LAB_00101654;
```
#### If b == 0
Third if (pink)
```c
if (data != 0) break;
// if byte is 0, save byte value and then point to the byte at i+2
ptr2[1] = *ptr3;
inputPtr = inputPtr + 2;
```
if b == 0
	save byte at `[addr + 1]`
	Increase the address by 2
#### If b == 1
Fourth if (green)
```c
if (data != 1) break;
// if data == 1, save the byte and increase pointer 2
data = *ptr3;
inputPtr = inputPtr + 2;
if (rOffset < inputPtr + data) break;
for (count = 0; count < (int)(uint)data; count = count + 1) {
char1 = *inputPtr;
inputPtr = inputPtr + 1;
if (0x19 < char1) goto LAB_00101654;
(&globalArray)[(int)(uint)char1] = 1;
}
```
Only continues if data == 1,
	Sets data to the byte at b+1
	
if b == 1
	break
Otherwise, continue
	Save the value at addr+1
	Increase addr by 2

Fifth if (orange)
Checks to see if our offset variable is less than our address + the saved value
	Breaks
Otherwise, continue into a loop
	Iterates through each character
		Breaks if the value is > 0x19
		Otherwise wipes out the data there

Call `handle` after the while loop
![[Pasted image 20240221164212.png]]
Checks to ensure that the offset counter is less than the addr value + 1
![[Pasted image 20240221164606.png]]

Checks `globalstate` - `globalstate` is incremented with each valid input (starting at 0)
It should match the value stored at `ptr2[1]` (which does increment with each valid input I think)
	If it doesn't, reset
After checking to see if it exists, it checks to for that data at `ptr2[1]`, which I guess determines if we erase the data  (determined by whether or not b == 2)

So if the globalstate is set as it should be and nothing is set to be cleared, we call check

![[Pasted image 20240221165344.png]]

Way more info in Ghidra
![[Pasted image 20240221165701.png]]
Notice that extra byte of 00 after each word with only 13 chars

```c
undefined8 check(void)

{
  char *__s;
  size_t sVar1;
  undefined8 uVar2;
  int x;
  int y;
  int z;
  
  __s = strs + (long)(int)(uint)globalstate * 0xf;
  for (x = 0; sVar1 = strlen(__s), (ulong)(long)x < sVar1; x = x + 1) {
    if ((&DAT_001040b1)[(int)(uint)(byte)(__s[x] + 0x9f)] != '\x01') goto LAB_0010137b;
  }
  y = 0;
  for (z = 0; z < 0x1a; z = z + 1) {
    if ((&DAT_001040b1)[z] == '\x01') {
      y = y + 1;
    }
  }
  sVar1 = strlen(__s);
  if ((long)y == sVar1) {
    globalstate = globalstate + 1;
    if (globalstate == 7) {
      uVar2 = 1;
    }
    else {
      puts("That\'s a nice word!");
      uVar2 = 0;
    }
  }
  else {
LAB_0010137b:
    puts("Meh, I\'m not feeling that");
    reset();
    uVar2 = 0;
  }
  return uVar2;
}
```

First condition
```c
  for (x = 0; sVar1 = strlen(__s), (ulong)(long)x < sVar1; x = x + 1) {
    if ((&DAT_001040b1)[(int)(uint)(byte)(__s[x] + 0x9f)] != '\x01') goto LAB_0010137b;
  }
```
Essentially, the `for` loop loops through every word in `__s` and checks to make sure that all values of `globalarray`


`if DATA[__s[x] + 0x9f] != 1`
That points to our global array
	Wants `globalarray[__s - 97]`
It wants to see that all values of the values in that global array equal 1 (for the length of the string)

Then, it checks to see if the total number of values set to one are equal to the length of the string (no cheating and filling everything with 1s)

If we do this 7 times, the global state is set to 7


Set up 

# Revisiting This
## Process Method
### Full Code:
```c

undefined8 process(void)

{
  int size;
  uint c;
  ssize_t r;
  byte *end;
  byte *ptr2;
  undefined8 v;
  int count;
  byte *addr;
  byte b;
  byte b2;
  byte *ptr3;
  
  addr = (byte *)malloc((ulong)BUFSIZE);
  memset(addr,0,(ulong)BUFSIZE);
  r = read(0,addr,(ulong)BUFSIZE);
  size = (int)r;
  if (size != 0) {
    end = addr + size;
    b = *addr;
    if ((size - 1U == (uint)b) && (3 < b)) {
      b2 = addr[1];
      addr = addr + 2;
      c = checksum((char *)addr,(char *)end);
      if (b2 == (byte)c) {
        ptr2 = (byte *)malloc(0x24);
        *ptr2 = b;
        *(uint *)(ptr2 + 0x20) = (uint)b2;
        while( true ) {
          while( true ) {
            while( true ) {
              if (end < addr + 1) {
                v = handle(ptr2);
                return v;
              }
              b = *addr;
              ptr3 = addr + 1;
              if (b != 2) break;
              addr = addr + 2;
              ptr2[0x1c] = *ptr3;
            }
            if (2 < b) goto LAB_00101654;
            if (b != 0) break;
            ptr2[1] = *ptr3;
            addr = addr + 2;
          }
          if (b != 1) break;
          b = *ptr3;
          addr = addr + 2;
          if (end < addr + b) break;
          for (count = 0; count < (int)(uint)b; count = count + 1) {
            b2 = *addr;
            addr = addr + 1;
            if (0x19 < b2) goto LAB_00101654;
            (&globalArray)[(int)(uint)b2] = 1;
          }
        }
      }
    }
  }
LAB_00101654:
  puts("Na, I don\'t like that");
  reset();
  return 0;
}

```
### First Series of Checks
```c
addr = (byte *)malloc((ulong)BUFSIZE);
memset(addr,0,(ulong)BUFSIZE);
r = read(0,addr,(ulong)BUFSIZE);
size = (int)r;
if (size != 0) {
end = addr + size;
b = *addr;
if ((size - 1U == (uint)b) && (3 < b)) {
  b2 = addr[1];
  addr = addr + 2;
  c = checksum((char *)addr,(char *)end);
  if (b2 == (byte)c) {
	ptr2 = (byte *)malloc(0x24);
	*ptr2 = b;
	*(uint *)(ptr2 + 0x20) = (uint)b2;
```
##### 1) `if ((size - 1U == (uint)b) && (3 < b)) `
`size - 1U == (uint)b)` returns true if the first value in the input (b) is equal to the length
`3 < b` returns true if b has a value greater than three, meaning there are at least three bytes of data
##### 2) Checksum stuff
If the first check is true, it saves the second value in the input (b2) and increases the address by 2
Then calculates the sum of the input data (from `word[2]` to `word[end]` essentially
##### 3) `if (b2 == (byte)c)`
Checks to see if that second value (b2) is equal to the checksum
Then it allocates new memory, setting the first byte to b and the 8th to b2
	(We will find out why later I hope)

#### Validating using GDB:

| Num | Type | Address | Operation | Statement |
| ---- | ---- | ---- | ---- | ---- |
| 1 | breakpoint | 0x00005555555554b7 | cmpl  $0x0,-0x2c(%rbp) | if (iVar5 != 0) { |
| 2 | breakpoint | 0x00005555555554f1 | cmp  %eax,-0x2c(%rbp) | if ((iVar5 - 1U == (uint)bVar |
| 3 | breakpoint | 0x00005555555554fa | cmpb  $0x3,-0x36(%rbp) | && (3 < bVar2)) { |
| 4 | breakpoint | 0x000055555555552e | cmp  %al,-0x35(%rbp) | if (bVar3 == bVar4) |
| 5 | breakpoint | 0x0000555555555572 | cmp  $0x2,%eax | if (bVar2 != 2) |
| 6 | breakpoint | 0x000055555555557b | cmp  $0x2,%eax | if (2 < bVar2) |
| 7 | breakpoint | 0x0000555555555588 | cmp  $0x1,%eax | while( true ) |
| 8 | breakpoint | 0x00005555555555c1 | cmp  %rax,-0x18(%rbp) | if (pbVar7 < local_30 + bVar2) |
| 9 | breakpoint | 0x00005555555555e3 | cmpb  $0x19,-0x31(%rbp) | if (0x19 < bVar3) |
| 10 | breakpoint | 0x0000555555555602 | cmp  %eax,-0x30(%rbp) | for (local_38 = 0; local_38 < (int)(uint)bVar2; local_38 = local_38 + 1) |
| 11 | breakpoint | 0x000055555555562c | cmp  %rax,-0x18(%rbp) | if (pbVar7 < local_30 + 1) |

```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ gdb ./heterograms
(gdb) break process
Breakpoint 1 at 0x146a
(gdb) r
Starting program: /home/kali/Desktop/3-Week/heterograms 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Send me some data to get the flag!

Breakpoint 1, 0x000055555555546a in process ()
(gdb) disas process
Dump of assembler code for function process:
   0x0000555555555462 <+0>:     endbr64
   0x0000555555555466 <+4>:     push   %rbp
   0x0000555555555467 <+5>:     mov    %rsp,%rbp
=> 0x000055555555546a <+8>:     sub    $0x40,%rsp
...omitted for brevity...
   0x0000555555555526 <+196>:   mov    %rax,%rdi
   0x0000555555555529 <+199>:   call   0x55555555542b <checksum>
   0x000055555555552e <+204>:   cmp    %al,-0x35(%rbp)
...omitted for brevity...
(gdb) break *0x0000555555555529
Breakpoint 2 at 0x555555555529
(gdb) break *0x000055555555552e
Breakpoint 3 at 0x55555555552e

```
### Then it gets upsetting
##### Code:
```c
while( true ) {
  while( true ) {
	while( true ) {
	  if (end < addr + 1) {
		v = handle(ptr2);
		return v;
	  }
	  b = *addr;
	  ptr3 = addr + 1;
	  if (b != 2) break;
	  addr = addr + 2;
	  ptr2[0x1c] = *ptr3;
	}
	if (2 < b) goto LAB_00101654;
	if (b != 0) break;
	ptr2[1] = *ptr3;
	addr = addr + 2;
  }
  if (b != 1) break;
  b = *ptr3;
  addr = addr + 2;
  if (end < addr + b) break;
  for (count = 0; count < (int)(uint)b; count = count + 1) {
	b2 = *addr;
	addr = addr + 1;
	if (0x19 < b2) goto LAB_00101654;
	(&globalArray)[(int)(uint)b2] = 1;
  }
}
```
#### First While Loop
###### Code:
```c
while( true ) {
  if (end < addr + 1) {
	v = handle(ptr2);
	return v;
  }
  b = *addr;
  ptr3 = addr + 1;
  if (b != 2) break;
  addr = addr + 2;
  ptr2[0x1c] = *ptr3;
}
```
##### `if (end < addr + 1)`
Stops everything once we've looped through each value in the input
Call's "handle" and passes it the pointer to our second set of memory. Ptr2 indicates our global state
Then it returns the response
##### Otherwise:
Saves the byte at the current address as `b`
Saves addr+1 in `ptr3`
##### If b == 2
Increases addr by two so that `addr = index of b + 2`
Sets the value at `ptr2[0x1c]` to `addr-1` aka `inde of b + 1`
	This sets thee `global array` to be cleared