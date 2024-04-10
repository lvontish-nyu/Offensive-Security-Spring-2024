More for [[Heterograms]]
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
| 1 | breakpoint | 0x00005555555554b7 | cmpl  $0x0,-0x2c(%rbp) | if (size != 0) { |
| 2 | breakpoint | 0x00005555555554f1 | cmp  %eax,-0x2c(%rbp) | size - 1U == (uint)b |
| 3 | breakpoint | 0x00005555555554fa | cmpb  $0x3,-0x36(%rbp) | && (3 < b)) { |
| 4 | breakpoint | 0x000055555555552e | cmp  %al,-0x35(%rbp) | if (b2 == (byte)c) |
| 5 | breakpoint | 0x0000555555555572 | cmp  $0x2,%eax | if (b != 2)  |
| 6 | breakpoint | 0x000055555555557b | cmp  $0x2,%eax | if (2 < b) |
| 7 | breakpoint | 0x0000555555555588 | cmp  $0x1,%eax | while( true ) |
| 8 | breakpoint | 0x00005555555555c1 | cmp  %rax,-0x18(%rbp) | if (end < addr + b) |
| 9 | breakpoint | 0x00005555555555e3 | cmpb  $0x19,-0x31(%rbp) | if (0x19 < b2) |
| 10 | breakpoint | 0x0000555555555602 | cmp  %eax,-0x30(%rbp) | for (count = 0; count < (int)(uint)b; count = count + 1) |
| 11 | breakpoint | 0x000055555555562c | cmp  %rax,-0x18(%rbp) | if (end < addr + 1) |
Validation
Sending `\x04\x02\x01\x01` gets me through the first three conditions/breakpoints, but I need to get through 4
```
┌──(kali㉿kali)-[~/Desktop/3-Week]
└─$ python3 HGram_Debug_Local.py
Breakpoint 1
(gdb) $2 = 5
(gdb) rax            0x5                 5

Breakpoint 2
(gdb) $4 = 4
(gdb) eax            0x4                 4

Breakpoint 3
(gdb) $5 = 0x7fffffffdc7a
(gdb) $6 = 0x7ffff704
Compare to 0x3

Breakpoint 4
(gdb) $8 = 8388354
(gdb) al             0xf3                -13

zsh: suspended (signal)  python3 HGram_Debug_Local.py
```
I'm not sure why breakpoint 3 passed but it did so...yay
Okay, I know now why, because the first byte at that address is four
```
Breakpoint 3
(gdb) $ x/1ub $rbp-0x36
0x7fffffffdc7a:    4

Breakpoint 4, 0x000055555555552e in process ()
(gdb) $ x/5i $pc
=> 0x55555555552e <process+204>:    cmp    %al,-0x35(%rbp)
   0x555555555531 <process+207>:    jne    0x55555555564a <process+488>
   0x555555555537 <process+213>:    mov    $0x24,%edi
   0x55555555553c <process+218>:    call   0x555555555110 <malloc@plt>
   0x555555555541 <process+223>:    mov    %rax,-0x8(%rbp)
(gdb) $ x/1ub $rbp-0x35
0x7fffffffdc7b:    2
(gdb) $ info registers al
al             0xf3                -13
(gdb) $ info registers eax
eax            0xfffffff3          -13

```
BUT TELL ME WHY `AL` is storing `-13`
Oh fuck me because `checkpoint` returns a NOT

Somehow, it gets the sum as 12 before the NOT occurs:
```
Breakpoint 14, 0x000055555555545e in checksum ()
(gdb) $ info registers eax
eax            0xc                 12
(gdb) $ x/5i $pc
=> 0x55555555545e <checksum+51>:    not    %eax
   0x555555555460 <checksum+53>:    pop    %rbp
   0x555555555461 <checksum+54>:    ret
   0x555555555462 <process>:    endbr64
   0x555555555466 <process+4>:    push   %rbp
(gdb) $ break *0x555555555460
Breakpoint 16 at 0x555555555460
(gdb) $ c
Continuing.

Breakpoint 16, 0x0000555555555460 in checksum ()
(gdb) $ info registers eax
eax            0xfffffff3          -13
(gdb) $ c
Continuing.
```
Math
```
12 = 0x0c
255 = 0xff

0x0c - 0xff = -0xf3

0xf3 = 13
so in this case, -0xf3 == -13
```

It looks like it's going through four things:
```
Breakpoint 12, 0x000055555555544b in checksum ()
(gdb) $ info registers al
al             0x1                 1
(gdb) $ x/1ub $rbp-0x1
0x7fffffffdc5f:    1
(gdb) $ c
Continuing.

Breakpoint 12, 0x000055555555544b in checksum ()
(gdb) $ info registers al
al             0x1                 1
(gdb) $ x/1ub $rbp-0x1
0x7fffffffdc5f:    2
(gdb) $ c
Continuing.

Breakpoint 12, 0x000055555555544b in checksum ()
(gdb) $ info registers al
al             0xa                 10
(gdb) $ x/1ub $rbp-0x1
0x7fffffffdc5f:    12
(gdb) $ c
Continuing.

Breakpoint 12, 0x000055555555544b in checksum ()
(gdb) $ info registers al
al             0x0                 0
(gdb) $ x/1ub $rbp-0x1
0x7fffffffdc5f:    12
(gdb) $ c
Continuing.

Breakpoint 13, 0x000055555555545e in checksum ()
(gdb) $ info registers al
al             0xc                 12
(gdb) $ x/1ub $rbp-0x1
0x7fffffffdc5f:    12
(gdb) $ c
Continuing.

Breakpoint 14, 0x0000555555555460 in checksum ()

```
Not sure where that `0xa` is coming from

Gonna focus on the rest of the things, but I know when I build my payload, that the second item needs to equal to Sum-255
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
We go into this while loop with addr pointing to `start + 2`
##### `if (end < addr + 1)`
Stops everything once we've looped through each value in the input
Call's "handle" and passes it the pointer to our second set of memory. Ptr2 indicates our global state
Then it returns the response
##### Otherwise:
Saves the byte at the current address as `b`
	It's worth noting that, at this point, addr is = to startAddr + 2
Saves addr+1 in `ptr3`
##### If b == 2
Increases addr by two so that `addr = index(b)  + 2`
Sets the value at `ptr2[0x1c]` to `addr-1` aka `index(b) + 1`
	This sets thee `global array` to be cleared
Goes back into the while loop

Otherwise, we go into the
#### Second While Loop
###### Code:
```c
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
```
##### If b > 2
Straight to jail
##### If b == 0
`ptr2[1] = *ptr3;` sets `globalstate` to the value at `index(b) + 1`
Increase `addr` by 2 again
Loop back around

Otherwise, break into the
#### Third While Loop
###### Code:
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
##### If b == 1
```c
b = *ptr3;
addr = addr + 2;
if (end < addr + b) break;
for (count = 0; count < (int)(uint)b; count = count + 1) {
	b2 = *addr;
	addr = addr + 1;
	if (0x19 < b2) goto LAB_00101654;
	(&globalArray)[(int)(uint)b2] = 1;
}
```
Set b as the byte at `index(b) + 1`
Increase `addr` by 2
Breaks if `addr + b` is greater than `end`
Loops `b` times:
	stores the value at `addr` in `b2` before increasing it
		Breaks if that value is > 25
	Otherwise sets the value in the `globalArray` at `int(b2)` to 1

The program calls `handle` IF we reach the end of the input data successfully

