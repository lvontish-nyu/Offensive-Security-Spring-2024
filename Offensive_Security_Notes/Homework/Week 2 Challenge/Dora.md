Connection: `nc offsec-chalbroker.osiris.cyber.nyu.edu 1250`
Lore: `Dora the explorer`
Points: `150`
Flag: `flag{mmaped_some_fresh_pages}`

```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  undefined8 *puVar1;
  long lVar2;
  undefined8 uVar3;
  ulong counter;
  
  init(param_1);
  puVar1 = (undefined8 *)mmap((void *)0x0,0x1000,7,0x22,-1,0);
  uVar3 = DAT_00104028;
  *puVar1 = read_flag;
  puVar1[1] = uVar3;
  uVar3 = DAT_00104038;
  puVar1[2] = DAT_00104030;
  puVar1[3] = uVar3;
  uVar3 = DAT_00104048;
  puVar1[4] = DAT_00104040;
  puVar1[5] = uVar3;
  uVar3 = DAT_00104058;
  puVar1[6] = DAT_00104050;
  puVar1[7] = uVar3;
  uVar3 = DAT_00104068;
  puVar1[8] = DAT_00104060;
  puVar1[9] = uVar3;
  puts("What\'s the key?");
  lVar2 = get_number();
  if ((lVar2 < 0) || (0xff < lVar2)) {
    puts("That key is out of range :( Try again?");
    uVar3 = 1;
  }
  else {
    for (counter = 0; counter < 0x50; counter = counter + 1) {
      *(byte *)(counter + (long)puVar1) = *(byte *)(counter + (long)puVar1) ^ (byte)lVar2;
    }
    (*(code *)puVar1)();
    uVar3 = 0;
  }
  return uVar3;
}
```

 **mmap**() creates a new mapping in the virtual address space of the calling process.  The starting address for the new mapping is  specified in _addr_.  The _length_ argument specifies the length of  the mapping (which must be greater than 0).
``
`void *mmap(void addr[.length], size_t length, int prot, int flags, int fd, off_t offset);`

So Our map
`puVar1 = (undefined8 *)mmap((void *)0x0,0x1000,7,0x22,-1,0)`
	`addr` = `0x0`
	`length` = `0x100`
	`prot` = `7`
	`flags` = `0x22`
	`fd` = `-1`
	`offset` = `0`


Okay, so what does this do
Creates a map
Sets it as the pointer to `get flag`
Puts data in it

Goes through each byte and xors it with the data I entered
Then tries to call that address (puts it in `rdx` and then does `call rdx`)

Gonna step through and see what values are being xored I guess

My guess is, it's gonna end up wanting to call the location of read flag?
She's just in here with the other data:
![[Pasted image 20240214113116.png]]

Plan, use a script to pull all of the values out, use a solver to find a value that makes that work ...profit

Run through looking at values
```
gdb ./dora
...omitted for brevity...
(gdb) disas main
Dump of assembler code for function main:
...omitted for brevity...
   0x000055555555538d <+275>:   mov    -0x28(%rbp),%rcx
   0x0000555555555391 <+279>:   mov    -0x30(%rbp),%rax
   0x0000555555555395 <+283>:   add    %rcx,%rax
   0x0000555555555398 <+286>:   xor    %esi,%edx
   0x000055555555539a <+288>:   mov    %dl,(%rax)
   0x000055555555539c <+290>:   addq   $0x1,-0x30(%rbp)
...omitted for brevity...
(gdb) break *0x0000555555555398
Breakpoint 2 at 0x555555555398
(gdb) break *0x000055555555539a
Breakpoint 3 at 0x55555555539a
Breakpoint 1.1, 0x0000555555555100 in _start ()
(gdb) c
Continuing.
What's the key?
23

Breakpoint 2, 0x0000555555555398 in main ()
(gdb) info registers edx
edx            0x97                151
(gdb) info registers esi
esi            0x17                23
(gdb) c
Continuing.

Breakpoint 3, 0x000055555555539a in main ()
(gdb) info registers esi
esi            0x17                23
(gdb) info registers edx
edx            0x80                128
(gdb) c
Continuing.

Breakpoint 2, 0x0000555555555398 in main ()
(gdb) info registers edx
edx            0x46                70
(gdb) info registers esi
esi            0x17                23
(gdb) c
Continuing.

Breakpoint 3, 0x000055555555539a in main ()
(gdb) info registers edx
edx            0x51                81
(gdb) c
Continuing.

Breakpoint 2, 0x0000555555555398 in main ()
(gdb) info registers edx
edx            0x23                35
(gdb) info registers esi
esi            0x17                23
(gdb) c
Continuing.

Breakpoint 3, 0x000055555555539a in main ()
(gdb) info registers edx
edx            0x34                52
(gdb) q

```
It looks like these values are the start of read_flag, which is interesting

So this is gonna get us the data:
### `Dora_GetBytes.py`
```python
def main():
	
	# Start gdb session
	p =  process('/bin/bash')
	p.sendline('gdb ./dora -q')
	p.sendline('break _start')
	p.recv() # GDB response with one line indicating that the breakpoint is set
	p.sendline('r')
	p.sendline('break *0x0000555555555398')
	p.recv()
	p.sendline('clear _start')
	p.recv()
	p.sendline('c')
	p.recvuntil(b'What\'s the key?')
	p.sendline(b'23')
	p.sendline('c')

	data = []

	for i in range(80):
		p.recvuntil(b'Breakpoint 2')
		p.recvline()
		p.sendline('info registers edx')
		c = cleanLine(p.recvline())
		r = re.split("\s+", c)
		data.append(r[2])
		p.sendline('c')

	print(data)
```
And here is our data:
```
['0x97', '0x46', '0x23', '0x34', '0x4d', '0x8a', '0xc4', '0x7e', '0x7c', '0x7c', '0x7c', '0x73', '0x79', '0x97', '0x47', '0x22', '0x34', '0xf5', '0xbb', '0xc6', '0x83', '0x7c', '0x7c', '0x7c', '0xc4', '0x7c', '0x7c', '0x7c', '0x7c', '0x73', '0x79', '0xc3', '0x7d', '0x7c', '0x7c', '0x7c', '0xc6', '0x83', '0x7c', '0x7c', '0x7c', '0xc4', '0x7d', '0x7c', '0x7c', '0x7c', '0x73', '0x79', '0xc3', '0x7c', '0x7c', '0x7c', '0x7c', '0xc4', '0x40', '0x7c', '0x7c', '0x7c', '0x73', '0x79', '0x94', '0xbd', '0x83', '0x83', '0x83', '0x1a', '0x10', '0x1d', '0x1b', '0x52', '0x8', '0x4', '0x8', '0x7c', '0x94', '0xbc', '0x83', '0x83', '0x83', '0x0']
```

Script will loop through 0-256, xor it with each byte, and seee if we get any usable data
```python
def bruteForceMagic():
    for i in range(256):
        data = bytes(c ^ i for c in test_chars)
        print(data)
    return 0
```
Data looks like garbage...EXCEPT
```bash
python3 Dora_BF.py | grep -i "flag"
b'\xcb\x1a\x7fh\x11\xd6\x98"   /%\xcb\x1b~h\xa9\xe7\x9a\xdf   \x98    /%\x9f!   \x9a\xdf   \x98!   /%\x9f    \x98\x1c   /%\xc8\xe1\xdf\xdf\xdfFLAG\x0eTXT \xc8\xe0\xdf\xdf\xdf\\'
b'\xeb:_H1\xf6\xb8\x02\x00\x00\x00\x0f\x05\xeb;^H\x89\xc7\xba\xff\x00\x00\x00\xb8\x00\x00\x00\x00\x0f\x05\xbf\x01\x00\x00\x00\xba\xff\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05\xbf\x00\x00\x00\x00\xb8<\x00\x00\x00\x0f\x05\xe8\xc1\xff\xff\xffflag.txt\x00\xe8\xc0\xff\xff\xff|'
```

So, now we must figure out where that is
New script:
```python
def bruteForceMagic():
    for i in range(256):
        data = bytes(c ^ i for c in test_chars)
        if 'flag'.encode() in data:
            return i
    return 0
```
Gets us:
```
python3 Dora_BF.py
124
```


Does she work? Maybe? This is the local one
```
$ gdb ./dora           
...omitted for brevity...
(gdb) r
Starting program: /home/kali/Desktop/2-Week/dora 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
What's the key?
124
|[Inferior 1 (process 90978) exited normally]
(gdb) q

```

Trying now:
```
nc offsec-chalbroker.osiris.cyber.nyu.edu 1250
What's the key?
124
flag{mmaped_some_fresh_pages}
```


YAYYYYYY
