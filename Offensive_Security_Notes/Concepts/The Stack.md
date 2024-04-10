From [CTF 101](https://ctf101.org/binary-exploitation/what-is-the-stack/)
In computer architecture, the stack is a hardware manifestation of the stack data structure.
	It's a Last In, First Out queue
In x86, the stack is an area in RAM, there is no special hardware to store stack contents. The `ESP`/`RSP` register holds the address in memory where the bottom of the stack resides. When something is `pushed` onto the stack, `ESP` decrements by 4 and the value that was `pushed` is stored at that location in memory.
	`ESP` decrements by 8 for 64-bit x86
Likewise, when a `pop` instruction is executed, the value at `ESP` is retrieved (ie: `ESP` is *dereferenced*), and `ESP` is incremented by 4 (or 8).
##### The stack "grows" down to lower memory addresses
Conventionally, `EBP`/`RBP` contains the address at the top of the current *stack frame* and sometimes local variables are referenced as an offset relative to `EBP` rather than `ESP`. 
	The *stack frame* is just the space used on the stack by a given function.
## Uses
The stack is primarily used for:
* Storing function arguments
* Storing local variables
* Storing the processor state between function calls
## Example
###### Code:
```c
# include <stdio.h>
void say_hi(const char * name) {
    printf("Hello %s!\n", name);
}

int main(int argc, char ** argv) {
    char * name;
    if (argc != 2) {
        return 1;
    }
    name = argv[1];
    say_hi(name);
    return 0;
}
```
###### Assembly:
```
0804840b <say_hi>:
 804840b:   55                      push   ebp
 804840c:   89 e5                   mov    ebp,esp
 804840e:   83 ec 08                sub    esp,0x8
 8048411:   83 ec 08                sub    esp,0x8
 8048414:   ff 75 08                push   DWORD PTR [ebp+0x8]
 8048417:   68 f0 84 04 08          push   0x80484f0
 804841c:   e8 bf fe ff ff          call   80482e0 <printf@plt>
 8048421:   83 c4 10                add    esp,0x10
 8048424:   90                      nop
 8048425:   c9                      leave
 8048426:   c3                      ret

08048427 <main>:
 8048427:   8d 4c 24 04             lea    ecx,[esp+0x4]
 804842b:   83 e4 f0                and    esp,0xfffffff0
 804842e:   ff 71 fc                push   DWORD PTR [ecx-0x4]
 8048431:   55                      push   ebp
 8048432:   89 e5                   mov    ebp,esp
 8048434:   51                      push   ecx
 8048435:   83 ec 14                sub    esp,0x14
 8048438:   89 c8                   mov    eax,ecx
 804843a:   83 38 02                cmp    DWORD PTR [eax],0x2
 804843d:   74 07                   je     8048446 <main+0x1f>
 804843f:   b8 01 00 00 00          mov    eax,0x1
 8048444:   eb 1c                   jmp    8048462 <main+0x3b>
 8048446:   8b 40 04                mov    eax,DWORD PTR [eax+0x4]
 8048449:   8b 40 04                mov    eax,DWORD PTR [eax+0x4]
 804844c:   89 45 f4                mov    DWORD PTR [ebp-0xc],eax
 804844f:   83 ec 0c                sub    esp,0xc
 8048452:   ff 75 f4                push   DWORD PTR [ebp-0xc]
 8048455:   e8 b1 ff ff ff          call   804840b <say_hi>
 804845a:   83 c4 10                add    esp,0x10
 804845d:   b8 00 00 00 00          mov    eax,0x0
 8048462:   8b 4d fc                mov    ecx,DWORD PTR [ebp-0x4]
 8048465:   c9                      leave
 8048466:   8d 61 fc                lea    esp,[ecx-0x4]
 8048469:   c3                      ret
```

So, what does the stack look like after `say_hi` has been called?
	This program is in 32-but x86 c
Skipping over the bulk of `main`, you'll see that at `0x8048452`, the `main` method's local variable `name` is pushed to the stack as the first argument to `say_hi`. Then, it executes a `call` instruction.
```c
say_hi(name);
```
```
08048427 <main>:
 ...omitted for brevity...
 8048452:   ff 75 f4                push   DWORD PTR [ebp-0xc]
 8048455:   e8 b1 ff ff ff          call   804840b <say_hi>
```
The `call` instructions first push the current pointer to the stack, then jump to their destination.

So when the processor begins executing `say_hi` at `0x0804840b`, the stack looks like this:
```
EIP = 0x0804840b (push ebp)
ESP = 0xffff0000
EBP = 0xffff002c

        0xffff0004: 0xffffa0a0              // say_hi argument 1
ESP ->  0xffff0000: 0x0804845a              // Return address for say_hi
```

The first thing `say_hi` does is save the current `EBP` so that when it returns, `EBP` is back where `main` expects it to be.
```
0804840b <say_hi>:
 804840b:   55                      push   ebp <--
 804840c:   89 e5                   mov    ebp,esp
```
The stack now looks like:
```
EIP = 0x0804840c (mov ebp, esp)
ESP = 0xfffefffc
EBP = 0xffff002c

        0xffff0004: 0xffffa0a0              // say_hi argument 1
        0xffff0000: 0x0804845a              // Return address for say_hi
ESP ->  0xfffefffc: 0xffff002c              // Saved EBP
```
**Note**: `ESP` gets smaller when the values are pushed to the stack

Next, the current `ESP` is saved into `EBP`, marking the top of the new stack frame:
```
0804840b <say_hi>:
 804840b:   55                      push   ebp 
 804840c:   89 e5                   mov    ebp,esp <--
 804840e:   83 ec 08                sub    esp,0x
```
Stack:
```
EIP = 0x0804840e (sub esp, 0x8)
ESP = 0xfffefffc
EBP = 0xfffefffc

            0xffff0004: 0xffffa0a0              // say_hi argument 1
            0xffff0000: 0x0804845a              // Return address for say_hi
ESP, EBP -> 0xfffefffc: 0xffff002c              // Saved EBP
```

Then, the stack is "grown" to accommodate the local variables in `say_hi`:
```
0804840b <say_hi>:
 804840b:   55                      push   ebp
 804840c:   89 e5                   mov    ebp,esp
 804840e:   83 ec 08                sub    esp,0x8
 8048411:   83 ec 08                sub    esp,0x8 <--
 8048414:   ff 75 08                push   DWORD PTR [ebp+0x8]
```
Stack:
```
EIP = 0x08048414 (push [ebp + 0x8])
ESP = 0xfffeffec
EBP = 0xfffefffc

        0xffff0004: 0xffffa0a0              // say_hi argument 1
        0xffff0000: 0x0804845a              // Return address for say_hi
EBP ->  0xfffefffc: 0xffff002c              // Saved EBP
        0xfffefff8: UNDEFINED
        0xfffefff4: UNDEFINED
        0xfffefff0: UNDEFINED
ESP ->  0xfffefffc: UNDEFINED
```
**Note**: Stack space is **not** implicitly cleared!

Now, the two arguments sent to `printf` are pushed **in reverse order**:
```
0804840b <say_hi>:
 804840b:   55                      push   ebp
 ...omitted for brevity...
 8048414:   ff 75 08                push   DWORD PTR [ebp+0x8]
 8048417:   68 f0 84 04 08          push   0x80484f0 <--
 804841c:   e8 bf fe ff ff          call   80482e0 <printf@plt>
```
Stack:
```
EIP = 0x0804841c (call printf@plt)
ESP = 0xfffeffe4
EBP = 0xfffefffc

        0xffff0004: 0xffffa0a0              // say_hi argument 1
        0xffff0000: 0x0804845a              // Return address for say_hi
EBP ->  0xfffefffc: 0xffff002c              // Saved EBP
        0xfffefff8: UNDEFINED
        0xfffefff4: UNDEFINED
        0xfffefff0: UNDEFINED
        0xfffeffec: UNDEFINED
        0xfffeffe8: 0xffffa0a0              // printf argument 2
ESP ->  0xfffeffe4: 0x080484f0              // printf argument 1
```

Finally, when `printf` is called, the address of the next instruction to execute is pushed on the stack:
```
0804840b <say_hi>:
 804840b:   55                      push   ebp
 ...omitted for brevity...
 804841c:   e8 bf fe ff ff          call   80482e0 <printf@plt> <--
 8048421:   83 c4 10                add    esp,0x10
```
Note that `EIP` does **not** point to the next instruction in `say_hi`
Stack:
```
EIP = 0x080482e0
ESP = 0xfffeffe4
EBP = 0xfffefffc

        0xffff0004: 0xffffa0a0              // say_hi argument 1
        0xffff0000: 0x0804845a              // Return address for say_hi
EBP ->  0xfffefffc: 0xffff002c              // Saved EBP
        0xfffefff8: UNDEFINED
        0xfffefff4: UNDEFINED
        0xfffefff0: UNDEFINED
        0xfffeffec: UNDEFINED
        0xfffeffe8: 0xffffa0a0              // printf argument 2
        0xfffeffe4: 0x080484f0              // printf argument 1
ESP ->  0xfffeffe0: 0x08048421              // Return address for printf
```

Once `printf` has returned and we're back to `say_hi`, the `leave` instruction moves `EBP` into `ESP` and `pops` the saved `EBP`
```
0804840b <say_hi>:
 ...omitted for brevity...
 804841c:   e8 bf fe ff ff          call   80482e0 <printf@plt>
 8048421:   83 c4 10                add    esp,0x10
 8048424:   90                      nop
 8048425:   c9                      leave <--
 8048426:   c3                      ret
```
Stack:
```
EIP = 0x08048426 (ret)
ESP = 0xfffefffc
EBP = 0xffff002c

        0xffff0004: 0xffffa0a0              // say_hi argument 1
ESP ->  0xffff0000: 0x0804845a              // Return address for say_hi
```

Finally, `ret` will `pop` the saved instruction pointer into `EIP`, which causes the program to return to `mmain` with the same `ESP`, `EBP`, and stack contents as when `say_hi` was initially called!
```
08048427 <main>:
 ...omitted for brevity...
 8048455:   e8 b1 ff ff ff          call   804840b <say_hi>
 804845a:   83 c4 10                add    esp,0x10
 804845d:   b8 00 00 00 00          mov    eax,0x0
 8048462:   8b 4d fc                mov    ecx,DWORD PTR [ebp-0x4]
 8048465:   c9                      leave
 8048466:   8d 61 fc                lea    esp,[ecx-0x4]
 8048469:   c3                      ret
```
Stack:
```
EIP = 0x0804845a (add esp, 0x10)
ESP = 0xffff0000
EBP = 0xffff002c

ESP ->  0xffff0004: 0xffffa0a0              // say_hi argument 1
```
