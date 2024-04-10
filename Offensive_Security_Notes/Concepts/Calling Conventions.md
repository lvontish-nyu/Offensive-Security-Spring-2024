[From CTF 101](https://ctf101.org/binary-exploitation/what-are-calling-conventions/)

To call functions, there must be an agreed-upon way to pass arguments.
* If a program is entirely self-contained in a binary, the compiler would be free to decide the calling convention
* However, in most cases, shared libraries are used so that common code (e.g. `libc`) can be stored once and dynamically linked to programs that need it
	* This reduces program size

In Linux binaries, there are really only two commonly used calling conventions:
* **32-Bit Binaries**: `cdecl`
* **64-Bit Binaries**: `SysV`

# `cdecl`
In 32-bit Linux binaries, function arguments are passed on [[The Stack]] in reverse order.

We have a function like so:
```c
int add(int a, int b, int c) {
    return a + b + c;
}
```
Invoke it by:
1) Push `c`
2) Push `b`
3) Push `a`

# `SysV`
For 64-bit binaries, arguments are first passed in certain registers (in this order?)
1) `RDI`
2) `RSI`
3) `RDX`
4) `RCX`
5) `R8`
6) `R9`
Any leftover arguments are pushed onto the stack in the reverse order, as in `cdecl`.

# Other Conventions
Any method of passing arguments could be used as long as the compiler is aware of the convention.
* This has resulted in *many* weird calling conventions, especially in the past
* [There is a comprehensive list on Wikipedia](https://en.wikipedia.org/wiki/X86_calling_conventions)