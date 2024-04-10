# Explanation from [CTF 101](https://ctf101.org/binary-exploitation/no-execute/)
No eXecute
* NX Bit
* Also called Data Execution Prevention or DEP

The NX bit marks certain areas of the program as **not executable**
* Stored data cannot be executed as code
* This prevents attackers from being able to jump to custom shellcode that they've stored in the stack or a global variable