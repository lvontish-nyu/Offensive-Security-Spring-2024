Someone in the slack recommended [this article](https://cyber.cole-ellis.com/binex/01-ret2win/win64) on [[64-Bit Ret2Win]] for the ROP part of this challenge

# Slides - Pwning 5: Overlaps and Glibc's Heap Allocator
## Visualizing Overlaps
Overlaps are one of the most powerful heap primitives
* Can lead to metadata or pointer corruption
* Can hijack execution flow easily
* Can be hard to visualize
###### Example:
```c
 struct a {
	uint64_t param1;
	uint64_t param2;
	char* param3;
 };
 
 struct b {
	char* param1;
	uint64_t param2;
	uint64_t param3;
 };
 
 struct c {
	uint64_t param1;
	char* param2;
	void (*param3)(uint64_t, char*);
 };
```

Now look at the 