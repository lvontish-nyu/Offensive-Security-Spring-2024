# Heap 1 - Intro and UAF
Slides
## What is the Heap?
The heap is just another location in memory.
* ASLR - Randomized Location
* RW - Non executable
	* So can't just jump to shellcode (by default)

Allocations to the heap are made through `malloc()` and `free()`
* the OS doesn't know much about the heap
	* The libraries manage it
	* uses function calls to allocate memory to processes

Heap Advantages
* Use memory between functions
* Can allocate very large blobs
	* Even larger than the stack

The heap is vulnerable to the same types of bugs we've seen in the stack
* ex: overflows
Many classes of bugs generally exist on the heap
* Unfreed allocation - Potential Memory Leak
* Double free'd allocation - potentially exploitable
	* Freeing it again may cause the free function to interpret it weird
* Using a free'd allocation - commonly exploitable
### Heap Characteristics
Grows up towards the stack
* sits on top of `bss` (uninitialized data)
The heap was intended to be high performance, so they made optimizations:
* no zero-ing out of memory
* Tries to re-use blocks of the same size for future allocations
* Avoids overhead allocations
### In this class, we're focusing on the glibc implementation of malloc

## Heap Usage
###### `void* p = malloc(size_t n)`
* Returns a pointer to a newly allocated chunk of at least `n` bytes
* It should allign to 16 bytes (implementation specific)
	* Last 4 bits of malloc addresses should be `0`
	* Includes heap metadata
	* This simplifies malloc internals
### Malloc Chunks
![[Pasted image 20240322154118.png]]

Flags (Last 4 bits of chunk size)
	`A`: Arena of allocation
		`0`: Main arena
		`1`: mmap
	`M`: mmap
		`0`: Part of Heap
		`1`: Mmap allocation (not part of heap)
	`P`: **Previous Chunk** (Remember this one for class)
		`0`: Previous chunk unallocated
			Previous size is set
		`1`: Previous chunk allocated
#### Example Chunk Size: `0x21`
Details:
	User data size: `0x20`
	Part of main arena heap (not mmap)
	Previous chunk is allocated
### `free (void * p)`
This frees the chunk that `p` points to
* `p` shouldn't have been freed already
	* Glibc does not care though
* `p` should be nulled out afterwards
	* Avoid "use after free-ing"
	* `p = 0`
![[Pasted image 20240322202933.png]]


User-data truncated and end used for pointers/sizes
* `FWD` Ptr
* `BCK` Ptr
* For larger allocations:
	* `FWD` size: Pointer to the next larger free chunk
	* `BCK` Size: Pointer to the previous smaller free chunk
## Heap Issues
### Use After Free (UAF)
C doesn't track allocations on its own
* This is up to the programmer
* If the pointer isn't nullified after the free, it's a **dangling pointer**
* This can be abused
#### Example: Structs With Function Pointers
This is a common issue
```c
struct example {
	void (* toUpper)(char *);
	char buffer[16];
}
```
###### `STRUCT example`:
![[Pasted image 20240322204117.png]]

The pointer remains even after the memory is freed
##### Other structures to abuse:
```c
struct exampleTwo {
	uint64 somVal;
}
```
###### `STRUCT exampleTwo`:
![[Pasted image 20240322204248.png]]

##### What happens if we can "overlay" a different type of object?
* Then call `example.toUpper()`
* Will it be `toUpper()` that gets called?
![[Pasted image 20240322204433.png]]
## Other Issues
UAF can be used for information leaks as well
UAF is difficult to detect during static source code analysis


# Other Resources
[[Heap Exploitation]]
[[Use After Free]]

# Addendum - glibc heap allocator
More slides...yay
## glibc versions
* silent for the most part
* Always backwards compatable
* Heap allocator upgrades can break exploits
	* *...or introduce new exploitation strategies...*
##### Check your glibx version:
![[Pasted image 20240324150112.png]]
### Other resources:
[glibc repo versions](https://repology.org/project/glibc/versions)
[Shellphish how2heap](https://github.com/shellphish/how2heap)
[glibc latest source](https://elixir.bootlin.com/glibc/latest/source)

## glibc < 2.32
Before "safe linking"
### Heap Function Pointers
* Many structures in large C programs have function pointers
	Ex: `int* (function)(int, char*)`
* C++ classes include the virtual function table (if applicable) in the first qword
	* This is a pointer to an array of pointer
* This may allow you to hijack the instruction pointer (IP)
	* Heap overflow
	* UAF + glibc leak
### Other Options
Need a location/address that is:
* invoked during execution
* reachable from the corrupted cache
* Has controllable parameters
Assume:
* We have a UAF or another semi-arbitrary way to leak the glibc address
* Corrupted cache means we have a semi-arbitrary write of `size` length
### Allocation Hooks
```
__malloc_hook
__free_hook
__realloc_hook
__memalign_hook
```

Allocation hooks are stubs to redirect allocations to debugging functions
* located in glibc
* Checked and called (if non-Null) when the original function is invoked
## Ex: `__free_hook`
```c
void
__libc_free ( void * mem)
{
	mstate ar_ptr;
	mchunkptr p;       /* chunk corresponding to mem */
	void (*hook) ( = void *, const void *) atomic_forced_read (__free_hook);
	if ( __builtin_expect (hook !=  NULL, 0 ))
	{
		(*hook)(mem, RETURN_ADDRESS (0 return; ));
	}
```
### Tactics
1) Leak glibc address
2) Find address of `__X_hook` in glibc
	Ex: `p & __free_hook`
3) Corrupt the cache to add the address of the hook
4) Overwrite hook to a function address
	Ex: `system`
5) Invoke a call with the hooked function
![[Pasted image 20240324151911.png]]



# UAF to Leak Addresses
Uses this code:
###### `leak.c`
```c
// NOTE: The leak strategy for heap addresses only works for glibc < 2.32. We
// will talk about how to leak heap addresses using UAFs for glibc >=2.32 in
// next week's content

#include 
#include 
#include 
#include 

const int STRING_LEN_HEAP = 0x40;
// allocate size large enough to avoid tcache; when freed, will fall into
// unsorted bins if larger than 0x408 (tcache max size is 0x410, which means
// malloc(0x408) is the largest tcache chunk size because glib reserves an
// additional 8 bytes for allocation metadata)
const int STRING_LEN_GLIBC = 0x409;

struct a {
    char* my_string;
    int string_len;
};

int main() {
    // leak heap address from second freed tcache chunk
    // here we use tcache, but also works if chunk is in fastbins
    struct a* a_ptr = malloc(sizeof(struct a));
    struct a* a_ptr_2 = malloc(sizeof(struct a));
    a_ptr->my_string = malloc(STRING_LEN_HEAP);
    a_ptr->string_len = STRING_LEN_HEAP;
    memset(a_ptr->my_string, 0x41, STRING_LEN_HEAP);
    a_ptr_2->my_string = malloc(STRING_LEN_HEAP);
    a_ptr_2->string_len = STRING_LEN_HEAP;
    memset(a_ptr_2->my_string, 0x42, STRING_LEN_HEAP);
    // simulate releasing the string data, but not zeroing it out
    free(a_ptr->my_string);
    free(a_ptr_2->my_string);
    a_ptr->string_len = 0;
    a_ptr_2->string_len = 0;

    printf("%s\n", a_ptr_2->my_string); // leaks forward pointer to next string

    getc(stdin);

    // leak glibc address from freed pointer in unsorted bins cache
    struct a* a_ptr_large_bins;
    a_ptr_large_bins = malloc(sizeof(struct a));
    a_ptr_large_bins->my_string = malloc(STRING_LEN_GLIBC);
    a_ptr_large_bins->string_len = STRING_LEN_GLIBC;
    memset(a_ptr_large_bins->my_string, 0x43, STRING_LEN_GLIBC);

    // need to allocate a "border" chunk to prevent consolidation upon free
    // this border chunk can be anything, with any size. It can even be freed
    // before freeing our unsorted bin chunk, so long as it falls into tcache
    void* border = malloc(0x20);

    // simulate the same as above. Thanks to border chunk, this allocation is
    // not consolated and will fall into unsorted bins
    free(a_ptr_large_bins->my_string);
    a_ptr_large_bins->string_len = 0;

    printf("%s\n", a_ptr_large_bins->my_string);
    getc(stdin);
    return 0;
}
```
## Lecture Video
## Recap
Modern systems usually have
* ASLR - Randomizes location in memory that shared libraries are imported into
	* Changes stack location
* PIE (Position-Independent Executables)
	* Randomizes the location in memory that the binary is loaded into
	* The Heap's location will be random too as it immediately follows the binary
So we will need a leak to access the binary, stack/libc, AND the heap

## Leaking - `leak.c` Example
### Starts by defining two sizes
```c
const int STRING_LEN_HEAP = 0x40;
// allocate size large enough to avoid tcache; when freed, will fall into
// unsorted bins if larger than 0x408 (tcache max size is 0x410, which means
// malloc(0x408) is the largest tcache chunk size because glib reserves an
// additional 8 bytes for allocation metadata)
const int STRING_LEN_GLIBC = 0x409;
```

Assume, for these *leak primitives* we have access to:
* Memory allocations on the heap of different sizes

The first one should go into `tcache` and the second should be too big

`tcache` - One of our caching bins for freed allocations
* 64 bins of different sizes
	* Largest of which holds `0x410` 
		* We need 8 bytes of metadata in 64 bit systems, so the largest we can request is `0x408`
* Can use this to leak heap address
	* After `free`, `tcache` chunks point to other `tcache` chunks
		* This points to another address on the heap
	* Can also use `fastbins`
		* `fastbins` have a smaller range of sizes than `tcache`
		* glibc lets us overflow into 'fastbins'

Goal: We need an allocation into one of the following:
* `Unsorted bins
* `Large bins
* `Small bins

The chosen bin depends on the operations that occur and the size

As long as it's one or more bytes larger than the `tcache size` (which was `0x408`)...
	`const int STRING_LEN_GLIBC = 0x409;`
* it will be put into an `unsorted bin` when freed

Unsorted Bin - Various size chunks that are too large to fit into `tcache`
* They're lazily sorted into `large bins`  or `small bins` during later heap operations

### The struct
We'll need a struct
* construction is important
```c
struct a {
    char* my_string;
    int string_len;
};
```

**Parameters**:
* `char* my_string`
	* A pointer to a string
	* We'll use it to leak memory
		* The pointer will be dereferenced and then we'll print the memory at the address
			* Usually we would expect it to print ascii chars
* `int string_len;`
	* String length
	* Isn't used in the exploit
### Setup
Now we'll take a look at how the Use-After-Free occurs and how we set the `bins` up to achieve the heap leak and then glibc leak.

Here we have two allocations that point to `struct a`
	Basically just initializing two new "objects", and just like arrays, the "*variable*" is a pointer
```c
    struct a* a_ptr = malloc(sizeof(struct a));
    struct a* a_ptr_2 = malloc(sizeof(struct a));
```
There is a reason we have two...it will be important later

Initialize each struct pointer:
```c
    a_ptr->my_string = malloc(STRING_LEN_HEAP);
    a_ptr->string_len = STRING_LEN_HEAP;
    memset(a_ptr->my_string, 0x41, STRING_LEN_HEAP); // All A's
    a_ptr_2->my_string = malloc(STRING_LEN_HEAP);
    a_ptr_2->string_len = STRING_LEN_HEAP;
    memset(a_ptr_2->my_string, 0x42, STRING_LEN_HEAP); // All B's
```

```c
    // simulate releasing the string data, but not zeroing it out
    free(a_ptr->my_string);
    free(a_ptr_2->my_string);
    a_ptr->string_len = 0;
    a_ptr_2->string_len = 0;

    printf("%s\n", a_ptr_2->my_string); // leaks forward pointer to next string

    getc(stdin);

    // leak glibc address from freed pointer in unsorted bins cache
    struct a* a_ptr_large_bins;
    a_ptr_large_bins = malloc(sizeof(struct a));
    a_ptr_large_bins->my_string = malloc(STRING_LEN_GLIBC);
    a_ptr_large_bins->string_len = STRING_LEN_GLIBC;
    memset(a_ptr_large_bins->my_string, 0x43, STRING_LEN_GLIBC);
```
### UAF Scenario
```c
    // simulate releasing the string data, but not zeroing it out
    free(a_ptr->my_string);
    free(a_ptr_2->my_string);
    a_ptr->string_len = 0;
    a_ptr_2->string_len = 0;
```

We don't set the string values equal to 0

The pointers point to data that have been freed, but we can still access them
* `mystring` is still going to be on the heap in an allocation sitting in a free `tcache` `bin`
* We can take advantage of this
###### So when we go to print...
```c
	printf("%s\n", a_ptr_2->my_string); // leaks forward pointer to next string
```
It will leak the pointer to the next string
* this is stored in the metadata of the `free` `chunk`

We need two allocations because of how `tcache` sets these pointers
* The allocations have forward and back pointers, we want it to point to something so that there's an address to leak
### Leaking glibc
```c
    getc(stdin);
    // leak glibc address from freed pointer in unsorted bins cache
    struct a* a_ptr_large_bins;
    a_ptr_large_bins = malloc(sizeof(struct a));
    a_ptr_large_bins->my_string = malloc(STRING_LEN_GLIBC);
    a_ptr_large_bins->string_len = STRING_LEN_GLIBC;
    memset(a_ptr_large_bins->my_string, 0x43, STRING_LEN_GLIBC);
```
`tcache` and `fastbins` won't help us here, because they only point to other stuff on the heap

glibc also has similar forward and back pointers

This time we use the larger string, the one that is too big to go in `tcache`
* The program tries to *"greedily" consolidate* it using `topchunk`
* The latest allocation will be the last thing on the heap
	* This puts it right next to `topchunk`
	* It will try to absorb the `free` allocation back into `topchunk`

To avoid this, we allocate a "border" `chunk` to put between them
```c
	// need to allocate a "border" chunk to prevent consolidation upon free
    // this border chunk can be anything, with any size. It can even be freed
    // before freeing our unsorted bin chunk, so long as it falls into tcache
    void* border = malloc(0x20);
```
Now it will put the freed data into the cache

Then we can free the allocation
```c
    // simulate the same as above. Thanks to border chunk, this allocation is
    // not consolated and will fall into unsorted bins
    free(a_ptr_large_bins->my_string);
    a_ptr_large_bins->string_len = 0;
```

This should now point to 
```c
    printf("%s\n", a_ptr_large_bins->my_string);
    getc(stdin);
    return 0;
```



`heap chunks` will show entire heap in `gef`


# Double Free Fastbins
Video
Goal: Getting the allocator to return the same address for two allocations

Fill tcache first

Then allocate three things
1) free the first
2) free the second
3) free the first again
It will check the top of the free list to make sure the thing isn't freed 2x in a row



`heap bins` to see what's on the heap

# Tcache Poisoning Diagram from Office Hours
### 1:
```c
malloc(0x18)
	Returns: 0x40    // 1
malloc(0x18)
	Returns: 0x60    // 2
malloc(0x18)
	Returns: 0x80    // 3
```
![[Pasted image 20240326174432.png]]

tcache ponts to nothing?
### 2:
```c
free(0x60)    // 2
```
![[Pasted image 20240326175031.png]]
So now the tcache points to that first free
### 3:
```c
free(0x40)    // 1
```
![[Pasted image 20240326175228.png]]
### 4: This is our UAF
```c
edit(0x40) = 0xff    // 1 (which was just freed)
```
![[Pasted image 20240326175443.png]]

### 5:
```c
malloc(0x18)
	Returns: 0x40    // 1
```
So this `malloc` call re-allocates that space, returning the pointer to that one we just edited
And more importantly, the `tcache` pointer points to that attacker-controlled value, which could be a cool pointer to something tricksy
![[Pasted image 20240326175956.png]]
### 6:
```c
malloc(0x18):
	Returns: 0xff
```
So when we call `malloc` **again**, the pointer it returns is that attacker-controlled value
* tcache is poisoned
### 7: So now we get a random read/write
```c
edit(0xff)
```


And this all happens in tcache so we don't have to worry about filling it to get to fastbins i think???
