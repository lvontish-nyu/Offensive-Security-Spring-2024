# Use After Free - CTF Wiki
From [CTF Wiki](https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/use_after_free/)
## Principle
Simply put, Use After Free literally just means what it says. A block of memory is used after release.
#### Scenarios:
1) After the memory block is released, its corresponding pointer is set to `NULL`.
		If the pointer is used again, the program will crash
2) After the memory block is released, its corresponding pointer is **not** set to `NULL`.
	And there is no code to modify the memory block before it is used next time
		If the pointer is used again, the program is *likely to work properly/*
3) After the memory block is released, its corresponding pointer is **not** set to `NULL` **BUT** the code modifies the memory before the program uses it again
		We'll see some strange problems
The **Use After Free** vulnerability generally refers to the latter two scenarios.
	The memory pointer that was not set to `NULL` is called a **dangling pointer**
## Example 1
```c
#include <stdio.h>
#include <stdlib.h>

typedef struct name {
  char *myname;
  void (*func)(char *str);
} NAME;

void myprint(char *str) { printf("%s\n", str); }
void printmyname() { printf("call print my name\n"); }

int main() {

  NAME *a;
  a = (NAME *)malloc(sizeof(struct name));
  a->func = myprint;
  a->myname = "I can also use it";
  a->func("this is my function");

  // free without modify
  free(a);
  a->func("I can also use it");

  // free with modify
  a->func = printmyname;
  a->func("this is my function");

  // set NULL
  a = NULL;
  printf("this pogram will crash...\n");
  a->func("can not be printed...");
}
```
###### Results:
```
➜  use_after_free git:(use_after_free) ✗ ./use_after_free                      

this is my function
I can also use it
call print my name
this pogram will crash...
[1]    38738 segmentation fault (core dumped)  ./use_after_free
```

## Example 2
Demo references [this blog](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/heap/use_after_free/hitcon-training-hacknote)
##### Example Code:
###### `hacknote.c` Code
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct note {
	void (*printnote)();
	char *content;
};

struct note *notelist[5];
int count = 0;

void print_note_content(struct note *this) { puts(this->content); }
void add_note() {
	int i;
	char buf[8];
	int size;
	if (count > 5) {
		puts("Full");
	    return;
	  }
	for (i = 0; i < 5; i++) {
	    if (!notelist[i]) {
		    notelist[i] = (struct note *)malloc(sizeof(struct note));
		    if (!notelist[i]) {
		        puts("Alloca Error");
			    exit(-1);
		    }
		    notelist[i]->printnote = print_note_content;
		    printf("Note size :");
		    read(0, buf, 8);
		    size = atoi(buf);
		    notelist[i]->content = (char *)malloc(size);
		    if (!notelist[i]->content) {
			    puts("Alloca Error");
		        exit(-1);
		    }
		    printf("Content :");
		    read(0, notelist[i]->content, size);
			puts("Success !");
			count++;
		    break;
		}
	}
}

void del_note() {
	char buf[4];
	int idx;
	printf("Index :");
	read(0, buf, 4);
	idx = atoi(buf);
	if (idx < 0 || idx >= count) {
		puts("Out of bound!");
		_exit(0);
	}
	if (notelist[idx]) {
		free(notelist[idx]->content);
		free(notelist[idx]);
		puts("Success");
	}
}

void print_note() {
	char buf[4];
	int idx;
	printf("Index :");
	read(0, buf, 4);
	idx = atoi(buf);
	if (idx < 0 || idx >= count) {
		puts("Out of bound!");
		_exit(0);
	}
	if (notelist[idx]) {
		notelist[idx]->printnote(notelist[idx]);
	}
}

void magic() { system("cat flag"); }

void menu() {
	puts("----------------------");
	puts("       HackNote       ");
	puts("----------------------");
	puts(" 1. Add note          ");
	puts(" 2. Delete note       ");
	puts(" 3. Print note        ");
	puts(" 4. Exit              ");
	puts("----------------------");
	printf("Your choice :");
};

int main() {
	setvbuf(stdout, 0, 2, 0);
	setvbuf(stdin, 0, 2, 0);
	char buf[4];
	while (1) {
		menu();
		read(0, buf, 4);
		switch (atoi(buf)) {
		case 1:
			add_note();
			break;
		case 2:
			del_note();
			break;
		case 3:
			print_note();
			break;
		case 4:
			exit(0);
			break;
		default:
			puts("Invalid choice");
			break;
		}
	}
	return 0;
}
```
###### Full Code Above
### Functional Analysis
There is a menu function at the beginning of the program that performs the following:
##### `void menu()`
###### Code
```c
  puts(" 1. Add note          ");
  puts(" 2. Delete note       ");
  puts(" 3. Print note        ");
  puts(" 4. Exit              ");
```

These correspond with the three main functions that the program will perform based on the user's input.
##### `int add_note()`
###### Code
```c
struct note {
	void (*printnote)();
	char *content;
};

void add_note() {
	int i;
	char buf[8];
	int size;
	if (count > 5) {
		puts("Full");
	    return;
	  }
	for (i = 0; i < 5; i++) {
	    if (!notelist[i]) {
		    notelist[i] = (struct note *)malloc(sizeof(struct note));
		    if (!notelist[i]) {
		        puts("Alloca Error");
			    exit(-1);
		    }
		    notelist[i]->printnote = print_note_content;
		    printf("Note size :");
		    read(0, buf, 8);
		    size = atoi(buf);
		    notelist[i]->content = (char *)malloc(size);
		    if (!notelist[i]->content) {
			    puts("Alloca Error");
		        exit(-1);
		    }
		    printf("Content :");
		    read(0, notelist[i]->content, size);
			puts("Success !");
			count++;
		    break;
		}
	}
}
```
###### The program can add up to 5 notes. 
Each note has two fields:
* `content`
* "`put`"
	This calls `printnote`, essentially pointing to a function that will print the note content

##### `void print_note()`
Simply outputs the contents of the note corresponding to the index based on the index of the given note.
###### Code
```c
void print_note() {
	char buf[4];
	int idx;
	printf("Index :");
	read(0, buf, 4);
	idx = atoi(buf);
	if (idx < 0 || idx >= count) {
		puts("Out of bound!");
		_exit(0);
	}
	if (notelist[idx]) {
		notelist[idx]->printnote(notelist[idx]);
	}
}
```
##### `void del_note()`
This will release the corresponding note based on the given index
	**NOTE**: Deleting sets it free, but not to NULL, so there is potential for a use after free
###### Code
```c
void del_note() {
	char buf[4];
	int idx;
	printf("Index :");
	read(0, buf, 4);
	idx = atoi(buf);
	if (idx < 0 || idx >= count) {
		puts("Out of bound!");
		_exit(0);
	}
	if (notelist[idx]) {
		free(notelist[idx]->content);
		free(notelist[idx]);
		puts("Success");
	}
}
```
