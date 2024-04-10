![[Pasted image 20240131132859.png]]


FLAG: flag{you_sure_are_a_math_genius}

It's the same URL as [[Doors of Durin]], but a different port, so maybe I shouldn't have scanned it

Interaction:
```
nc offsec-chalbroker.osiris.cyber.nyu.edu 1236
PSSSST... Hey, I heard you were some kinda math genius...
I got some of the good stuff from my math vendor, and I need you to check it...
Can you prove that you're a real math whiz??
1534 * 8422 = ?
12919348
Aww yeah!
8571 + 2275 = ?
10846 
Aww yeah!
4641 - 7058 = ?
-2417 
Aww yeah!
1814 - 6966 = ?
no
Hey, that doesn't look like a number!! Get outta here!
Guess you aren't the math whiz I thought you were...
```



So I guess after enough questions, it starts to ask you using WORDS

```
Math = 
 b'5281 + 6450 = ?\n'
Math = 
 b'2129 - 4665 = ?\n'
Math = 
 b'8836 + 5788 = ?\n'
Math = 
 b'3723 + 4793 = ?\n'
Math = 
 b'348 - 8700 = ?\n'
Math = 
 b'1764 * 1535 = ?\n'
Math = 
 b'1885 - 7635 = ?\n'
Math = 
 b'1888 + 6606 = ?\n'
Math = 
 b'6608 + 5014 = ?\n'
Math = 
 b'9764 + 4428 = ?\n'
Math = 
 b'1159 + 5405 = ?\n'
Math = 
 b'1577 + 2906 = ?\n'
Math = 
 b'3562 - 4787 = ?\n'
Math = 
 b'4358 + 7008 = ?\n'
Math = 
 b'1056 + 6198 = ?\n'
Math = 
 b'4472 * TWO-EIGHT-ZERO-SIX = ?\n'

```


Also get hex at level 30

Answer is at 100, it breaks
