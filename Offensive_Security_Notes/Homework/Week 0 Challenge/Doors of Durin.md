![[Pasted image 20240131131448.png]]

100 Points

Target: `nc offsec-chalbroker.osiris.cyber.nyu.edu 1235`

IP: 128.238.62.235
```
ping offsec-chalbroker.osiris.cyber.nyu.edu 
PING offsec-chalbroker.osiris.cyber.nyu.edu (128.238.62.235) 56(84) bytes of data.
64 bytes from 128.238.62.235 (128.238.62.235): icmp_seq=1 ttl=51 time=38.5 ms
64 bytes from 128.238.62.235 (128.238.62.235): icmp_seq=2 ttl=51 time=39.6 ms
```

Nmap:
Top 1K TCP
```
Nmap scan report for 128.238.62.235
Host is up (2.2s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh
25/tcp   filtered smtp
1236/tcp open     bvcontrol
1247/tcp open     visionpyramid
2000/tcp open     cisco-sccp
3283/tcp filtered netassistant
5060/tcp open     sip
```

Well, what's there?
Well, I'm a nerd...
```
─$ nc offsec-chalbroker.osiris.cyber.nyu.edu 1235
You and your party of a Wizard, a Dwarf, and Elf, 2 Men, and 3 other Hobbits stand around the Doors of Durin, the entrance to the Dwarven Mines of Moria.
A door blocks your way into the Mines, the only remaining path you have to get to the forest Lothlórien, where the Lady Galadriel is sure to offer you sanctuary from the dark forces pursuing you.

The Wizard looks at the Doors, and reads:

        "Ennyn Durin Aran Moria. Pedo mellon a Minno. Im Narvi hain echant. Celebrimbor o Eregion tethant. I thiw hin."

You ask, "What does it mean?"

"Oh, it is a simple riddle," says the Wizard.

        "The Doors of Durin, Lord of Moria. Speak friend and enter. I Narvi made them. Celebrimbor of Hollin drew these signs."

You think for a moment. "Speak friend and enter." What could it mean?

Suddenly, the answer comes to you!
You shout: mellon 

The Doors open! As you delve into the Mines, you hear a whisper on the wind:

        The flag is: flag{the_dwarves_dug_too_deep}

```