## 🧬 sl0ppy-svg-intel-scan

> **Ultimate SVG Security Intelligence Scanner**  
> Built by **x0xr00t** Aka **Patrick Hoogeveen** · For authorized security research & personal use
> Team **Sl0ppyr00t** **0xsec** 
A high-signal **passive + active SVG security scanner** designed to uncover **server-side and delivery-pipeline vulnerabilities** hidden in SVG files.

---

## 📜 Table of Contents

- Introduction  
- Why SVG  
- Features  
- Vulnerabilities Detected  
- Installation  
- Usage  
- Configuration  
- Technical Deep Dive  
- Mitigations  
- Legal Notice  

---

## 📌 Introduction

**sl0ppy-svg-intel-scan** is an advanced SVG security intelligence scanner that combines static analysis, deep fuzzing, and exploit-chain testing to identify XXE, SSRF, LFI, RCE, XSS, and delivery-pipeline vulnerabilities.

---

## 🎯 Why SVG?

SVG files are often whitelisted as images but can contain executable code, external references, and XML entities. Many systems render SVGs server-side, making them a powerful attack vector.

---

## 🔍 Features

- Deep fuzzing with 100+ payloads per vulnerability class  
- Static SVG security analysis  
- Multi-stage exploit chain detection  
- 150+ SVG XSS vectors  
- Delivery pipeline security testing  
- Risk scoring (0–10)  
- NL-specific payload intelligence  
- Easter eggs for security orgs  

---

## 🚨 Vulnerabilities Detected

- XXE (10/10)  
- SSRF (10/10)  
- LFI (9/10)  
- RCE (10/10)  
- XSS (8/10)  
- Header Injection  
- CORS Misconfiguration  
- Open Redirects  

---

## 🛠 Installation

```
git clone https://github.com/x0xr00t/sl0ppy-svg-intel-scan.git
cd sl0ppy-svg-intel-scan
npm install jsdom node-fetch
```
## 🚀 Usage
```
node sl0ppy-svg-intel-scan.js
```
# ⚙ Configuration
```
Payloads, HTTPS agent behavior, and organization detection can be customized directly in the script.
```
# 🔬 Technical Deep Dive
```
The scanner tests real-world attack scenarios involving XXE, SSRF, LFI, RCE, XSS, and delivery pipeline weaknesses using chained payload logic.
```
# 🛡 Mitigations
```
Disable external entity processing

Sanitize SVG uploads

Sandbox rendering

Apply strict security headers

Restrict outbound network access
```
# ⚖ Legal Notice
```
This tool is for authorized testing only. Unauthorized use may violate applicable laws
```
.
