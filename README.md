# js-finder-burp-extentions
BurpJSLinkFinder-Enhanced is a Burp Suite extension (Jython 2.7) that extracts endpoints from JavaScript files, performs optional HEAD probing, and provides an interactive UI with live search, filtering and export to CSV/JSON. It includes heuristics for concatenated strings and base64/hex decoding and supports sending findings to Repeater or adding to scope.

# Key features

- Parse JS responses and extract endpoints via regex + simple patterns

- Live search across Endpoint, Source and Log

- Context-based priority tagging (HIGH when fetch/axios/XMLHttpRequest present)

- Decode embedded base64/hex strings and re-parse decoded content

- Optional background HEAD probing (concurrency control)

- Copy/open in browser/send to Repeater/add to scope UI actions

- Export results to CSV/JSON and clearable results

# Quick requirements & install

- Burp Suite (Extender tab)

- Jython standalone JAR configured in Burp

- Drop the .py file into Burp Extender and enable the extension

# Improves identification of sensitive keys

https://github.com/user-attachments/assets/ba8976cc-4f77-4641-acd2-360bd16f123e

# Endpoint and Key Detection Rules

## 1. Suspicious/Hidden Endpoint Detection in JS

Detects endpoints used in JavaScript HTTP/request functions, such as:

```javascript

$http.get('/path')

$http.post('/path')

fetch('/path')

axios.get('/path')

axios.post('/path')

XMLHttpRequest.open('GET', '/path')
```

Labels: [SUSPICIOUS ENDPOINT FOUND]

Priority: HIGH

## 2\. Generic Endpoint Patterns

Detects URLs and paths using broad regex patterns:

Full URLs (e.g., https://...)

Strings that look like endpoints or file paths (e.g., /api/v1/user, login)

Labels: No special label

Priority: LOW (default)

## 3\. String Concatenation Endpoints

Detects endpoints built by concatenating strings, e.g.:

```bash

"api/" + "v1/user"
```

Labels: No special label

Priority: LOW (default)

## 4\. Base64/Hex Decoded Endpoints

Detects endpoints hidden in base64 or hex-encoded strings by decoding and re-parsing them.

Labels: No special label (priority LOW by default, or "DECODED" if found via decoding)

## 5\. Private Key Detection

Detects private key blocks (RSA, DSA, EC, etc.) in the content.

Labels: [PRIVATE KEY FOUND]

Priority: CRITICAL (highlighted red)

## 6\. AWS Credential Detection

Detects AWS Access Key IDs and Secret Access Keys in the content.

Labels: [AWS KEY FOUND]

Priority: CRITICAL (highlighted orange)

## 7\. Config-style Endpoint Detection

Detects endpoints in config-like objects, such as:

```bash
{

  "path": "...",

  "linkUrl": "...",

  "baseUrl": "...",

  "allowedRoutes": ["/reset-password", ...],

  "routes": ["reset-password", ...]

}
```

Relative endpoints (not starting with / or http) are marked as (relative)

Labels: [CONFIG ENDPOINT FOUND]

Priority: MEDIUM (highlighted teal)

# Test_BurpJSLinkFinder_for_Community.py

This version contains the regex from https://github.com/ResidualLaugh/FindSomething/blob/master/background.js

# Support
If my tool helped you land a bug bounty, consider buying me a coffee ☕️ as a small thank-you! Everything I build is free, but a little support helps me keep improving and creating more cool stuff ❤️
---


<div align="center">
  <h3>☕ Support My Journey</h3>
</div>


<div align="center">
  <a href="https://www.buymeacoffee.com/tobiasguta">
    <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" />
  </a>
</div>

---
