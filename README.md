# R2SAE - React2Shell Auto-Exploit

<p align="center">
  <img src="icons/icon-96.png" alt="R2SAE Logo" width="96" height="96">
</p>

<p align="center">
  <strong>A Firefox extension for detecting and exploiting CVE-2025-55182</strong><br>
  Prototype Pollution vulnerability in React Server Actions
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#disclaimer">Disclaimer</a>
</p>

---

## ⚠️ Disclaimer

**This tool is for authorized security testing only.** Unauthorized access to computer systems is illegal. Only use this tool on systems you own or have explicit written permission to test. The author is not responsible for any misuse of this tool.

---

## 🎯 Overview

R2SAE (React2Shell Auto-Exploit) is a Firefox browser extension that automates the detection and exploitation of **CVE-2025-55182** - a critical prototype pollution vulnerability in Next.js React Server Actions that can lead to Remote Code Execution (RCE).

The vulnerability exists in how Next.js handles multipart form data in Server Actions, allowing attackers to pollute object prototypes and achieve arbitrary code execution on the server.

---

## ✨ Features

### 🔍 Scanning
- **Vulnerability Detection**: Confirms RCE by executing harmless test command
- **Auto-detect**: Automatically detects current tab's URL as target

### ⚡ Execution
- **Single Command**: Execute individual commands on vulnerable targets
- **Output Capture**: Base64-encoded output retrieval via HTTP headers
- **Real-time Console**: View command output in styled terminal

### 📋 Bulk Scanning
- **Multi-URL Support**: Scan hundreds of URLs at once
- **Sequential Processing**: Reliable one-by-one scanning
- **Visual Results**: Color-coded vulnerable (red) vs safe (green) indicators

### 🖥️ Interactive Shell
- **Pseudo-Shell Interface**: Interactive command execution
- **Command History**: Navigate previous commands
- **Persistent Connection**: Stay connected to vulnerable target

### 🛠️ Additional Features
- **Export Results**: Save scan results as JSON or TXT
- **Configurable Timeout**: Adjust request timeout in settings
- **Dark Theme**: Beautiful dark UI optimized for security testing
- **Keyboard Shortcuts**: Enter to execute, Escape to close modals

---

## 📦 Installation

### Option 1: Install Signed XPI (Recommended)
1. Download the signed `.xpi` from [Releases](https://github.com/oscarmine/R2SAE/releases)
2. Open Firefox and drag the `.xpi` file into the browser window
3. Click "Add" when prompted
4. The extension icon will appear in your toolbar

### Option 2: Temporary Installation (Development)
1. Clone this repository
2. Open Firefox and go to `about:debugging`
3. Click "This Firefox" → "Load Temporary Add-on"
4. Select any file from the extension folder (e.g., `manifest.json`)

---

## 🚀 Usage

### Quick Start
1. Click the R2SAE icon in your Firefox toolbar
2. Navigate to a target website (URL auto-detected)
3. Click **Start Scan** to check for vulnerability

### Command Execution
1. Switch to the **Execute** tab
2. Enter your command (e.g., `whoami`, `id`, `cat /etc/passwd`)
3. Press **Enter** or click **Execute**
4. View output in the console below

### Bulk Scanning
1. Switch to the **Bulk** tab
2. Paste URLs (one per line) - just domain names work too!
3. Click **Scan All** - results appear in real-time

---

## 🔧 Technical Details

### Vulnerability: CVE-2025-55182

**Affected**: Next.js applications using React Server Actions with multipart form data

**Root Cause**: Insufficient input validation in the form data parser allows prototype pollution through specially crafted form field names

**Impact**: Remote Code Execution (RCE) on the server

### Exploit Mechanism
1. Crafted multipart form data with prototype pollution payload
2. Payload triggers code execution via polluted prototype chain
3. Command output encoded in base64 and exfiltrated via `X-Action-Redirect` header
4. Extension captures header via `webRequest` API and decodes output

### Payload Structure
```
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model",...}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
```

---

## 📁 Project Structure

```
extension/
├── manifest.json      # Extension configuration
├── background.js      # Exploit logic & webRequest handlers
├── popup.html         # Extension popup UI
├── popup.css          # Styles
├── popup.js           # UI logic & event handlers
└── icons/
    ├── icon-48.png
    └── icon-96.png
```

---

## 🔒 Permissions

The extension requires these permissions:

| Permission | Purpose |
|------------|---------|
| `<all_urls>` | Send exploit payloads to any target |
| `webRequest` | Capture response headers for output |
| `webRequestBlocking` | Modify request headers (CORS bypass) |
| `storage` | Save settings locally |
| `clipboardWrite` | Copy output to clipboard |
| `activeTab` | Detect current tab URL |
| `tabs` | Access tab information |

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

- Original vulnerability research and Python POC by security researchers
- Extension developed by [oscarmine](https://github.com/oscarmine)

---

## 📞 Contact

- GitHub: [@oscarmine](https://github.com/oscarmine)
- Project Link: [https://github.com/oscarmine/R2SAE](https://github.com/oscarmine/R2SAE)

---

<p align="center">
  <strong>⚠️ Use responsibly. For authorized security testing only. ⚠️</strong>
</p>
