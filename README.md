# FINDER'X
<div align="center">
  <a href="https://github.com/INTELEON404/FINDERX/releases">
    <img src="https://img.shields.io/badge/Version-12.0%20Ultimate-blue.svg" alt="Version">
  </a>
  <a href="https://github.com/INTELEON404">
    <img src="https://img.shields.io/badge/GITHUB-INTELEON404-red.svg" alt="GitHub">
  </a>
  <a href="#">
    <img src="https://img.shields.io/badge/Language-Python%203-yellow.svg" alt="Python">
  </a>
</div>

**FINDER'X v12.0 Ultimate** is an advanced, automated vulnerability scanner designed for detecting Cross-Site Scripting (XSS) and other web vulnerabilities. It features a robust engine capable of crawling, bypassing WAFs, and verifying vulnerabilities using a headless browser to reduce false positives.

## Features 🚀

- 🎯 **Multi-Targeting**: Scan a single URL or load a list of domains from a file.
- 🕷️ **Smart Crawling**: Automatically crawls the target to find hidden parameters and endpoints.
- 🛡️ **WAF Bypass**: Includes specialized payloads designed to evade Web Application Firewalls.
- 🤖 **Headless Verification**: Verifies XSS execution in a real browser environment to eliminate false positives.
- ⏱️ **Rate Limiting**: Configurable delay to prevent server blocking or DoS.
- 🔄 **Proxy Support**: Route traffic through HTTP proxies (e.g., Burp Suite) for analysis.
- 📝 **Custom Payloads**: Fully customizable payload injection via external files.
- 💾 **Auto-Save**: Automatically logs vulnerable URLs and reports.

## Requirements

- 🐍 **Python 3.x**
- 📦 **Dependencies**: `requests`, `selenium` (for verification)
  
  *(Ensure you have the necessary browser drivers installed if using `--verify`)*

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/INTELEON404/FINDERX.git
   cd FINDERX```

2.  **Install the Dependencies**:

    ```bash
    pip install -r requirements.txt --break-system-packages
```
    # Or manually:
```
    pip install requests selenium --break-system-packages
    ```

## Usage

**FINDER'X** uses command-line arguments for flexibility.

```bash
python3 finderx.py [options]
```

### Options

| Flag | Long Flag | Description |
| :--- | :--- | :--- |
| `-h` | `--help` | Show the help message and exit. |
| `-u` | `--url` | Specify a single target URL. |
| `-f` | `--file` | Load a list of URLs from a specific file. |
| `-l` | `--list` | Alias for `-f` (load from file). |
| `-p` | `--payloads` | Path to a custom payloads file. |
| | `--crawl` | Enable the crawler to find dynamic endpoints. |
| | `--delay` | Set a delay (in seconds) between requests. |
| | `--proxy` | Set an HTTP Proxy (e.g., `http://127.0.0.1:8080`). |
| | `--verify` | Enable XSS verification using a headless browser. |
| | `--waf-bypass` | Attempt to use WAF bypass payloads. |

## Examples

### 1\. Basic Single URL Scan

Scan a specific URL using the default payload set.

```bash
python3 finderx.py -u "https://example.com/search.php?q="
```

### 2\. Bulk Scan with Custom Payloads

Scan a list of URLs from `targets.txt` using payloads from `payloads.txt`.

```bash
python3 finderx.py -f targets.txt -p payloads.txt
```

### 3\. The Ultimate Scan (Crawler + WAF Bypass + Verification)

Crawl the domain, attempt to bypass WAFs, and verify results with a headless browser.

```bash
python3 finderx.py -u https://example.com --crawl --waf-bypass --verify
```

### 4\. Stealth Scan (Proxy + Delay)

Route traffic through Tor/Burp and add a 2-second delay to avoid detection.

```bash
python3 finderx.py -u https://example.com --proxy http://127.0.0.1:8080 --delay 2
```

## Output

Results are displayed in the terminal with color-coded tags:

  - 💥 **[VULN]**: Confirmed Vulnerability.
  - ✅ **[SAFE]**: Payload reflected but not executed (or sanitised).
  - 🕷️ **[CRAWL]**: New link discovered.
  - ⚠ **[ERROR]**: Connection timeout or error.

All findings are automatically saved to `results/<domain>-report.txt`.

## Warning ⚠

  - **Permission**: Only run this tool on domains you own or have explicit permission to test.
  - **Intrusiveness**: The `--crawl` and `--waf-bypass` modes generate significant traffic. Use `--delay` to respect server limits.
  - **Legal**: The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## Contributing 🤝

Contributions are welcome\!

1.  🍴 Fork the repository.
2.  🌱 Create a new branch.
3.  ✨ Implement your feature.
4.  📤 Submit a pull request.

## Contact 📧

For bugs, suggestions, or private inquiries:

[](mailto:inteleon404@gmail.com)


