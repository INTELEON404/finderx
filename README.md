# LOXIA
<div align="center">
  <a href="https://github.com/INTELEON404/LOXIA/releases">
    <img src="https://img.shields.io/badge/Version-2.0.-blue.svg" alt="Version">
  </a>
  <a href="https://github.com/hackinter">
    <img src="https://img.shields.io/badge/GITHUB-INTELEON404-red.svg" alt="GitHub">
  </a>
</div>

**LOXIA** is an automated tool designed for testing XSS (Cross-Site Scripting) vulnerabilities on specified domains. This tool helps you check the security of web applications against common XSS attack vectors by utilizing customizable payloads.

## Features

- 📝 **Custom Payloads**: Load payloads from a specified file for testing.
- 🌐 **HTTP Method Support**: Supports both `GET` and `POST` HTTP methods for testing.
- 📊 **Real-time Analysis**: Displays live analysis of potential XSS vulnerabilities in the terminal.
- 💾 **Results Saving**: Automatically saves test results to a file named according to the domain tested, ensuring you can revisit your findings.
- 🎨 **Color-Coded Output**: User-friendly terminal output with color codes for easier interpretation of test results.

## Requirements

- 🐍 **Python 3.x**
- 📦 **`requests` library** (install with `pip install requests`)

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/INTELEON404/LOXIA.git
   cd LOXIA
   ```

2. **Install the Dependencies**:

   ```bash
   pip install requests
   ```

## Usage

1. **Run the Script**:

   Execute the script in the terminal:

   ```bash
   python loxia.py
   ```

2. **Input the Following Information**:

   - 🔗 **Target Domain**: Enter the domain you want to test (e.g., `https://example.com/search.jsp?query=`).
   - 📁 **Payload File Path**: Provide the full path to your payload file (e.g., `/path/to/payloads.txt`).
   - 📜 **HTTP Method**: Choose either `GET` or `POST` based on your test requirements.

3. **Review the Results**: After running the tool, results will be displayed in the terminal with color-coded outputs:
   - ✅ **Success**: Safe URLs will be highlighted.
   - 💥 **Vulnerabilities**: Detected XSS vulnerabilities will be marked with the appropriate emoji.
   - ⚠️ **Connection Errors**: Any issues connecting to the server will also be flagged.

4. **Saving Results**: After the test, you can save the results to a file:
   - For example, if the target domain is `kali.org`, the result file will be named `kali-result.txt`.
   - If a file with that name already exists, the tool will create additional files like `kali-result1.txt`, `kali-result2.txt`, etc.

## Example

```bash
🔗 Enter the target domain (e.g., https://example.com): https://example.com/search.jsp?query=
📁 Enter the path to the payload file: /path/to/payloads.txt
📜 Choose the HTTP method (GET/POST): GET
```

### Sample Output

- 💥 **Vulnerability Found**:
  ```
  💥 Possible XSS vulnerability found: https://example.com?payload=<script>alert('xss')</script> with payload: <script>alert('xss')</script>
  ```

- ✅ **No Vulnerability Found**:
  ```
  ❎ No vulnerability found; URL is safe: https://example.com?payload=<script>console.log('test')</script> with payload: <script>console.log('test')</script>
  ```

- ⚠️ **Connection Error**:
  ```
  ⚠️ Error connecting to server; URL is not accessible for testing: https://example.com?payload=<script>alert('fail')</script>
  ```

- 💾 **Results Saved**:
  ```
  ✅ Results saved to example-com-result.txt
  ```

## Warning

- ⚠️ **Security**: Always ensure you have explicit permission before testing any website. Unauthorized testing may be illegal and could result in serious consequences.
- 🛡️ **Payloads**: The effectiveness of the tool relies on using relevant and up-to-date payloads. Ensure you have the latest payloads for accurate testing.
- 📶 **Network Traffic**: Repeated requests to a website can be flagged as malicious by servers. Monitor your network traffic to avoid being blocked.
- 🌐 **Ethical Use**: This tool is designed for educational and ethical hacking purposes only. Always comply with ethical guidelines and legal regulations.

## Contributing

We welcome contributions! To contribute:
1. 🍴 Fork the repository.
2. 🌱 Create a new branch.
3. ✨ Implement your feature or fix.
4. 📤 Submit a pull request.

## License 📜
This project is licensed under the MIT License. See the [LICENSE](https://github.com/INTELEON404/oneclick/blob/main/LICENSE) file for more details.

## Contributing 🤝
We welcome contributions! If you would like to contribute, feel free to fork the repository and submit a pull request. If you encounter any bugs or have suggestions, please open an issue.

## Contact 📧
For any queries or issues, feel free to reach out to us:

[![Email](https://img.shields.io/badge/INTELEON404-MAIL-red.svg)](mailto:ceh.ec.counselor147@gmail.com)  
[![Telegram](https://img.shields.io/badge/INTELEON404-T.ME-blue.svg)](https://t.me/chat_with_hackinter_bot)  
[![Twitter](https://img.shields.io/badge/INTELEON404-TWITTER-black.svg)](https://x.com/_anonix_z)




