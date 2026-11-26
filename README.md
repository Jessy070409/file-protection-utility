# File Protection Utility

A Python command-line utility built for the VirtualWorks Cyber Security Internship (Task 4) that converts file contents into a password-protected format and restores them when required.

## Features
- **Password-Based Protection:** Transforms readable files into encoded `.locked` files using a SHA-256 derived key stream and Base64 encoding.
- **Controlled Access & Verification:** Embeds a password signature check to prevent restoring files with an incorrect password.
- **Zero External Dependencies:** Built using Python's standard `hashlib`, `base64`, and `os` modules.

## Usage
1. Clone the repository:
   ```bash
   git clone [https://github.com/Jessy070409/file-protection-utility.git](https://github.com/Jessy070409/file-protection-utility.git)
