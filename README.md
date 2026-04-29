# Web Vulnerability Scanner

A Python-based CLI tool that scans web applications for common vulnerabilities. Built as a learning project to understand how web security tools work under the hood.

## Features

- **Security Header Analysis** — checks for missing HTTP security headers
- **XSS Detection** — tests URL parameters and form fields for reflected Cross-Site Scripting
- **SQL Injection Detection** — tests URL parameters and form fields for SQL injection vulnerabilities

## Project Structure

```
scanner/
├── main.py        # CLI entry point
├── headers.py     # Security header checks
├── xss.py         # XSS detection (URL params + forms)
├── sqli.py        # SQL injection detection (URL params + forms)
└── utils.py       # Shared request utility
```

## Requirements

- Python 3.x
- `requests`
- `beautifulsoup4`

Install dependencies:

```bash
pip install requests beautifulsoup4
```

## Usage

```bash
python main.py --url http://target-url.com
```

## What It Checks

### Security Headers
Flags missing headers from the response:
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Strict-Transport-Security`
- `Referrer-Policy`
- `Permissions-Policy`

### XSS (Reflected)
- Injects payloads into URL parameters
- Parses HTML forms, extracts input fields, submits payloads via GET/POST
- Flags if payload reflects back unescaped in the response

### SQL Injection
- Injects SQL payloads into URL parameters and form fields
- Checks response for known database error signatures
- Supports session cookies for authenticated scanning

## Testing

Tested against [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application) running locally via Docker:

```bash
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

## Disclaimer

This tool is for educational purposes only. Only use it against applications you have explicit permission to test.
