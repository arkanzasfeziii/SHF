# SHF
Security Header Fixer
SHF (Security Header Fixer) is a Python CLI tool designed to analyze the security headers of a given website and generate configuration files for popular web servers (Nginx, Apache, IIS) to add or fix missing/weak security headers. It helps improve website security by providing ready-to-use config snippets with standard secure values.

Many security scanners point out missing headers like CSP or HSTS, but SHF goes further by automatically fetching current headers, identifying issues, and outputting tailored config files.

## Features
- Fetches and analyzes HTTP security headers from any URL.
- Identifies missing or weak headers (e.g., CSP, HSTS, X-Frame-Options, etc.).
- Generates config files for:
  - Nginx (`nginx_security.conf`)
  - Apache (`apache_security.conf`)
  - IIS (`web.config`)
- Clean CLI interface with a beautiful ASCII banner.
- Handles errors gracefully (e.g., invalid URLs, network issues).
- Outputs in English for global usability.

Made by [arkanzasfeziii](https://github.com/arkanzasfeziii).

## Installation

1. Clone the repository:
git clone https://github.com/arkanzasfeziii/SHF.git
cd SHF
text2. Install dependencies:
pip install -r requirements.txt
text## Usage

Run the tool with the following command:
python shf.py --url <website_url> --server <nginx|apache|iis> [--output <custom_filename>]
text### Arguments:
- `--url`: Required. The target website URL (e.g., `https://example.com`).
- `--server`: Required. Server type: `nginx`, `apache`, or `iis`.
- `--output`: Optional. Custom output filename (defaults to server-specific name).

### Example:
python shf.py --url https://example.com --server nginx
textThis will:
- Analyze headers.
- Generate `nginx_security.conf` with missing/fixed headers.
- Provide instructions on how to apply the config.

## How It Works
1. The tool fetches the site's headers using `requests`.
2. Compares against a set of standard security headers.
3. If headers are missing or weak, it suggests secure defaults.
4. Outputs a config file snippet ready for your server.

## Security Headers Covered
- Content-Security-Policy (CSP)
- Strict-Transport-Security (HSTS)
- X-Content-Type-Options
- X-Frame-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Embedder-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Resource-Policy

## Contributing
Contributions are welcome! Please open an issue or submit a pull request for improvements.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer
This tool provides standard recommendations but may need customization for your specific site. Always test configs in a staging environment before production.
