#!/usr/bin/env python3

import sys
import argparse
import requests
from urllib.parse import urlparse


def print_banner():
    banner = """
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║              Security Header Fixer                             ║
║                                                                ║
║                   Made By arkanzasfeziii                       ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
    """
    print(banner)


SECURITY_HEADERS = {
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin'
}


def fetch_headers(url):
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        response = requests.get(url, timeout=10, allow_redirects=True, verify=True)
        return response.headers, response.url
    except requests.exceptions.SSLError:
        try:
            url = url.replace('https://', 'http://')
            response = requests.get(url, timeout=10, allow_redirects=True, verify=False)
            return response.headers, response.url
        except Exception as e:
            raise Exception(f"Failed to fetch URL: {str(e)}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"Network error: {str(e)}")
    except Exception as e:
        raise Exception(f"Unexpected error: {str(e)}")


def analyze_headers(current_headers):
    missing = {}
    weak = {}
    
    for header, default_value in SECURITY_HEADERS.items():
        header_lower = header.lower()
        found = False
        
        for key in current_headers.keys():
            if key.lower() == header_lower:
                found = True
                current_value = current_headers[key]
                
                if header == 'Strict-Transport-Security':
                    if 'max-age' not in current_value or int(current_value.split('max-age=')[1].split(';')[0]) < 31536000:
                        weak[header] = current_value
                elif header == 'X-Frame-Options':
                    if current_value.upper() not in ['DENY', 'SAMEORIGIN']:
                        weak[header] = current_value
                elif header == 'Content-Security-Policy':
                    if "default-src 'none'" in current_value or len(current_value) < 20:
                        weak[header] = current_value
                break
        
        if not found:
            missing[header] = default_value
    
    return missing, weak


def generate_nginx_config(headers):
    lines = []
    for header, value in headers.items():
        lines.append(f"add_header {header} \"{value}\" always;")
    return '\n'.join(lines)


def generate_apache_config(headers):
    lines = ['<IfModule mod_headers.c>']
    for header, value in headers.items():
        lines.append(f'    Header always set {header} "{value}"')
    lines.append('</IfModule>')
    return '\n'.join(lines)


def generate_iis_config(headers):
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<configuration>',
        '    <system.webServer>',
        '        <httpProtocol>',
        '            <customHeaders>'
    ]
    
    for header, value in headers.items():
        lines.append(f'                <add name="{header}" value="{value}" />')
    
    lines.extend([
        '            </customHeaders>',
        '        </httpProtocol>',
        '    </system.webServer>',
        '</configuration>'
    ])
    
    return '\n'.join(lines)


def save_config(server_type, content, output_file=None):
    if output_file is None:
        filenames = {
            'nginx': 'nginx_security.conf',
            'apache': 'apache_security.conf',
            'iis': 'web.config'
        }
        output_file = filenames.get(server_type)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return output_file


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Generate security header configuration files',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--url',
        required=True,
        help='Target website URL (e.g., https://example.com)'
    )
    
    parser.add_argument(
        '--server',
        required=True,
        choices=['nginx', 'apache', 'iis'],
        help='Server type: nginx, apache, or iis'
    )
    
    parser.add_argument(
        '--output',
        help='Custom output filename (optional)'
    )
    
    args = parser.parse_args()
    
    print(f"[*] Analyzing security headers for: {args.url}")
    
    try:
        current_headers, final_url = fetch_headers(args.url)
        print(f"[+] Successfully fetched headers from: {final_url}")
        
        missing, weak = analyze_headers(current_headers)
        
        if missing:
            print(f"\n[!] Found {len(missing)} missing security header(s):")
            for header in missing.keys():
                print(f"    - {header}")
        else:
            print("\n[+] All essential security headers are present!")
        
        if weak:
            print(f"\n[!] Found {len(weak)} weak security header(s):")
            for header, value in weak.items():
                print(f"    - {header}: {value[:50]}...")
        
        if not missing and not weak:
            print("\n[+] Your site has excellent security headers!")
            print("[*] Generating configuration file with all standard headers...")
            headers_to_add = SECURITY_HEADERS
        else:
            headers_to_add = {**missing, **weak}
        
        print(f"\n[*] Generating {args.server.upper()} configuration file...")
        
        if args.server == 'nginx':
            config_content = generate_nginx_config(headers_to_add)
        elif args.server == 'apache':
            config_content = generate_apache_config(headers_to_add)
        else:
            config_content = generate_iis_config(headers_to_add)
        
        output_path = save_config(args.server, config_content, args.output)
        
        print(f"[+] Configuration file generated successfully!")
        print(f"[+] Saved to: {output_path}")
        print(f"\n[*] Instructions:")
        
        if args.server == 'nginx':
            print("    1. Copy the content to your Nginx configuration")
            print("    2. Place it inside a server {} block")
            print("    3. Run: nginx -t")
            print("    4. Reload: systemctl reload nginx")
        elif args.server == 'apache':
            print("    1. Ensure mod_headers is enabled: a2enmod headers")
            print("    2. Copy the content to your .htaccess or VirtualHost")
            print("    3. Run: apachectl configtest")
            print("    4. Restart: systemctl restart apache2")
        else:
            print("    1. Backup your existing web.config")
            print("    2. Merge the generated content with your web.config")
            print("    3. Restart IIS or the application pool")
        
        print("\n[+] Done! Your website will be more secure after applying these headers.")
        
    except Exception as e:
        print(f"\n[!] Error: {str(e)}")
        sys.exit(1)


if __name__ == '__main__':
    main()
