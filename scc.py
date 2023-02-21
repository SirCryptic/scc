import argparse
import json
import socket
import os
import re
import requests
from bs4 import BeautifulSoup
import subprocess

# Developer: SirCryptic (NullSecurityTeam)
# Info: Security Configuration Checker v1.0

# Firewall rules check
def check_firewall_rules(host):
    # Check if port 22 is open to outside
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, 22))
        except:
            return False
    
    # Check if port 80 or 443 is open to outside
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, 80))
        except:
            try:
                s.connect((host, 443))
            except:
                return False
    
    return True

# Encryption settings check
def check_encryption_settings(host):
    # Check if SSLv2 or SSLv3 is enabled
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, 443))
            s.sendall(b"GET / HTTP/1.1\r\nHost: "+bytes(host, 'utf-8')+b"\r\nConnection: close\r\n\r\n")
            data = s.recv(1024)
            if b'sslv2' in data.lower() or b'sslv3' in data.lower():
                return False
        except:
            pass
    
    # Check if weak ciphers are enabled
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        try:
            s.connect((host, 443))
            s.sendall(b"GET / HTTP/1.1\r\nHost: "+bytes(host, 'utf-8')+b"\r\nConnection: close\r\n\r\n")
            data = s.recv(1024)
            if b'des-cbc3-sha' in data.lower():
                return False
        except:
            pass
    
    return True

# DNS resolution check
def check_dns_resolution(host):
    try:
        socket.gethostbyname(host)
    except:
        return False
    
    return True

# Reverse DNS lookup check
def check_reverse_dns_lookup(host):
    try:
        socket.gethostbyaddr(host)
    except:
        return False
    
    return True

# Check Programming languages
def check_programming_languages(host):
    try:
        response = requests.get(f'http://{host}', timeout=5)
        response.raise_for_status()

        page_source = response.text

        # Search for programming languages in page source
        languages = {
    'PHP': 'php',
    'Python': 'python',
    'Ruby': 'ruby',
    'Perl': 'perl',
    'ASP.NET': 'asp.net',
    'Java': 'java',
    'JavaScript': 'javascript',
    'TypeScript': 'typescript',
    'Swift': 'swift',
    'Objective-C': 'objective-c',
    'C#': 'c#',
    'C++': 'c\+\+',
    'C': 'c',
    'Go': 'go',
    'Scala': '(?i)\\bscala\\b',
    'Kotlin': '(?i)\\bkotlin\\b',
    'Rust': '(?i)\\brust\\b',
    'Haskell': '(?i)\\bhaskell\\b',
    'Elixir': '(?i)\\belixir\\b',
    'Clojure': '(?i)\\bclojure\\b',
    'Groovy': '(?i)\\bgroovy\\b',
    'Dart': '(?i)\\bdart\\b',
    'Lua': '(?i)\\blua\\b',
    'Julia': '(?i)\\bjulia\\b',
    'F#': '(?i)\\bf#\\b',
    'OCaml': '(?i)\\bocaml\\b',
    'Scheme': '(?i)\\bscheme\\b',
    'Common Lisp': '(?i)\\bcommon lisp\\b',
    'Erlang': '(?i)\\berlang\\b',
    'R': '(?i)\\br\\b',
    'Matlab': '(?i)\\bmatlab\\b',
    'Visual Basic': '(?i)\\bvisual basic\\b',
    'Assembly': '(?i)\\bassembly\\b',
    'Shell': '(?i)\\bshell\\b'
        }
        detected_languages = []
        for lang, regex in languages.items():
            if re.search(regex, page_source):
                detected_languages.append(lang)

        if detected_languages:
            print(f"The website is using {', '.join(detected_languages)}")

        return bool(detected_languages)

    except requests.exceptions.RequestException as e:
        print(f"Error checking programming languages: {e}")
        return False
        
# Check for insecure HTTP headers
def check_insecure_http_headers(host):
    url = f'http://{host}'
    response = requests.get(url)
    headers = response.headers
    insecure_headers = []

    # Check for X-Powered-By header
    if 'X-Powered-By' in headers:
        insecure_headers.append('X-Powered-By')

    # Check for Server header
    if 'Server' in headers:
        insecure_headers.append('Server')

    return insecure_headers

# Check for default login credentials
def check_default_login_credentials(host):
    try:
        # Open the file containing default login credentials
        with open("default_credentials.txt", "r") as f:
            default_credentials = f.read().splitlines()

    except FileNotFoundError:
        print("Error: could not open file 'default_credentials.txt'")
        return False

    # List of known default credentials
    known_credentials = ["admin:password", "root:root", "guest:guest"]

    # Check if the host's credentials match any of the known default credentials
    for credential in default_credentials:
        if credential.strip() in known_credentials:
            return True

    return False

def check_logged_in_users(host):
    # check for logged in users
    try:
        output = subprocess.check_output(['ssh', host, 'who']).decode()
    except subprocess.CalledProcessError as e:
        print(f"Error checking for logged in users on {host}: {e}")
        return False
        
    lines = output.strip().split('\n')
    if len(lines) > 0:
        return True

    return False

# Check for publicly accessible sensitive information
def check_publicly_accessible_sensitive_information(url):
    response = requests.get('http://' + url)
    soup = BeautifulSoup(response.text, 'html.parser')
    sensitive_information = []

    # Look for sensitive information in the HTML source code
    for tag in ['input', 'textarea', 'select']:
        for el in soup.find_all(tag):
            if el.has_attr('name') and ('password' in el['name'].lower() or 'token' in el['name'].lower()):
                sensitive_information.append(el['name'])

    return sensitive_information
def check_website_info(host,url):
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()

        # Check for CMS or server technology in headers
        cms = response.headers.get('X-Powered-By')
        if cms:
            print(f"The website is powered by {cms}")

        # Check page source for references to Java or JavaScript
        page_source = response.text
        if re.search(r"<script.*?src.*?\.js", page_source):
            print("The website is using JavaScript")
        if re.search(r"<applet.*?code.*?\.class", page_source):
            print("The website is using Java")

    except requests.exceptions.RequestException as e:
        print(f"Error checking website: {e}")
        
# Main function
def main():
    # Help Menu
    parser = argparse.ArgumentParser(description='Security Configuration Checker')
    parser.add_argument('host', help='hostname or IP address to check')
    parser.add_argument('-f', '--firewall', action='store_true', help='check firewall rules')
    parser.add_argument('-e', '--encryption', action='store_true', help='check encryption settings')
    parser.add_argument('-d', '--dns', action='store_true', help='check DNS resolution')
    parser.add_argument('-r', '--reverse-dns', action='store_true', help='check reverse DNS lookup')
    parser.add_argument('-p', '--programming-languages', action='store_true', help='check programming languages')
    parser.add_argument('-H', '--headers', action='store_true', help='check for insecure HTTP headers')
    parser.add_argument('-w', '--website-info', action='store_true', help='check website info')
    parser.add_argument('-i', '--info', action='store_true', help='check for publicly accessible sensitive information')
    parser.add_argument('-o', '--output', choices=['text', 'json'], default='text', help='output format')
    args = parser.parse_args()

    results = {}
    if args.firewall:
        results['firewall'] = check_firewall_rules(args.host)
    if args.encryption:
        results['encryption'] = check_encryption_settings(args.host)
    if args.dns:
        results['dns'] = check_dns_resolution(args.host)
    if args.reverse_dns:
        results['reverse_dns'] = check_reverse_dns_lookup(args.host)
    if args.programming_languages:
        results['programming_languages'] = check_programming_languages(args.host)
    if args.headers:
        results['headers'] = check_insecure_http_headers(args.host)
    if args.website_info:
        url = f'http://{args.host}'
        results['website_info'] = check_website_info(args.host, url)
    if args.info:
        results['info'] = check_publicly_accessible_sensitive_information(args.host)

    # check credentials
    results['default_credentials'] = check_default_login_credentials(args.host)
    results['logged_in_users'] = check_logged_in_users(args.host)

    # Print or output results
    if args.output == 'json':
        print(json.dumps(results, indent=4))
    else:
        for setting, result in results.items():
            print(f'{setting}: {"Secure" if result else "Insecure"}')

if __name__ == '__main__':
    main()
