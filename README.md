# Security Configuration Checker
This is a Python-based security testing script that performs multiple security checks on a host. The script is capable of checking for the following:

- Firewall rules
- Encryption settings
- DNS resolution
- Reverse DNS lookup
- Programming languages
- Insecure HTTP headers
- Default login credentials


# Installation & Prerequisite
```
git clone https://github.com/SirCryptic/scc
```
```
cd scc
```

```
pip install -r requirements.txt
```

# Example Usage:
```
python3 scc.py example.com -i -o json
```

```
Security Configuration Checker

positional arguments:
  host                  hostname or IP address to check

options:
  -h, --help            show this help message and exit
  -f, --firewall        check firewall rules
  -e, --encryption      check encryption settings
  -d, --dns             check DNS resolution
  -r, --reverse-dns     check reverse DNS lookup
  -p, --programming-languages
                        check programming languages
  -H, --headers         check for insecure HTTP headers
  -w, --website-info    check website info
  -i, --info            check for publicly accessible sensitive information
  -o {text,json}, --output {text,json}
                        output format
```
