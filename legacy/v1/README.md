# SimplySec - Network Security Tool

SimplySec is a user-friendly network security application for Windows, designed for home users and small businesses with limited security knowledge. It helps identify and fix common security vulnerabilities through network scanning and automated security fixes.

## Features

- **Network Scanning**: Detects open ports and services on your network
- **Security Assessment**: Evaluates risks based on open ports and services
- **Enhanced Port Security**: Goes beyond simple firewall rules with comprehensive fixes
- **Firewall Management**: Controls Windows Firewall settings
- **Security Recommendations**: Provides actionable advice to improve security
- **Security Fix Application**: Applies recommended fixes with one click
- **Log Management**: Keeps records of previous scans

## Requirements

- Windows 10 or later
- Python 3.7 or later
- [Nmap](https://nmap.org/download.html) (installed automatically if missing)
- Administrator privileges for applying security fixes

## Installation

1. Clone or download this repository
2. Install required Python packages:
   ```
   pip install -r requirements.txt
   ```
3. Run the `check_nmap.py` script to verify Nmap is installed:
   ```
   python check_nmap.py
   ```

## Usage

### Running the Application

Always run SimplySec with administrator privileges to enable all security features:

```
run_as_admin.bat
```

### Main Features

1. **Network Scan and Protect**
   - Scans your network for open ports and vulnerabilities
   - Shows risk levels for each port
   - Provides detailed explanations of security implications

2. **Windows Firewall Status**
   - Checks if your firewall is properly configured
   - Allows enabling the firewall if it's disabled

3. **Apply Security Recommendations**
   - Creates firewall rules to block high-risk ports
   - Disables unnecessary services
   - Applies specialized fixes for specific ports (e.g., NetBIOS)
   - Modifies registry settings for better security

4. **View Security Scan Logs**
   - Maintains a history of previous scans
   - Allows reviewing past security issues

## Enhanced Port Security System

SimplySec includes an advanced port security system that goes beyond just firewall rules. For ports like NetBIOS (139) that require multiple security actions, the system can:

1. Create firewall rules
2. Disable related Windows services
3. Configure network adapter settings
4. Modify registry settings

See [port_security_docs.md](port_security_docs.md) for technical details.

## Troubleshooting

- **Administrator Rights**: Most security functions require administrator privileges. Always use the provided `run_as_admin.bat` script.
- **Firewall Rules Not Working**: Some ports require more than just firewall rules. SimplySec's enhanced port security system addresses this.
- **Nmap Not Found**: Run `check_nmap.py` to diagnose and fix Nmap installation issues.

## License

[MIT License](LICENSE)

## Acknowledgements

- [Python-nmap](https://pypi.org/project/python-nmap/) for network scanning capabilities
- [PyQt5](https://pypi.org/project/PyQt5/) for the user interface 