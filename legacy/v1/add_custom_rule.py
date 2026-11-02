import subprocess
import sys
import os
import argparse

def is_admin():
    try:
        # Check if script is running with admin privileges
        return os.name == 'nt' and ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def add_firewall_rule(name, direction, action, port=None, protocol=None, 
                     program=None, remote_ip=None):
    """
    Add a Windows Firewall rule using netsh
    
    Parameters:
    - name: Rule name
    - direction: 'in' or 'out'
    - action: 'allow' or 'block'
    - port: Port number (optional)
    - protocol: 'TCP' or 'UDP' (optional)
    - program: Program path (optional)
    - remote_ip: Remote IP address (optional)
    """
    if not is_admin():
        print("Error: This script must be run as administrator.")
        return False
    
    # Build the command
    cmd = ["netsh", "advfirewall", "firewall", "add", "rule"]
    cmd.extend([f"name={name}", f"dir={direction}", f"action={action}"])
    
    if port:
        cmd.append(f"localport={port}")
    
    if protocol:
        cmd.append(f"protocol={protocol}")
    
    if program:
        cmd.append(f"program={program}")
    
    if remote_ip:
        cmd.append(f"remoteip={remote_ip}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"✓ Firewall rule '{name}' added successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ Failed to add firewall rule: {e.stderr}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Add custom Windows Firewall rules")
    parser.add_argument("--name", required=True, help="Name for the firewall rule")
    parser.add_argument("--direction", required=True, choices=["in", "out"], 
                        help="Direction (in/out)")
    parser.add_argument("--action", required=True, choices=["allow", "block"], 
                        help="Action (allow/block)")
    parser.add_argument("--port", help="Port number")
    parser.add_argument("--protocol", choices=["TCP", "UDP"], help="Protocol (TCP/UDP)")
    parser.add_argument("--program", help="Program path")
    parser.add_argument("--remote-ip", help="Remote IP address")
    
    args = parser.parse_args()
    
    # Ensure we have either port, protocol, or program
    if not any([args.port, args.program, args.remote_ip]):
        print("Error: You must specify at least one of: --port, --program, or --remote-ip")
        parser.print_help()
        sys.exit(1)
    
    # If port is specified, protocol is required
    if args.port and not args.protocol:
        print("Error: --protocol is required when using --port")
        sys.exit(1)
    
    # Add the rule
    success = add_firewall_rule(
        name=args.name,
        direction=args.direction,
        action=args.action,
        port=args.port,
        protocol=args.protocol,
        program=args.program,
        remote_ip=args.remote_ip
    )
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    import ctypes
    main() 