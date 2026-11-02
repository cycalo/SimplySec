# Enhanced Port Security System Documentation

## Overview

The Enhanced Port Security System in SimplySec provides comprehensive protection for network ports by going beyond simple firewall rules. It can perform multiple security actions for each port, including:

1. Creating firewall rules
2. Disabling related Windows services
3. Configuring network adapter settings
4. Modifying registry settings

This system is particularly useful for securing ports that require complex fixes, such as port 139 (NetBIOS) which requires both firewall rules AND disabling NetBIOS over TCP/IP.

## Technical Implementation

### The `PortFix` Class

The core of the system is the `PortFix` class which represents a specialized fix for a specific port:

```python
class PortFix:
    def __init__(self, port, name, description, actions):
        """
        Initialize a port fix.
        
        Args:
            port (int): The port number
            name (str): Name of the service using this port
            description (str): Human-readable description of the fix
            actions (list): List of actions to take (firewall, service, netbios, etc.)
        """
```

Each port fix contains a list of actions to take, with each action being a dictionary specifying:
- The action type (e.g., 'firewall', 'service', 'netbios', 'registry')
- Action-specific parameters

### Port Fix Registry

The system maintains a registry of specialized fixes for different ports in the `_initialize_port_fixes` method:

```python
def _initialize_port_fixes(self):
    self.port_fixes = {
        # Port 139 (NetBIOS)
        139: PortFix(
            port=139,
            name="NetBIOS",
            description="NetBIOS is an old Windows protocol that can be exploited.",
            actions=[
                {'type': 'firewall', 'protocol': 'TCP', 'direction': 'in', 'action': 'block'},
                {'type': 'service', 'name': 'lmhosts', 'action': 'disable'},
                {'type': 'netbios'}
            ]
        ),
        # Additional port fixes...
    }
```

### Supported Action Types

1. **Firewall Rules** (`'type': 'firewall'`)
   - Creates Windows Firewall rules using netsh
   - Parameters: `protocol`, `direction`, `action`
   - All rule names start with "SimpleSec-" for easy identification

2. **Service Management** (`'type': 'service'`)
   - Enables or disables Windows services
   - Parameters: `name`, `action`

3. **NetBIOS Configuration** (`'type': 'netbios'`)
   - Disables NetBIOS over TCP/IP on all network adapters
   - No additional parameters required

4. **Registry Modifications** (`'type': 'registry'`)
   - Modifies Windows Registry settings
   - Parameters: `path`, `key`, `value`, `value_type`

## Example Port Fixes

### Port 139 (NetBIOS)

```python
139: PortFix(
    port=139,
    name="NetBIOS",
    description="NetBIOS is an old Windows protocol that can be exploited.",
    actions=[
        {'type': 'firewall', 'protocol': 'TCP', 'direction': 'in', 'action': 'block'},
        {'type': 'firewall', 'protocol': 'UDP', 'direction': 'in', 'action': 'block'},
        {'type': 'service', 'name': 'lmhosts', 'action': 'disable'},
        {'type': 'netbios'}
    ]
)
```

When this port fix is applied, it will create firewall rules with names like `SimpleSec-BlockPort139-TCP-in` and `SimpleSec-BlockPort139-UDP-in`.

### Port 445 (SMB)

```python
445: PortFix(
    port=445,
    name="SMB",
    description="SMB is a Windows file sharing protocol often targeted by ransomware.",
    actions=[
        {'type': 'firewall', 'protocol': 'TCP', 'direction': 'in', 'action': 'block'},
        {'type': 'firewall', 'protocol': 'UDP', 'direction': 'in', 'action': 'block'},
        {'type': 'firewall', 'protocol': 'TCP', 'direction': 'out', 'action': 'block'},
        {'type': 'firewall', 'protocol': 'UDP', 'direction': 'out', 'action': 'block'},
        {'type': 'registry', 'path': 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters', 
         'key': 'SMB1', 'value': 0, 'value_type': 'REG_DWORD'}
    ]
)
```

## How to Add a New Port Fix

To add a fix for a new port, add an entry to the `self.port_fixes` dictionary in the `_initialize_port_fixes` method:

```python
def _initialize_port_fixes(self):
    self.port_fixes = {
        # Existing port fixes...
        
        # New port fix for port XXX
        XXX: PortFix(
            port=XXX,
            name="Service Name",
            description="Description of the service and security implications.",
            actions=[
                # List of actions to take
                {'type': 'firewall', 'protocol': 'TCP', 'direction': 'in', 'action': 'block'},
                # Additional actions...
            ]
        ),
    }
```

## Administrator Privileges

The Enhanced Port Security System requires administrator privileges to:
1. Create and modify firewall rules
2. Manage Windows services
3. Modify registry settings
4. Configure network adapter settings

Always run SimplySec with administrator privileges using the provided `run_as_admin.bat` script.

## Error Handling

The system provides detailed feedback on which actions succeeded or failed. If some actions fail while others succeed, the system will report a partial success and continue with the next port.

## Firewall Rule Naming Convention

All firewall rules created by SimplySec follow a standard naming convention starting with "SimpleSec-" for easy identification in the Windows Firewall settings. This makes it simple to identify, manage, and remove rules created by the application.

Example rule names:
- `SimpleSec-BlockPort139-TCP-in` - Blocks inbound TCP traffic on port 139
- `SimpleSec-BlockPort445-UDP-out` - Blocks outbound UDP traffic on port 445
- `SimpleSec-RestrictPort80-TCP` - Restricts access to port 80 from external networks 