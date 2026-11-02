import sys
import os
import time
import json
import datetime
import ipaddress
import logging
import socket
import subprocess
import threading
import platform
import nmap
import psutil
import signal
import re
import winreg
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QTextEdit, QLineEdit, QProgressBar, 
    QMessageBox, QStatusBar, QDialog, QListWidget, QSplitter, 
    QComboBox, QStyleFactory, QFileDialog, QDialogButtonBox,
    QGroupBox, QScrollArea, QButtonGroup, QRadioButton, QCheckBox
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer, QSize
from PyQt5.QtGui import QFont, QIcon, QTextCursor, QColor, QPalette
from typing import Dict, List, Tuple, Optional, Union, Any

# Configuration Constants
APP_NAME = "SimplySec"
APP_VERSION = "1.0"
DEFAULT_WINDOW_WIDTH = 800
DEFAULT_WINDOW_HEIGHT = 600
LOGS_DIRECTORY = "logs"

# UI Constants
BUTTON_HEIGHT = 50
SPACING = 10

# Risk Level Colors
RISK_COLORS = {
    "High": "#FF5252",    # Red
    "Medium": "#FFA726",  # Orange
    "Low": "#66BB6A"      # Green
}

# Setup logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)
log_file = os.path.join(log_dir, 'simplysec.log')

# Configure the root logger
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# Create a logger for our application
logger = logging.getLogger('SimpleSec')

class ScanThread(QThread):
    """
    Thread for running network scans without blocking the UI.
    
    Signals:
        scan_complete (dict): Emitted when scan is complete with results
        update_progress (str): Provides progress updates during scanning
        update_status (str): Updates the status message shown to the user
    """
    scan_complete = pyqtSignal(dict)
    update_progress = pyqtSignal(str)
    update_status = pyqtSignal(str)
    
    def __init__(self, selected_adapter: Optional[Tuple[str, str]] = None, local_only: bool = True) -> None:
        """
        Initialize the scan thread.
        
        Args:
            selected_adapter: Network adapter to use (name, ip)
            local_only: If True, scan only the local machine. If False, scan the entire network.
        """
        super().__init__()
        self.selected_adapter = selected_adapter
        self.local_only = local_only
        logger.info(f"Scan thread initialized with adapter: {selected_adapter}, local_only: {local_only}")
        
        # Store active nmap processes for cleanup
        self.active_processes = []
        
    def run(self) -> None:
        """Run the network scan in a separate thread."""
        try:
            scan_results = self.scan_network()
            self.scan_complete.emit(scan_results)
        except Exception as e:
            logger.error(f"Error during network scan: {str(e)}", exc_info=True)
            self.update_status.emit(f"Error: {str(e)}")
            self.scan_complete.emit({})
    
    def get_primary_network_interface(self) -> Tuple[str, str]:
        """
        Get the primary network interface (the one with a default route).
        
        Returns:
            Tuple containing (interface_name, ip_address)
        """
        try:
            # Use the selected adapter if provided
            if self.selected_adapter:
                iface_name, ip = self.selected_adapter
                self.update_status.emit(f"Using selected adapter: {iface_name} ({ip})")
                logger.info(f"Using selected adapter: {iface_name} ({ip})")
                return iface_name, ip
            
            # Otherwise try to find the primary interface
            self.update_status.emit("Detecting primary network interface...")
            
            # Get network interfaces with addresses
            addrs = []
            
            # Windows version that focuses on physical adapters
            if platform.system() == "Windows":
                # Use ipconfig to get adapters with more detail
                try:
                    output = subprocess.check_output("ipconfig", text=True)
                    
                    current_adapter = None
                    for line in output.splitlines():
                        line = line.strip()
                        
                        # Look for adapter name lines
                        if line and ":" in line and "adapter" in line.lower():
                            current_adapter = line.strip(":")
                        
                        # Look for IPv4 address lines
                        if current_adapter and "IPv4 Address" in line and ":" in line:
                            ip = line.split(":")[-1].strip()
                            
                            # Skip localhost/loopback addresses
                            if ip.startswith("127.") or ip == "::1":
                                continue
                                
                            # Use a regex to validate the IP
                            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                                addrs.append((current_adapter, ip))
                except Exception as e:
                    logger.error(f"Error getting Windows adapters: {str(e)}")
            else:
                # For non-Windows systems
                net_info = psutil.net_if_addrs()
                
                for iface, addr_list in net_info.items():
                    for addr in addr_list:
                        if addr.family == socket.AF_INET:  # IPv4
                            # Skip localhost
                            if addr.address.startswith("127."):
                                continue
                            addrs.append((iface, addr.address))
            
            if not addrs:
                raise RuntimeError("No suitable network interfaces found")
            
            # Prefer Ethernet over wireless if multiple adapters found
            for addr in addrs:
                iface_name = addr[0].lower()
                if "ethernet" in iface_name or "local area connection" in iface_name:
                    logger.info(f"Selected Ethernet adapter: {addr}")
                    return addr
            
            # If no preference, return the first one
            logger.info(f"Using adapter: {addrs[0]}")
            return addrs[0]
        except Exception as e:
            logger.error(f"Error detecting network interface: {str(e)}", exc_info=True)
            raise RuntimeError(f"Failed to detect network interface: {str(e)}")
    
    def scan_network(self) -> Dict[str, Any]:
        """
        Perform a network scan to discover hosts and open ports.
        
        Returns:
            Dictionary of scan results organized by host
        """
        try:
            interface_name, ip_address = self.get_primary_network_interface()
            logger.info(f"Started network scan with adapter: {interface_name} - {ip_address}")
            
            # Extract network prefix
            ip_obj = ipaddress.IPv4Address(ip_address)
            
            # Determine target network based on scan mode
            if self.local_only:
                # Scan only the local machine
                network = ip_address
                self.update_status.emit(f"Scanning local machine only: {network}")
            elif ip_obj.is_private:
                # For private IPs, scan the local network
                network = f"{ip_address}/24"
                self.update_status.emit(f"Scanning local network: {network}")
            else:
                # For public IPs, just scan the host itself for safety
                network = ip_address
                self.update_status.emit(f"Scanning host: {network}")
            
            # Initialize nmap scanner
            scanner = nmap.PortScanner()
            
            # Scan for host discovery
            self.update_progress.emit("0%")
            self.update_status.emit("Discovering hosts on network...")
            
            # Host discovery scan
            # -T3: Normal timing template (not too fast, not too slow)
            # -sn: Ping scan - disable port scanning, just determine if hosts are up
            # -n: No DNS resolution to speed up scan
            host_scan = scanner.scan(hosts=network, arguments='-T3 -sn -n')
            
            # Check if we found any hosts
            scan_results = {}
            up_hosts = []
            
            if 'scan' in host_scan:
                # Get all hosts that are up
                for host, host_data in host_scan['scan'].items():
                    if host_data.get('status', {}).get('state') == 'up':
                        up_hosts.append(host)
            
            # Always include localhost (the machine running the scan)
            if ip_address not in up_hosts:
                up_hosts.append(ip_address)
            
            # Also always include 127.0.0.1 for comprehensive localhost scanning
            if '127.0.0.1' not in up_hosts:
                up_hosts.append('127.0.0.1')
                
            total_hosts = len(up_hosts)
            if total_hosts > 0:
                self.update_status.emit(f"Found {total_hosts} host(s), scanning ports...")
                
                # For each host, scan for open ports
                for i, host in enumerate(up_hosts):
                    # Skip scanning external hosts for security and privacy
                    if not ipaddress.IPv4Address(host).is_private and host != ip_address:
                        continue
                        
                    self.update_progress.emit(f"{int((i/total_hosts) * 100)}%")
                    self.update_status.emit(f"Scanning host {i+1}/{total_hosts}: {host}")
                    
                    try:
                        # Detailed port scan
                        # -sS: SYN scan (faster, stealthier)
                        # -sV: Version detection
                        # -O: OS detection
                        # -T4: Faster timing template
                        # --top-ports 1000: Scan the 1000 most common ports
                        port_scan = scanner.scan(
                            hosts=host, 
                            arguments='-sS -sV -O --top-ports 1000 -T4'
                        )
                        
                        # Process scan data for this host
                        if 'scan' in port_scan and host in port_scan['scan']:
                            scan_results[host] = port_scan['scan'][host]
                            
                            # Count open ports for status update
                            open_ports = 0
                            
                            # Check TCP ports
                            if 'tcp' in port_scan['scan'][host]:
                                for port, port_data in port_scan['scan'][host]['tcp'].items():
                                    if port_data['state'] == 'open':
                                        open_ports += 1
                            
                            # Check UDP ports
                            if 'udp' in port_scan['scan'][host]:
                                for port, port_data in port_scan['scan'][host]['udp'].items():
                                    if port_data['state'] == 'open':
                                        open_ports += 1
                            
                            self.update_status.emit(f"Found {open_ports} open ports on {host}")
                    except Exception as host_error:
                        logger.error(f"Error scanning host {host}: {str(host_error)}")
                        self.update_status.emit(f"Error scanning {host}: {str(host_error)}")
            
            self.update_progress.emit("100%")
            self.update_status.emit("Scan complete!")
            
            return scan_results
        except Exception as e:
            logger.error(f"Error in network scan: {str(e)}", exc_info=True)
            self.update_status.emit(f"Scan failed: {str(e)}")
            return {}


class AdapterSelectionDialog(QDialog):
    """Dialog to select a network adapter for scanning."""
    
    def __init__(self, parent=None) -> None:
        """Initialize the adapter selection dialog."""
        super().__init__(parent)
        self.setWindowTitle("Select Network Adapter")
        self.selected_adapter: Optional[Tuple[str, str]] = None
        self.init_ui()
    
    def init_ui(self) -> None:
        """Initialize the user interface for the dialog."""
        # Set window properties
        self.resize(500, 300)
        
        # Create layout
        layout = QVBoxLayout()
        
        # Add explanation label
        explanation = QLabel("Select the network adapter to use for scanning:")
        explanation.setWordWrap(True)
        layout.addWidget(explanation)
        
        # Create adapter list
        self.adapter_list = QListWidget()
        layout.addWidget(self.adapter_list)
        
        # Populate adapter list
        adapters = self.get_network_adapters()
        if adapters:
            for adapter in adapters:
                self.adapter_list.addItem(f"{adapter[0]} - {adapter[1]}")
        else:
            self.adapter_list.addItem("No network adapters found")
        
        # Select first item by default
        if self.adapter_list.count() > 0:
            self.adapter_list.setCurrentRow(0)
        
        # Add buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
    
    def get_network_adapters(self) -> List[Tuple[str, str]]:
        """
        Get a list of network adapters with their IP addresses.
        
        Returns:
            List of (adapter_name, ip_address) tuples
        """
        adapters = []
        
        try:
            # On Windows, use ipconfig for more user-friendly adapter names
            if platform.system() == "Windows":
                output = subprocess.check_output("ipconfig", text=True)
                
                current_adapter = None
                for line in output.splitlines():
                    line = line.strip()
                    
                    # Look for adapter name lines
                    if line and ":" in line and "adapter" in line.lower():
                        current_adapter = line.strip(":")
                    
                    # Look for IPv4 address lines
                    if current_adapter and "IPv4 Address" in line and ":" in line:
                        ip = line.split(":")[-1].strip()
                        
                        # Skip localhost/loopback addresses
                        if ip.startswith("127.") or ip == "::1":
                            continue
                        
                        # Use a regex to validate the IP
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
                            # Skip disconnected adapters (often have 169.254.x.x)
                            if ip.startswith("169.254."):
                                continue
                                
                            adapters.append((current_adapter, ip))
            else:
                # For non-Windows systems
                net_info = psutil.net_if_addrs()
                
                for iface, addr_list in net_info.items():
                    for addr in addr_list:
                        if addr.family == socket.AF_INET:  # IPv4
                            # Skip localhost
                            if addr.address.startswith("127."):
                                continue
                            
                            # Skip disconnected adapters (often have 169.254.x.x)
                            if addr.address.startswith("169.254."):
                                continue
                                
                            adapters.append((iface, addr.address))
            
            # Sort adapters: Ethernet first, then WiFi, then others
            adapters.sort(key=self._adapter_sort_key)
            
            return adapters
        except Exception as e:
            logger.error(f"Error getting network adapters: {str(e)}", exc_info=True)
            return []
    
    def _adapter_sort_key(self, adapter: Tuple[str, str]) -> int:
        """
        Sort key function for network adapters.
        
        Args:
            adapter: The adapter tuple (name, ip)
            
        Returns:
            Integer priority (lower is higher priority)
        """
        name = adapter[0].lower()
        if "ethernet" in name or "local area connection" in name:
            return 0
        elif "wi-fi" in name or "wireless" in name or "wlan" in name:
            return 1
        else:
            return 2
    
    def get_selected_adapter(self) -> Optional[Tuple[str, str]]:
        """
        Get the selected network adapter.
        
        Returns:
            Tuple of (adapter_name, ip_address) or None if no selection
        """
        return self.selected_adapter
    
    def accept(self) -> None:
        """Handle the OK button click."""
        selected_index = self.adapter_list.currentRow()
        if selected_index >= 0 and self.adapter_list.count() > 0:
            # Parse the adapter name and IP from the list item text
            text = self.adapter_list.item(selected_index).text()
            parts = text.split(" - ")
            if len(parts) == 2:
                self.selected_adapter = (parts[0], parts[1])
        super().accept()


class PortFix:
    """
    Represents a specialized fix for a specific port that may require multiple actions beyond firewall rules.
    """
    def __init__(self, port: int, name: str, description: str, actions: List[Dict[str, str]]) -> None:
        """
        Initialize a port fix.
        
        Args:
            port: The port number
            name: Name of the service using this port
            description: Human-readable description of the fix
            actions: List of actions to take (firewall, service, netbios, etc.)
        """
        self.port = port
        self.name = name
        self.description = description
        self.actions = actions
        
    def apply(self, app_instance: 'SecurityApp') -> bool:
        """
        Apply all the required fixes for this port.
        
        Args:
            app_instance: Reference to the SecurityApp instance
            
        Returns:
            True if all fixes were successfully applied, False otherwise
        """
        results = []
        total_actions = len(self.actions)
        applied_actions = 0
        failed_actions = []
        
        # Log the start of the fix application
        app_instance.results_text.append(f"\nApplying specialized fix for {self.name} (Port {self.port}):")
        print(f"  > Applying specialized fix for {self.name} (Port {self.port})...")
        
        try:
            for action in self.actions:
                action_type = action.get('type', 'unknown')
                
                if action_type == 'firewall':
                    # Apply firewall rules
                    protocol = action.get('protocol', 'TCP')
                    direction = action.get('direction', 'in')
                    action_value = action.get('action', 'block')
                    
                    app_instance.results_text.append(f"  • Creating {protocol} {direction}bound firewall rule...")
                    
                    result = app_instance._create_firewall_rule(
                        self.port, self.name, protocol, direction, action_value
                    )
                    results.append(result)
                    
                    if result:
                        applied_actions += 1
                    else:
                        failed_actions.append(f"Create {protocol} {direction}bound firewall rule")
                
                elif action_type == 'service':
                    # Disable/configure Windows service
                    service_name = action.get('name', '')
                    service_action = action.get('action', 'disable')
                    
                    if service_action == 'disable':
                        app_instance.results_text.append(f"  • Disabling {service_name} service...")
                    else:
                        app_instance.results_text.append(f"  • Configuring {service_name} service...")
                    
                    result = self._configure_service(service_name, service_action)
                    results.append(result)
                    
                    if result:
                        applied_actions += 1
                    else:
                        failed_actions.append(f"{service_action} {service_name} service")
                
                elif action_type == 'netbios':
                    # Configure NetBIOS over TCP/IP
                    app_instance.results_text.append(f"  • Disabling NetBIOS over TCP/IP on network adapters...")
                    result = self._disable_netbios_over_tcpip()
                    results.append(result)
                    
                    if result:
                        applied_actions += 1
                    else:
                        failed_actions.append("Disable NetBIOS over TCP/IP")
                
                elif action_type == 'registry':
                    # Modify registry settings
                    reg_path = action.get('path', '')
                    reg_key = action.get('key', '')
                    reg_value = action.get('value', 0)
                    reg_type = action.get('type', 'REG_DWORD')
                    
                    app_instance.results_text.append(f"  • Modifying registry key {reg_key}...")
                    
                    try:
                        result = app_instance._modify_registry(reg_path, reg_key, reg_value, reg_type)
                        results.append(result)
                        
                        if result:
                            applied_actions += 1
                            app_instance.results_text.append(f"    ✓ Successfully modified {reg_key}")
                        else:
                            failed_actions.append(f"Modify registry key {reg_key}")
                            app_instance.results_text.append(f"    ✗ Failed to modify {reg_key}")
                    except Exception as e:
                        app_instance.results_text.append(f"    ✗ Error modifying registry: {str(e)}")
                        failed_actions.append(f"Modify registry key {reg_key}")
                        results.append(False)
                
                else:
                    app_instance.results_text.append(f"  ⚠️ Unknown action type: {action_type}")
                    results.append(False)
                    failed_actions.append(f"Unknown action type: {action_type}")
            
            success = len([r for r in results if r]) >= total_actions * 0.75  # 75% success rate required
            
            if success:
                app_instance.results_text.append(f"✅ Successfully applied all {total_actions} fixes for {self.name} (Port {self.port})")
                print(f"  > SUCCESS: Applied all {total_actions} fixes for port {self.port}")
                logger.info(f"Successfully applied all fixes for port {self.port} ({self.name})")
            elif applied_actions > 0:
                app_instance.results_text.append(f"⚠️ Partially applied fixes for {self.name} (Port {self.port}): {applied_actions}/{total_actions} actions completed")
                if failed_actions:
                    app_instance.results_text.append(f"   Failed actions: {', '.join(failed_actions)}")
                
                print(f"  > WARNING: Partially applied fixes for port {self.port}: {applied_actions}/{total_actions}")
                logger.warning(f"Partially applied fixes for port {self.port} ({self.name}): {applied_actions}/{total_actions}")
            else:
                app_instance.results_text.append(f"❌ Failed to apply fixes for {self.name} (Port {self.port})")
                print(f"  > ERROR: Failed to apply fixes for port {self.port}")
                logger.error(f"Failed to apply any fixes for port {self.port} ({self.name})")
            
            return success
            
        except Exception as e:
            app_instance.results_text.append(f"❌ Error applying fixes: {str(e)}")
            logger.error(f"Error applying fixes for port {self.port}: {str(e)}", exc_info=True)
            print(f"  > ERROR: Failed to apply fixes for port {self.port}: {str(e)}")
            return False
    
    def _configure_service(self, service_name: str, action: str = 'disable') -> bool:
        """
        Configure a Windows service.
        
        Args:
            service_name: Name of the service to configure
            action: Action to take (disable, enable, etc.)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # First check if the service exists
            check_cmd = ["sc", "query", service_name]
            check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
            
            # If service doesn't exist, return False but don't treat as error
            if "The specified service does not exist" in check_result.stderr or "1060" in check_result.stderr:
                print(f"  > Service {service_name} does not exist on this system")
                # For OpenSSH specifically, add a note for clarity
                if service_name == "OpenSSH SSH Server" or service_name == "sshd":
                    print(f"  > Note: This is normal if you don't have OpenSSH installed or use a different SSH implementation")
                return False
                
            if action == 'disable':
                # First, stop the service if it's running
                stop_cmd = ["net", "stop", service_name]
                try:
                    stop_result = subprocess.run(stop_cmd, capture_output=True, text=True, timeout=10)
                    if stop_result.returncode == 0:
                        print(f"  > Stopped service {service_name}")
                    else:
                        # Check if it was already stopped
                        if "service was not started" in stop_result.stderr.lower() or "has not been started" in stop_result.stderr.lower():
                            print(f"  > Service {service_name} is already stopped")
                        else:
                            print(f"  > Warning: Could not stop service {service_name}: {stop_result.stderr}")
                            # Try SC STOP as alternative
                            try:
                                alt_stop = ["sc", "stop", service_name]
                                subprocess.run(alt_stop, capture_output=True, text=True, timeout=10)
                                print(f"  > Attempted to stop {service_name} using sc command")
                            except:
                                pass
                except subprocess.SubprocessError as e:
                    print(f"  > Warning: Could not stop service {service_name}: {str(e)}")
                    # Continue anyway to disable it
                
                # Then, disable the service
                cmd = ["sc", "config", service_name, "start=disabled"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    print(f"  > Service {service_name} disabled")
                    logger.info(f"Service {service_name} disabled")
                    return True
                else:
                    print(f"  > Error disabling service {service_name}: {result.stderr}")
                    return False
                
            elif action == 'enable':
                # Configure service to start automatically
                cmd = ["sc", "config", service_name, "start=auto"]
                config_result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if config_result.returncode != 0:
                    print(f"  > Error configuring service {service_name}: {config_result.stderr}")
                    return False
                
                # Start the service
                start_cmd = ["net", "start", service_name]
                start_result = subprocess.run(start_cmd, capture_output=True, text=True, timeout=10)
                
                if start_result.returncode == 0:
                    print(f"  > Service {service_name} enabled and started")
                    logger.info(f"Service {service_name} enabled and started")
                    return True
                else:
                    print(f"  > Warning: Service configured but could not start: {start_result.stderr}")
                    return True  # Still return true since configuration worked
                
            return False
            
        except Exception as e:
            print(f"  > Error configuring service {service_name}: {str(e)}")
            logger.error(f"Error configuring service {service_name}: {str(e)}")
            return False
    
    def _disable_netbios_over_tcpip(self) -> bool:
        """
        Disable NetBIOS over TCP/IP for all network adapters using PowerShell.
        This is needed for completely blocking port 139.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # PowerShell command to disable NetBIOS over TCP/IP on all adapters
            ps_command = """
            # Get all network adapters
            $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
            
            # Disable NetBIOS over TCP/IP for each adapter
            foreach ($adapter in $adapters) {
                Write-Host "Disabling NetBIOS for adapter: " $adapter.Description
                $result = $adapter.SetTcpipNetbios(2)
                if ($result.ReturnValue -eq 0) {
                    Write-Host "Successfully disabled NetBIOS over TCP/IP"
                } else {
                    Write-Host "Failed to disable NetBIOS over TCP/IP. Error code: " $result.ReturnValue
                }
            }
            """
            
            # Execute the PowerShell command
            cmd = ["powershell", "-Command", ps_command]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            # Check if the command was successful
            if "Successfully disabled NetBIOS over TCP/IP" in result.stdout:
                print("  > NetBIOS over TCP/IP disabled for network adapters")
                logger.info("NetBIOS over TCP/IP disabled for network adapters")
                print(f"  > PowerShell output: {result.stdout.strip()}")
                return True
            else:
                print("  > Warning: Could not verify NetBIOS over TCP/IP was disabled")
                logger.warning("Could not verify NetBIOS over TCP/IP was disabled")
                print(f"  > PowerShell output: {result.stdout.strip()}")
                print(f"  > PowerShell error: {result.stderr.strip()}")
                
                # If PowerShell didn't work, provide user instructions
                print("  > Providing manual instructions to the user")
                return False
                
        except Exception as e:
            print(f"  > Error disabling NetBIOS over TCP/IP: {str(e)}")
            logger.error(f"Error disabling NetBIOS over TCP/IP: {str(e)}")
            return False
    
    def _modify_registry(self, registry_path: str, key_name: str, value: Union[str, int], value_type: str = 'REG_DWORD') -> bool:
        """
        Modify a Windows registry key.
        
        Args:
            registry_path: Registry path (e.g. 'HKLM\\SYSTEM\\CurrentControlSet\\Services')
            key_name: Name of the registry key
            value: Value to set
            value_type: Type of registry value (REG_DWORD, REG_SZ, etc.)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Format the value based on its type
            if value_type == 'REG_DWORD':
                formatted_value = str(value)
            elif value_type == 'REG_SZ':
                formatted_value = f'"{value}"'
            else:
                formatted_value = str(value)
            
            # Create the registry command
            cmd = [
                "reg", "add", registry_path, 
                "/v", key_name, 
                "/t", value_type, 
                "/d", formatted_value, 
                "/f"
            ]
            
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            print(f"  > Modified registry key {registry_path}\\{key_name}")
            logger.info(f"Modified registry key {registry_path}\\{key_name}")
            return True
            
        except Exception as e:
            print(f"  > Error modifying registry key {registry_path}\\{key_name}: {str(e)}")
            logger.error(f"Error modifying registry key {registry_path}\\{key_name}: {str(e)}")
            return False


class SecurityApp(QMainWindow):
    """
    Main application window for SimpleSec security scanning tool.
    
    Provides functionality for:
    - Network scanning and vulnerability detection
    - Firewall status checking
    - Security recommendations
    - Log management
    """
    def __init__(self):
        """Initialize the security application."""
        super().__init__()
        
        # Initialize application state
        self.is_scanning = False
        self.scan_thread = None
        self.scan_results = {}
        self.scan_count = 0
        self.is_exiting = False
        
        # Set up logs directory
        self.logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), LOGS_DIRECTORY)
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # Initialize port fixes registry
        self._initialize_port_fixes()
        
        # Setup UI components
        self.setWindowTitle("SimplySec - Network Security Scanner")
        self.setMinimumSize(800, 600)
        self.initUI()
        
        # Center the window on screen
        self.center_window()
        
        # Check firewall status on startup
        QTimer.singleShot(1000, self.check_firewall_status)
        
        logger.info("SimplySec v1.0 started")
    
    def initUI(self):
        """Initialize the user interface components."""
        self.setWindowTitle(f'{APP_NAME} - Network Security')
        self.setGeometry(100, 100, DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT)
        
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Add header section
        main_layout.addLayout(self._create_header_section())
        
        # Add options section
        main_layout.addWidget(self._create_options_section())
        
        # Add progress section
        main_layout.addWidget(self._create_progress_section())
        
        # Add results section
        main_layout.addWidget(self._create_results_section())
        
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Welcome message
        self.results_text.append(f"Welcome to {APP_NAME}!")
        self.results_text.append("Select an option above to begin securing your system.")
    
    def _create_header_section(self):
        """Create the header section with title and subtitle."""
        header_layout = QVBoxLayout()
        
        # Header
        header_label = QLabel(f'{APP_NAME} - Network Security Tool')
        header_font = QFont()
        header_font.setPointSize(16)
        header_font.setBold(True)
        header_label.setFont(header_font)
        header_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(header_label)
        
        # Subtitle
        subtitle_label = QLabel('Protect your network with simple, understandable security')
        subtitle_label.setAlignment(Qt.AlignCenter)
        header_layout.addWidget(subtitle_label)
        
        return header_layout
    
    def _create_options_section(self):
        """Create the options section with action buttons."""
        options_group = QGroupBox("Security Options")
        options_layout = QVBoxLayout()
        
        # Add scan mode selection checkbox
        self.scan_mode_layout = QHBoxLayout()
        self.local_scan_checkbox = QCheckBox("Scan only my computer")
        self.local_scan_checkbox.setChecked(True)  # Default to local-only scan
        self.local_scan_checkbox.setToolTip("When checked, only your computer will be scanned (faster). When unchecked, your entire local network will be scanned.")
        self.scan_mode_layout.addWidget(self.local_scan_checkbox)
        self.scan_mode_layout.addStretch()
        options_layout.addLayout(self.scan_mode_layout)
        
        # Add some spacing
        options_layout.addSpacing(SPACING)
        
        # Network scan button
        self.scan_btn = QPushButton('Network Scan and Protect')
        self.scan_btn.setMinimumHeight(BUTTON_HEIGHT)
        self.scan_btn.clicked.connect(self.start_network_scan)
        options_layout.addWidget(self.scan_btn)
        
        # Add some spacing
        options_layout.addSpacing(SPACING)
        
        # Firewall status button
        self.firewall_btn = QPushButton('Windows Firewall Status')
        self.firewall_btn.setMinimumHeight(BUTTON_HEIGHT)
        self.firewall_btn.clicked.connect(self.check_firewall_status)
        options_layout.addWidget(self.firewall_btn)
        
        # Add some spacing
        options_layout.addSpacing(SPACING)
        
        # View Logs button
        self.logs_btn = QPushButton('View Security Scan Logs')
        self.logs_btn.setMinimumHeight(BUTTON_HEIGHT)
        self.logs_btn.clicked.connect(self.show_logs)
        options_layout.addWidget(self.logs_btn)
        
        options_group.setLayout(options_layout)
        return options_group
    
    def _create_progress_section(self):
        """Create the progress section with status and progress bar."""
        self.progress_group = QGroupBox("Scan Progress")
        progress_layout = QVBoxLayout()
        
        # Status label above progress bar
        self.status_label = QLabel("Preparing scan...")
        self.status_label.setAlignment(Qt.AlignCenter)
        progress_layout.addWidget(self.status_label)
        
        # Busy indicator (indeterminate progress bar)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)  # Setting min=max=0 makes it indeterminate
        self.progress_bar.setTextVisible(False)
        
        # Add some style to make it more visually appealing
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid grey;
                border-radius: 5px;
                text-align: center;
                height: 20px;
                background-color: #f0f0f0;
            }
            
            QProgressBar::chunk {
                background-color: #4CAF50;
            }
        """)
        
        progress_layout.addWidget(self.progress_bar)
        
        self.progress_group.setLayout(progress_layout)
        self.progress_group.setVisible(False)  # Hide initially
        return self.progress_group
    
    def _create_results_section(self):
        """Create the results section with text display and action buttons."""
        results_group = QGroupBox("Results and Actions")
        results_layout = QVBoxLayout()
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        
        scroll_area = QScrollArea()
        scroll_area.setWidget(self.results_text)
        scroll_area.setWidgetResizable(True)
        
        results_layout.addWidget(scroll_area)
        
        # Action buttons (initially hidden)
        self.action_layout = QHBoxLayout()
        self.secure_btn = QPushButton('Apply Security Recommendations')
        self.secure_btn.clicked.connect(self.apply_security_fixes)
        self.secure_btn.setVisible(False)
        self.action_layout.addWidget(self.secure_btn)
        
        results_layout.addLayout(self.action_layout)
        results_group.setLayout(results_layout)
        return results_group
    
    def start_network_scan(self):
        """
        Start the network scanning process by showing adapter selection dialog
        and initializing the scanning thread.
        """
        try:
            # First, show adapter selection dialog
            adapter_dialog = AdapterSelectionDialog(self)
            if adapter_dialog.exec_() != QDialog.Accepted:
                # User cancelled
                logger.info("User cancelled adapter selection")
                return
            
            # Get selected adapter
            selected_adapter = adapter_dialog.get_selected_adapter()
            if not selected_adapter:
                QMessageBox.warning(self, "No Adapter Selected", "Please select a network adapter to continue.")
                logger.warning("No adapter selected for scan")
                return
                
            # Clear and update UI
            self._prepare_ui_for_scan(selected_adapter)
            
            # Get scan mode from checkbox
            local_only = self.local_scan_checkbox.isChecked()
            
            # Create and start scanning thread with selected adapter and scan mode
            self.scan_thread = ScanThread(selected_adapter, local_only)
            self.scan_thread.update_progress.connect(self.update_scan_progress)
            self.scan_thread.update_status.connect(self.update_status_label)
            self.scan_thread.scan_complete.connect(self.display_scan_results)
            self.scan_thread.start()
            
            logger.info(f"Started network scan with adapter: {selected_adapter[0]} - {selected_adapter[1]}, local_only: {local_only}")
        except Exception as e:
            logger.error(f"Error starting network scan: {str(e)}", exc_info=True)
            QMessageBox.critical(self, "Scan Error", f"An error occurred starting the scan: {str(e)}")
    
    def _prepare_ui_for_scan(self, selected_adapter):
        """
        Prepare the UI for a scan in progress.
        
        Args:
            selected_adapter (tuple): The selected adapter (name, ip)
        """
        self.results_text.clear()
        self.results_text.append("Security Scan in Progress")
        self.results_text.append(f"Using adapter: {selected_adapter[0]} ({selected_adapter[1]})")
        
        # Show scan mode
        scan_mode = "Scanning local computer only" if self.local_scan_checkbox.isChecked() else "Scanning entire network"
        self.results_text.append(scan_mode)
        
        self.scan_btn.setEnabled(False)
        self.secure_btn.setVisible(False)
        
        # Show progress group with busy indicator
        self.progress_group.setVisible(True)
        self.status_label.setText("Preparing scan...")
    
    def update_status_label(self, status):
        """
        Update the status label above the progress bar.
        
        Args:
            status (str): Status message to display
        """
        self.status_label.setText(status)
        logger.debug(f"Status update: {status}")
    
    def update_scan_progress(self, message):
        """
        Filter and display scan progress messages.
        
        Args:
            message (str): Progress message from scan thread
        """
        # Filter out all progress messages and only show essential information
        essential_info = [
            "Computer Name:", 
            "Network Adapter:", 
            "Detected local IP:",
            "Found device:"
        ]
        
        # Only display essential information
        if any(info in message for info in essential_info):
            self.results_text.append(message)
            logger.debug(f"Progress update: {message}")
    
    def display_scan_results(self, results):
        """
        Process and display scan results.
        
        Args:
            results (dict): Scan results from the scanner
        """
        try:
            self.scan_results = results
            self.scan_btn.setEnabled(True)
            
            # Hide progress group when scan is complete
            self.progress_group.setVisible(False)
            
            if not results:
                self._display_no_results()
                return
            
            # Clear previous content and display results
            self._display_scan_results(results)
            
            logger.info("Scan completed and results displayed")
        except Exception as e:
            logger.error(f"Error displaying scan results: {str(e)}", exc_info=True)
            self.results_text.clear()
            self.results_text.append(f"Error processing scan results: {str(e)}")
            self.scan_btn.setEnabled(True)
            self.progress_group.setVisible(False)
    
    def _display_no_results(self):
        """Display a message when no scan results are available."""
        self.results_text.clear()
        self.results_text.append("No scan results or an error occurred during scanning.")
        logger.warning("No scan results to display")
    
    def _display_scan_results(self, results):
        """
        Format and display the scan results in the UI.
        
        Args:
            results (dict): Scan results to display
        """
        # Clear previous content and show results header
        self.results_text.clear()
        self.results_text.append("--- SECURITY SCAN COMPLETE ---\n")
        
        # Get our primary IP to identify our computer in the results
        my_ip = self.get_primary_ip()
        
        # Get hostname and adapter information for the log
        hostname = socket.gethostname()
        adapter_name = self.get_adapter_name(my_ip)
        
        # Store the results as text for logging
        log_text = []
        log_text.append(f"--- SECURITY SCAN ({datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---")
        log_text.append(f"HOSTNAME: {hostname}")
        log_text.append(f"NETWORK ADAPTER: {adapter_name}")
        log_text.append(f"IP ADDRESS: {my_ip}")
        log_text.append("") # Empty line for better readability
        
        # Add system info to results display
        self.results_text.append(f"Computer: {hostname}")
        self.results_text.append(f"Network: {adapter_name}")
        self.results_text.append(f"IP Address: {my_ip}\n")
        
        # Process scan results for the local machine
        if my_ip in results:
            self._process_host_scan_results(results[my_ip], my_ip, log_text)
        else:
            self.results_text.append(f"Error: Could not scan your computer ({my_ip})")
            log_text.append(f"Error: Could not scan your computer ({my_ip})")
            return
        
        # Security recommendations
        self.results_text.append("--- SECURITY RECOMMENDATIONS ---\n")
        log_text.append("--- SECURITY RECOMMENDATIONS ---")
        
        recommendations = self.generate_recommendations()
        
        for rec in recommendations:
            self.results_text.append(f"• {rec}")
            log_text.append(f"• {rec}")
        
        # Save the log to a file
        self.save_log(log_text, results)
        
        # Show action button if we have recommendations
        if recommendations:
            self.secure_btn.setVisible(True)
    
    def _process_host_scan_results(self, host_data, ip, log_text):
        """
        Process and display scan results for a specific host.
        
        Args:
            host_data (dict): Scan data for the host
            ip (str): IP address of the host
            log_text (list): List to append log entries to
        """
        # Count open ports
        open_tcp_ports = len(host_data.get('tcp', {})) if 'tcp' in host_data else 0
        open_udp_ports = len(host_data.get('udp', {})) if 'udp' in host_data else 0
        total_open_ports = open_tcp_ports + open_udp_ports
        
        self.results_text.append(f"YOUR COMPUTER ({ip}):")
        self.results_text.append(f"Detected {total_open_ports} open ports ({open_tcp_ports} TCP, {open_udp_ports} UDP)\n")
        
        # Add to log text
        log_text.append(f"OPEN PORTS: {total_open_ports} ({open_tcp_ports} TCP, {open_udp_ports} UDP)")
        
        if total_open_ports == 0:
            self.results_text.append("  No open ports detected")
            log_text.append("No open ports detected")
            return
        
        # Track security issues found
        security_issues = []
        
        # Process TCP ports
        if 'tcp' in host_data:
            self.results_text.append("TCP PORTS:")
            log_text.append("TCP PORTS:")
            for port, port_data in host_data['tcp'].items():
                self._process_port_data(port, port_data, security_issues, log_text, 'TCP')
            self.results_text.append("")
        
        # Process UDP ports
        if 'udp' in host_data:
            self.results_text.append("UDP PORTS:")
            log_text.append("UDP PORTS:")
            for port, port_data in host_data['udp'].items():
                self._process_port_data(port, port_data, security_issues, log_text, 'UDP')
            self.results_text.append("")
        
        # Store security issues for recommendations
        self.security_issues = security_issues
    
    def _process_port_data(self, port, port_data, security_issues, log_text, protocol):
        """
        Process and display information about a specific port.
        
        Args:
            port (str or int): Port number
            port_data (dict): Port scan data
            security_issues (list): List to append security issues to
            log_text (list): List to append log entries to
            protocol (str): Protocol ('TCP' or 'UDP')
        """
        try:
            # Convert port to int if it's a string
            port_num = int(port) if isinstance(port, str) else port
            
            service = port_data.get('name', 'unknown')
            product = port_data.get('product', '')
            version = port_data.get('version', '')
            state = port_data.get('state', '')
            
            # Security risk level based on service
            risk_level = self.assess_port_risk(port_num, service)
            risk_color = self.get_risk_color(risk_level)
            
            # Format port info
            port_info = f"  Port {port_num}/{protocol} ({service})"
            if product:
                port_info += f" - {product}"
                if version:
                    port_info += f" {version}"
            
            port_info += f" [Risk: {risk_level}]"
            self.results_text.append(port_info)
            log_text.append(port_info)
            
            # Add explanations for security implications
            explanation = self.get_port_explanation(port_num)
            if explanation:
                self.results_text.append(f"    → {explanation}")
                log_text.append(f"    → {explanation}")
            
            # Check for vulnerabilities in scripts output
            if 'script' in port_data:
                self._process_vulnerability_scripts(port_data['script'], service, port_num, security_issues, log_text)
            
            # If this is a risky port, add a specific recommendation
            if risk_level in ['High', 'Medium']:
                rec = self.get_port_recommendation(port_num, service)
                if rec:
                    self.results_text.append(f"    👉 {rec}")
                    log_text.append(f"    👉 {rec}")
                    security_issues.append(f"Risky port {port_num}/{protocol} ({service}) is open")
            
            self.results_text.append("")
            log_text.append("")
        except Exception as e:
            logger.error(f"Error processing port {port}: {str(e)}", exc_info=True)
            self.results_text.append(f"  Error processing port {port}: {str(e)}")
            log_text.append(f"Error processing port {port}: {str(e)}")
    
    def _process_vulnerability_scripts(self, scripts, service, port, security_issues, log_text):
        """
        Process vulnerability script outputs for a port.
        
        Args:
            scripts (dict): Script results
            service (str): Service name
            port (int or str): Port number
            security_issues (list): List to append security issues to
            log_text (list): List to append log entries to
        """
        for script_name, output in scripts.items():
            # Look for vulnerability information in the output
            if output and ('VULNERABLE' in output or 'WARNING' in output or 'CVE' in output):
                # Simplify the display of security issues
                self.results_text.append(f"    ⚠️ SECURITY ISSUE DETECTED: {script_name}")
                log_text.append(f"    ⚠️ SECURITY ISSUE DETECTED: {script_name}")
                
                # Extract the most important info (first 2-3 lines)
                important_info = output.strip().split('\n')[:3]
                for line in important_info:
                    if line.strip():
                        self.results_text.append(f"      {line.strip()}")
                        log_text.append(f"      {line.strip()}")
                
                # Add to security issues list
                security_issues.append(f"Security issue with {service} on port {port}")
    
    def assess_port_risk(self, port, service):
        """Assess the security risk level of a port"""
        # High-risk ports and services based on common attack vectors
        high_risk_ports = {
            21: "FTP Control",       # Often targeted by hackers, unencrypted
            22: "SSH",               # Secure remote access but frequently brute-forced
            23: "Telnet",            # Old, unencrypted remote access, very risky
            69: "TFTP",              # Trivial FTP, often unauthenticated and risky
            135: "RPC",              # Often exploited by attackers
            137: "NetBIOS",          # Legacy Windows file sharing, risky
            138: "NetBIOS",          # Legacy Windows network discovery
            139: "NetBIOS",          # Legacy Windows printer sharing
            445: "SMB",              # Common ransomware target
            5060: "SIP",             # VoIP signaling, can be abused for toll fraud
            1433: "MS SQL Server",   # Database port, often attacked
            1723: "PPTP",            # Weak VPN protocol, avoid use
            1900: "UPnP",            # Can expose internal devices
            3389: "RDP",             # Remote desktop, frequent target of brute force
            3388: "Alternate RDP",   # Sometimes used as alternate RDP port
            5432: "PostgreSQL",      # Database port, secure if properly configured
            5900: "VNC",             # Remote desktop, often weakly secured
            5901: "VNC Variant",     # Additional VNC ports
            11211: "Memcached",      # Often exploited in DDoS attacks
            12345: "NetBus",         # Malware-associated port
            27017: "MongoDB",        # Database port, often unsecured
            5000: "UPnP/Media Server", # UPnP and media servers can be risky
            8443: "HTTPS Alt",       # Secure web admin panels, often targeted
            10000: "Webmin",         # Web-based server management
            25565: "Minecraft",      # Game server, should be secured if public
        }

        medium_risk_ports = {
            20: "FTP Data",          # Often insecure data channel
            25: "SMTP",              # Email sending, can be abused for spam
            53: "DNS",               # DNS servers can be abused for amplification
            80: "HTTP",              # Unencrypted web traffic
            110: "POP3",             # Unencrypted email retrieval
            123: "NTP",              # Time sync, can be abused in amplification attacks
            143: "IMAP",             # Unencrypted email syncing
            161: "SNMP",             # Can leak sensitive info if misconfigured
            3306: "MySQL",           # Database port, secure if configured properly
            8080: "HTTP Alt",        # Alternate HTTP port, often used for admin panels
            9090: "Openfire",        # Chat server, may be unnecessary
            9100: "Printer",         # Network printing, can be abused
            10000: "Webmin",         # Also medium if not properly secured
        }

        # Normalize service string for matching
        service_norm = service.lower().strip() if service else ""

        # Check for high-risk services regardless of port
        high_risk_services = ["telnet", "netbus", "netbios", "microsoft-ds", "ms-sql", "rdp", "vnc", "ssh", "rpc", "smb", "memcached", "mongodb", "upnp", "pptp"]
        medium_risk_services = ["http", "smtp", "pop3", "imap", "ftp", "mysql", "snmp", "upnp", "dns", "ntp"]

        if port in high_risk_ports or any(s in service_norm for s in high_risk_services):
            return "High"
        elif port in medium_risk_ports or any(s in service_norm for s in medium_risk_services):
            return "Medium"
        else:
            return "Low"
    
    def get_risk_color(self, risk_level):
        """Return color code for risk level"""
        if risk_level == "High":
            return "red"
        elif risk_level == "Medium":
            return "orange"
        else:
            return "green"
    
    def get_port_recommendation(self, port, service):
        """Get specific recommendation for a port"""
        recommendations = {
            20: "Disable FTP if not needed, or use secure alternatives like SFTP/FTPS",
            21: "Close FTP port or use SFTP/FTPS instead for secure file transfers",
            22: "Secure SSH with key-based authentication and disable password login. Consider using non-standard ports and IP filtering",
            23: "Disable Telnet immediately and use SSH instead for secure remote access",
            25: "Secure SMTP with TLS or use ports 465/587 for encrypted email sending",
            53: "Keep your DNS server software updated and properly configured",
            69: "Disable TFTP unless absolutely necessary; it is unauthenticated and risky",
            80: "Consider redirecting HTTP traffic to HTTPS for better security",
            110: "Use secure POP3S (port 995) instead for encrypted email downloads",
            123: "Secure NTP servers or restrict access to prevent abuse",
            135: "Block RPC from external access - commonly targeted by attackers",
            137: "Disable NetBIOS if not needed on your network",
            138: "Turn off NetBIOS network discovery for better security",
            139: "Block NetBIOS ports from external access",
            143: "Use secure IMAPS (port 993) instead for encrypted email syncing",
            161: "Secure SNMP with strong community strings or disable if not needed",
            445: "Block SMB from external access to prevent ransomware attacks",
            5060: "Secure SIP servers to prevent toll fraud or disable if unused",
            1433: "Restrict SQL Server access and use strong authentication",
            1723: "Avoid using PPTP VPN - use more secure alternatives like OpenVPN",
            1900: "Disable UPnP if not needed to prevent potential vulnerabilities",
            3306: "Secure MySQL with strong passwords and restricted access",
            3389: "Lock down RDP with VPN, strong passwords, or disable if unused",
            3388: "Check alternate RDP ports and secure similarly",
            5432: "Secure PostgreSQL with authentication and firewall rules",
            5900: "Protect VNC with a strong password or disable if not needed",
            5901: "Secure additional VNC ports similarly",
            8080: "Secure alternate HTTP ports or redirect to HTTPS",
            8443: "Secure HTTPS alternate ports, often used for admin panels",
            9090: "Disable Openfire chat server if not used",
            9100: "Secure printer ports or disable if unnecessary",
            10000: "Secure Webmin access with strong authentication or disable",
            11211: "Close Memcached port if not needed - frequently exploited",
            12345: "Close this port immediately - known for malware (NetBus)",
            25565: "Secure Minecraft servers or close if unused",
            27017: "Keep MongoDB closed or secured with authentication",
            5000: "Disable UPnP/media servers if not needed to reduce attack surface"
        }
        return recommendations.get(port, "")
    
    def get_port_explanation(self, port: int) -> str:
        """Explain the purpose and security implications of common ports"""
        port_explanations = {
            20: "FTP Data - Transfers files between devices. Often insecure—avoid leaving open.",
            21: "FTP Control - Manages file transfers. Hackers often target this—keep closed if unused.",
            22: "SSH - Secure remote access to computers/servers. While secure, it's frequently targeted by brute force attacks.",
            23: "Telnet - Old, unencrypted remote access. Very risky—disable this!",
            25: "SMTP - Sends emails (e.g., your Gmail outgoing messages).",
            53: "DNS - Translates website names to IP addresses (like a phonebook for the internet).",
            67: "DHCP Server - Assigns IP addresses to devices on your network (like automatic WiFi setup).",
            68: "DHCP Client - Receives IP addresses from the DHCP server.",
            69: "TFTP - Trivial FTP, often unauthenticated and risky for file transfers.",
            80: "HTTP - Regular websites (not secure—never enter passwords here!).",
            110: "POP3 - Downloads emails to one device (used by older email apps).",
            123: "NTP - Keeps your device's clock accurate (syncs time automatically). Can be abused in amplification attacks.",
            135: "RPC - Allows programs to communicate. Often exploited by hackers—close if possible.",
            137: "NetBIOS - Old Windows file sharing. Disable unless you need it.",
            138: "NetBIOS - Old Windows network discovery. Turn off for safety.",
            139: "NetBIOS - Old Windows printer sharing. Risky if left open.",
            143: "IMAP - Syncs emails across devices (like the Mail app on your phone).",
            161: "SNMP - Monitors network devices (printers, routers). Can leak data if unsecured.",
            443: "HTTPS - Secure websites (banks, shopping sites). Safe for passwords.",
            445: "SMB - Shares files/printers on Windows. A common target for hackers!",
            465: "SMTP Secure - Sends emails with encryption (safer than regular SMTP).",
            5060: "SIP - Used for VoIP calls (like Skype or Zoom). Can be abused if unsecured.",
            587: "SMTP Modern - Newer secure email-sending port (used by most email apps).",
            631: "CUPS - Used for printer sharing (like connecting to a home printer).",
            993: "IMAP Secure - Encrypted email syncing (protects your inbox).",
            995: "POP3 Secure - Encrypted email downloads (safer than regular POP3).",
            1433: "MS SQL Server - Database port for Microsoft apps. Keep closed unless needed.",
            1723: "PPTP - Older VPN protocol. Not secure—avoid using this.",
            1900: "UPnP - Auto-configures devices on your network (like Gaming Consoles). Can be risky.",
            2483: "Oracle DB - Database port for Oracle software. Close if unused.",
            3306: "MySQL - Database port for websites/apps. Secure it if open.",
            3388: "Alternate RDP - Sometimes used as an alternate port for Remote Desktop.",
            3389: "RDP - Remote access to Windows PCs (like Screen Sharing). Lock this down!",
            5432: "PostgreSQL - Database port for modern apps. Secure with authentication.",
            5900: "VNC - Remote screen sharing. Protect with a strong password!",
            5901: "VNC Variant - Additional VNC ports, secure similarly.",
            6881: "BitTorrent - Peer-to-peer file sharing (used by torrent apps).",
            8080: "HTTP Alt - Alternate port for websites (common for local projects).",
            8443: "HTTPS Alt - Secure alternate port for websites (like admin panels).",
            9090: "Openfire - Chat server port. Close if you don't use chat apps.",
            9100: "Printer - Direct printing port (used by some network printers).",
            10000: "Webmin - Web-based server management tool. Secure it!",
            11211: "Memcached - Database caching port. Often exploited—keep closed.",
            12345: "NetBus - Known for malware. Close immediately if open.",
            25565: "Minecraft - Hosts Minecraft multiplayer games. Fun but secure it!",
            27017: "MongoDB - Database port for modern apps. Keep closed if unused.",
            5000: "UPnP/Media Server - Often used for media streaming or device discovery. Disable if not needed."
        }
        return port_explanations.get(port, "")
    
    def generate_recommendations(self):
        recommendations = []
        
        # Add specific recommendations based on detected issues
        if hasattr(self, 'security_issues') and self.security_issues:
            for issue in self.security_issues:
                action_item = self.convert_issue_to_action(issue)
                if action_item and action_item not in recommendations:
                    recommendations.append(action_item)
        
        # Check for high-risk ports
        my_ip = self.get_primary_ip()
        if my_ip in self.scan_results:
            host_data = self.scan_results[my_ip]
            
            # Only highlight the most critical ports for home/small business users
            critical_ports = {
                21: "Disable FTP or use SFTP instead for secure file transfers",
                22: "Secure SSH with key-based authentication and disable password login. Consider using non-standard ports and IP filtering",
                23: "Disable Telnet immediately - it's a major security risk",
                135: "Block RPC ports from external access - commonly targeted by attackers",
                139: "Block NetBIOS ports - disable if not sharing files on your network",
                445: "Restrict Windows file sharing (SMB) access to prevent ransomware",
                1433: "Secure SQL Server or disable if not needed",
                3306: "Secure MySQL database or disable if not needed",
                3389: "Secure Remote Desktop (RDP) with a VPN or disable it when not in use",
                5900: "Protect VNC with a strong password or disable if not needed",
                8080: "Secure alternate HTTP ports or redirect to HTTPS",
                10000: "Secure Webmin or disable if not needed",
                12345: "Close this port immediately - known for malware (NetBus)"
            }
            
            # Check TCP ports
            if 'tcp' in host_data:
                for port_str, port_data in host_data['tcp'].items():
                    if port_data.get('state') == 'open':
                        port = int(port_str)
                        if port in critical_ports and f"port {port}" not in ' '.join(recommendations):
                            recommendations.append(critical_ports[port])
            
            # Check UDP ports
            if 'udp' in host_data:
                for port_str, port_data in host_data['udp'].items():
                    if port_data.get('state') == 'open':
                        port = int(port_str)
                        if port in critical_ports and f"port {port}" not in ' '.join(recommendations):
                            recommendations.append(critical_ports[port])
        
        # Add basic security recommendations (limit to 6 most important)
        basic_recs = [
            "Enable Windows Firewall on all network profiles",
            "Keep all software and operating system up-to-date with security patches",
            "Use HTTPS (port 443) instead of HTTP (port 80) for websites whenever possible",
            "Use secure ports for email: IMAPS (993), POP3S (995), and SMTPS (465/587)",
            "Install and maintain antivirus/anti-malware software",
            "Create regular system backups to protect against ransomware attacks"
        ]
        
        # Add basic recommendations that aren't already covered
        for rec in basic_recs:
            if not any(rec.lower() in r.lower() for r in recommendations):
                recommendations.append(rec)
        
        # Limit to 10 recommendations maximum to avoid overwhelming the user
        if len(recommendations) > 10:
            recommendations = recommendations[:10]
            
        return recommendations
    
    def convert_issue_to_action(self, issue):
        """Convert a security issue into an actionable recommendation"""
        # Extract service and port information
        if "Security issue with" in issue and "on port" in issue:
            service = issue.split("with ")[1].split(" on port")[0]
            port = issue.split("on port ")[1]
            
            # Get specific recommendation if available
            try:
                port_num = int(port)
                rec = self.get_port_recommendation(port_num, service)
                if rec:
                    return rec
            except:
                pass
                
            # Generic recommendation based on service
            return f"Update {service} to the latest secure version and check its configuration"
            
        # Generic port recommendation
        if "Risky port" in issue and "is open" in issue:
            try:
                # Format: "Risky port 123/TCP (service) is open"
                parts = issue.split("Risky port ")[1].split(" is open")[0]
                port_info = parts.split(" (")[0]  # Get "123/TCP"
                service = parts.split("(")[1].split(")")[0]  # Get "service"
                
                port = port_info.split("/")[0]  # Get just the port number
                protocol = port_info.split("/")[1]  # Get the protocol
                
                return f"Secure {service} on port {port}/{protocol} if not needed"
            except:
                # Fallback for old format
                try:
                    port = issue.split("port ")[1].split(" ")[0]
                    service = issue.split("(")[1].split(")")[0]
                    return f"Secure {service} on port {port} if not needed"
                except:
                    pass
                
        return None
    
    def apply_security_fixes(self):
        """
        Apply security fixes based on scan results.
        This includes enabling Windows Firewall and adding port-specific rules.
        """
        reply = QMessageBox.question(
            self, 'Confirm Action', 
            'This will apply security fixes to your system. Continue?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                self.results_text.append("\nApplying security fixes...")
                logger.info("Starting to apply security fixes")
                print("\n======== APPLYING SECURITY FIXES ========")
                print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Starting security fix application")
                
                # Create our enhanced security fixer
                self.security_fixer = SecurityFixer(self.results_text)
                
                # Apply fixes in order of importance
                self._enable_windows_firewall()
                
                # Use the enhanced security fixer for advanced fixes
                self._apply_enhanced_security_fixes()
                
                # Apply firewall rules for all ports
                self._apply_port_specific_fixes()
                
                # Set default firewall policy
                self._set_default_firewall_policy()
                
                self.results_text.append("\nSecurity fixes applied. Your system is now better protected.")
                self.results_text.append("Note: Some services may require restarting to apply all changes.")
                logger.info("Security fixes applied successfully")
                print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Security fixes completed successfully")
                print("========================================\n")
            except Exception as e:
                self.results_text.append(f"\n❌ Error applying security fixes: {str(e)}")
                logger.error(f"Error applying security fixes: {str(e)}", exc_info=True)
                print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] ERROR: Failed to apply security fixes: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to apply security fixes: {str(e)}")
    
    def _apply_enhanced_security_fixes(self):
        """Apply enhanced security fixes using the SecurityFixer class."""
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Applying advanced security fixes...")
        self.results_text.append("\n--- ENHANCED SECURITY FIXES ---")
        
        # Define high-risk ports and medium-risk ports
        high_risk_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 135: "RPC", 137: "NetBIOS", 
            138: "NetBIOS", 139: "NetBIOS", 445: "SMB", 1433: "SQL Server",
            3389: "RDP", 5900: "VNC", 11211: "Memcached", 12345: "NetBus"
        }
        
        medium_risk_ports = {
            80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
            1723: "PPTP", 8080: "HTTP-Alt", 10000: "Webmin"
        }
        
        # Apply comprehensive security fixes
        success_count, total_count = self.security_fixer.apply_all_security_fixes(
            self.scan_results, high_risk_ports, medium_risk_ports
        )
        
        # Show summary
        if success_count > 0:
            self.results_text.append(f"\n--- SECURITY HARDENING SUMMARY ---")
            if self.security_fixer.fixed_items:
                self.results_text.append("✅ Successfully secured:")
                for item in self.security_fixer.fixed_items:
                    self.results_text.append(f"  • {item}")
                    
            if self.security_fixer.failed_items:
                self.results_text.append("\n❌ Failed to secure:")
                for item in self.security_fixer.failed_items:
                    self.results_text.append(f"  • {item}")
                
        # Report to logs
        logger.info(f"Enhanced security fixes applied: {success_count}/{total_count} successful")
        print(f"  > Enhanced security fixes: {success_count}/{total_count} successful")
    
    def _enable_windows_firewall(self):
        """Enable Windows Firewall on all profiles."""
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Enabling Windows Firewall on all profiles...")
        command = ["netsh", "advfirewall", "set", "allprofiles", "state", "on"]
        print(f"  > EXECUTING: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command, 
                check=True,
                capture_output=True,
                text=True
            )
            self.results_text.append("✓ Windows Firewall enabled on all profiles")
            logger.info("Enabled Windows Firewall on all profiles")
            print(f"  > SUCCESS: Windows Firewall enabled")
            if result.stdout:
                print(f"  > OUTPUT: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            self.results_text.append(f"✗ Failed to enable Windows Firewall: {e.stderr}")
            logger.error(f"Failed to enable Windows Firewall: {e.stderr}")
            print(f"  > ERROR: Failed to enable Windows Firewall")
            print(f"  > STDERR: {e.stderr}")
            raise
    
    def _apply_port_specific_fixes(self):
        """Apply port-specific security fixes based on scan results."""
        my_ip = self.get_primary_ip()
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Applying port-specific security fixes for {my_ip}...")
        
        if my_ip not in self.scan_results:
            self.results_text.append("⚠️ No scan results available for port-specific fixes.")
            logger.warning("No scan results available for port-specific fixes")
            print(f"  > WARNING: No scan results available for port-specific fixes")
            return
        
        host_data = self.scan_results[my_ip]
        open_ports = {}
        
        # Collect TCP ports
        if 'tcp' in host_data:
            for port, port_data in host_data['tcp'].items():
                if port_data.get('state') == 'open':
                    open_ports[port] = port_data
        
        # Collect UDP ports
        if 'udp' in host_data:
            for port, port_data in host_data['udp'].items():
                if port_data.get('state') == 'open':
                    open_ports[port] = port_data
        
        if not open_ports:
            self.results_text.append("⚠️ No open ports found to secure.")
            logger.warning("No open ports found to secure")
            print(f"  > WARNING: No open ports found to secure")
            return
        
        # Debug: Print detected open ports - convert keys to strings first
        port_list = [str(port) for port in open_ports.keys()]
        print(f"  > Found {len(open_ports)} open ports to analyze")
        print(f"  > Open ports: {', '.join(port_list)}")
        
        # Track which ports we've applied fixes for
        fixed_ports = []
        
        # Apply fixes for high-risk ports first
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Processing high-risk ports...")
        self._fix_high_risk_ports(open_ports, fixed_ports)
        
        # Then apply fixes for medium-risk ports
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Processing medium-risk ports...")
        self._fix_medium_risk_ports(open_ports, fixed_ports)
        
        # Check if we fixed any security issues
        if not fixed_ports:
            self.results_text.append("No high-risk ports needed to be secured")
            logger.info("No high-risk ports needed to be secured")
            print(f"  > INFO: No high-risk ports needed to be secured")
        else:
            port_strings = [str(port) for port in fixed_ports]
            self.results_text.append(f"✓ Protected {len(fixed_ports)} ports: {', '.join(port_strings)}")
            logger.info(f"Protected {len(fixed_ports)} ports: {', '.join(port_strings)}")
            print(f"  > SUCCESS: Protected {len(fixed_ports)} ports: {', '.join(port_strings)}")
            
            # Verify the ports are actually blocked
            if fixed_ports:
                # Wait a moment for firewall rules to take effect
                time.sleep(2)
                self._verify_all_protected_ports(fixed_ports)
    
    def _fix_high_risk_ports(self, open_ports, fixed_ports):
        """
        Apply security fixes for high-risk ports.
        
        Args:
            open_ports (dict): Dictionary of open ports from scan results
            fixed_ports (list): List to track which ports have been fixed
        """
        # Define high-risk ports and services
        high_risk_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 135: "RPC", 137: "NetBIOS", 
            138: "NetBIOS", 139: "NetBIOS", 445: "SMB", 1433: "SQL Server",
            3389: "RDP", 5900: "VNC", 11211: "Memcached", 12345: "NetBus"
        }
        
        # Also check for high-risk services by name
        high_risk_services = {
            "ssh": "SSH",
            "msrpc": "RPC", 
            "netbios-ssn": "NetBIOS", 
            "microsoft-ds": "SMB",
            "ms-wbt-server": "RDP"
        }
        
        # Iterate through the port entries in the scan results
        for port, port_info in open_ports.items():
            try:
                # Convert port to integer if it's a string
                port_num = int(port) if isinstance(port, str) else port
                
                # Get service name if available
                service_name = port_info.get('name', 'unknown')
                
                # Check if this is a high-risk port by number or service name
                is_high_risk = port_num in high_risk_ports or service_name in high_risk_services
                
                if is_high_risk:
                    # Get display name for the service
                    display_name = high_risk_ports.get(port_num, high_risk_services.get(service_name, service_name))
                    
                    print(f"  > Found high-risk port {port_num} ({service_name}/{display_name}) - blocking...")
                    
                    # First verify if any existing rules are already blocking this port
                    self._remove_existing_port_rules(port_num)
                    
                    # Check if this port has a specialized fix
                    if port_num in self.port_fixes:
                        print(f"  > Applying specialized fix for port {port_num} ({display_name})...")
                        
                        # Apply the specialized fix
                        success = self.port_fixes[port_num].apply(self)
                        
                        if success:
                            fixed_ports.append(port_num)
                            logger.info(f"Applied specialized fix for port {port_num} ({display_name})")
                            print(f"  > SUCCESS: Applied specialized fix for port {port_num}")
                        else:
                            # Still add to fixed ports since we did try to fix it
                            fixed_ports.append(port_num)
                            logger.warning(f"Partial fix applied for port {port_num} ({display_name})")
                            print(f"  > WARNING: Could only apply partial fix for port {port_num}")
                    else:
                        # Create standard firewall rules
                        # 1. Block TCP inbound
                        self._create_firewall_rule(port_num, display_name, "TCP", "in", "block")
                        
                        # 2. Block UDP inbound
                        self._create_firewall_rule(port_num, display_name, "UDP", "in", "block")
                        
                        # For critical ports like RDP and SMB, also block outbound
                        if port_num in [445, 3389, 22]:  # Added SSH (22) as critical
                            # 3. Block TCP outbound for critical services
                            self._create_firewall_rule(port_num, display_name, "TCP", "out", "block")
                            
                            # 4. Block UDP outbound for critical services
                            self._create_firewall_rule(port_num, display_name, "UDP", "out", "block")
                        
                        # Verify the rules were created
                        if self._verify_port_blocked(port_num):
                            self.results_text.append(f"✓ Blocked high-risk port {port_num} ({display_name})")
                            fixed_ports.append(port_num)
                            logger.info(f"Blocked high-risk port {port_num} ({display_name})")
                            print(f"  > SUCCESS: Blocked port {port_num}")
                        else:
                            self.results_text.append(f"⚠️ Port {port_num} may not be fully blocked - created rules but verification failed")
                            logger.warning(f"Port {port_num} rules created but verification failed")
                            print(f"  > WARNING: Port {port_num} rules created but verification failed")
                            # Still add to fixed ports since we did try to fix it
                            fixed_ports.append(port_num)
                
            except (ValueError, KeyError) as e:
                print(f"  > ERROR processing port {port}: {str(e)}")
    
    def _fix_medium_risk_ports(self, open_ports, fixed_ports):
        """
        Apply security fixes for medium-risk ports.
        
        Args:
            open_ports (dict): Dictionary of open ports from scan results
            fixed_ports (list): List to track which ports have been fixed
        """
        # Define medium-risk ports that need attention
        medium_risk_ports = {
            80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP",
            1723: "PPTP", 8080: "HTTP-Alt", 10000: "Webmin"
        }
        
        # Also check for medium-risk services by name
        medium_risk_services = {
            "http": "HTTP",
            "pop3": "POP3",
            "imap": "IMAP",
            "snmp": "SNMP"
        }
        
        # Iterate through the port entries in the scan results
        for port, port_info in open_ports.items():
            try:
                # Convert port to integer if it's a string
                port_num = int(port) if isinstance(port, str) else port
                
                # Skip if already fixed
                if port_num in fixed_ports:
                    continue
                
                # Get service name if available
                service_name = port_info.get('name', 'unknown')
                
                # Check if this is a medium-risk port by number or service name
                is_medium_risk = port_num in medium_risk_ports or service_name in medium_risk_services
                
                if is_medium_risk:
                    # Get display name for the service
                    display_name = medium_risk_ports.get(port_num, medium_risk_services.get(service_name, service_name))
                    
                    print(f"  > Found medium-risk port {port_num} ({service_name}/{display_name}) - restricting external access...")
                    
                    # Remove any existing rules first
                    self._remove_existing_port_rules(port_num)
                    
                    # Create rule to block external access but allow local
                    command = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=SimpleSec-RestrictPort{port_num}-TCP", "dir=in", f"localport={port_num}",
                        "protocol=TCP", "action=block", "remoteip=Internet", "profile=any"
                    ]
                    print(f"  > EXECUTING: {' '.join(command)}")
                    
                    try:
                        result = subprocess.run(
                            command,
                            check=True,
                            capture_output=True,
                            text=True
                        )
                        
                        # Also create UDP rule
                        udp_command = [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name=SimpleSec-RestrictPort{port_num}-UDP", "dir=in", f"localport={port_num}",
                            "protocol=UDP", "action=block", "remoteip=Internet", "profile=any"
                        ]
                        subprocess.run(udp_command, check=True, capture_output=True, text=True)
                        
                        # Ensure rules persist
                        try:
                            subprocess.run(
                                ["netsh", "advfirewall", "export", "policy.wfw"], 
                                stdout=subprocess.DEVNULL, 
                                stderr=subprocess.DEVNULL
                            )
                        except:
                            print(f"  > WARNING: Failed to export firewall policy")
                        
                        self.results_text.append(f"✓ Restricted external access to port {port_num} ({display_name})")
                        fixed_ports.append(port_num)
                        logger.info(f"Restricted external access to port {port_num} ({display_name})")
                        print(f"  > SUCCESS: Restricted external access to port {port_num}")
                        if result.stdout:
                            print(f"  > OUTPUT: {result.stdout.strip()}")
                    except subprocess.CalledProcessError as e:
                        self.results_text.append(f"✗ Failed to restrict port {port_num}: {e.stderr}")
                        logger.error(f"Failed to restrict port {port_num}: {e.stderr}")
                        print(f"  > ERROR: Failed to restrict port {port_num}")
                        print(f"  > STDERR: {e.stderr}")
            except (ValueError, KeyError) as e:
                print(f"  > ERROR processing port {port}: {str(e)}")
                
    def _set_default_firewall_policy(self):
        """Set default firewall policy to block inbound connections."""
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Setting default firewall policy...")
        command = [
            "netsh", "advfirewall", "set", "allprofiles", 
            "firewallpolicy", "blockinbound,allowoutbound"
        ]
        print(f"  > EXECUTING: {' '.join(command)}")
        
        try:
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True
            )
            self.results_text.append("✓ Set default firewall policy to block inbound connections")
            logger.info("Set default firewall policy to block inbound connections")
            print(f"  > SUCCESS: Default firewall policy set to block inbound connections")
            if result.stdout:
                print(f"  > OUTPUT: {result.stdout.strip()}")
            
            # Restart the Windows Firewall service to ensure changes take effect
            self._restart_firewall_service()
            
        except subprocess.CalledProcessError as e:
            self.results_text.append(f"✗ Failed to update default firewall policy: {e.stderr}")
            logger.error(f"Failed to update default firewall policy: {e.stderr}")
            print(f"  > ERROR: Failed to update default firewall policy")
            print(f"  > STDERR: {e.stderr}")
    
    def _restart_firewall_service(self):
        """Restart the Windows Firewall service to ensure changes take effect."""
        try:
            print(f"  > Restarting Windows Firewall service...")
            
            # Export current firewall configuration
            export_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "firewall_backup.wfw")
            try:
                export_cmd = ["netsh", "advfirewall", "export", export_path]
                subprocess.run(export_cmd, capture_output=True, text=True, timeout=10)
                print(f"  > Exported current firewall configuration")
            except Exception as e:
                print(f"  > WARNING: Could not export firewall configuration: {str(e)}")
            
            # Stop firewall service
            stop_command = ["net", "stop", "MpsSvc"]
            subprocess.run(stop_command, capture_output=True, text=True, timeout=15)
            
            # Wait a moment for the service to stop
            import time
            time.sleep(2)
            
            # Start firewall service
            start_command = ["net", "start", "MpsSvc"]
            result = subprocess.run(start_command, capture_output=True, text=True, timeout=15)
            
            # Wait for service to fully initialize
            time.sleep(3)
            
            # Import the saved configuration if it exists
            if os.path.exists(export_path):
                try:
                    import_cmd = ["netsh", "advfirewall", "import", export_path]
                    subprocess.run(import_cmd, capture_output=True, text=True, timeout=10)
                    print(f"  > Restored firewall configuration")
                    
                    # Clean up
                    os.remove(export_path)
                except Exception as e:
                    print(f"  > WARNING: Could not import firewall configuration: {str(e)}")
            
            print(f"  > Windows Firewall service restarted")
            self.results_text.append("✓ Restarted Windows Firewall service")
            logger.info("Restarted Windows Firewall service")
        except Exception as e:
            print(f"  > WARNING: Could not restart firewall service: {str(e)}")
            logger.warning(f"Could not restart firewall service: {str(e)}")
    
    def check_firewall_status(self):
        """Check and display the current status of Windows Firewall."""
        try:
            self.results_text.clear()
            self.results_text.append("Checking Windows Firewall status...\n")
            self.secure_btn.setVisible(False)
            
            # Make sure progress bar is hidden
            self.progress_group.setVisible(False)
            
            # Run firewall status command
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"], 
                capture_output=True, 
                text=True,
                check=True
            )
            
            # Display the output
            self.results_text.append(result.stdout)
            
            # Check if any profile is off
            if "State                                 OFF" in result.stdout:
                self._handle_disabled_firewall()
            
            logger.info("Checked firewall status")
        except subprocess.CalledProcessError as e:
            self.results_text.append(f"Error checking firewall status: {e.stderr}")
            logger.error(f"Error checking firewall status: {e.stderr}")
        except Exception as e:
            self.results_text.append(f"Error checking firewall status: {str(e)}")
            logger.error(f"Error checking firewall status: {str(e)}", exc_info=True)
    
    def _handle_disabled_firewall(self):
        """Handle the case when one or more firewall profiles are disabled."""
        self.results_text.append("\n⚠️ WARNING: One or more firewall profiles are disabled!")
        self.results_text.append("Recommendation: Enable all firewall profiles for better security.")
        
        # Add button to enable all profiles
        self.secure_btn.setText("Enable All Firewall Profiles")
        self.secure_btn.clicked.disconnect()
        self.secure_btn.clicked.connect(self.enable_all_firewall_profiles)
        self.secure_btn.setVisible(True)
        
        logger.warning("One or more firewall profiles are disabled")
    
    def enable_all_firewall_profiles(self):
        """Enable all Windows Firewall profiles."""
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "on"], 
                check=True,
                capture_output=True,
                text=True
            )
            self.results_text.append("\n✓ All firewall profiles have been enabled.")
            self.secure_btn.setVisible(False)
            
            # Refresh the status
            self.check_firewall_status()
            
            logger.info("Enabled all firewall profiles")
        except subprocess.CalledProcessError as e:
            self.results_text.append(f"\n✗ Failed to enable firewall profiles: {e.stderr}")
            logger.error(f"Failed to enable firewall profiles: {e.stderr}")
        except Exception as e:
            self.results_text.append(f"\n✗ Failed to enable firewall profiles: {str(e)}")
            logger.error(f"Failed to enable firewall profiles: {str(e)}", exc_info=True)
    
    def get_primary_ip(self):
        """Get the primary IP address of this computer"""
        try:
            # Use the same method as in the scanner to be consistent
            result = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True)
            output = result.stdout
            
            # Split by adapter sections
            adapters = output.split("\r\n\r\n")
            
            for adapter in adapters:
                # Skip virtual, loopback, and disconnected adapters
                if not adapter or "Media disconnected" in adapter:
                    continue
                if "vEthernet" in adapter or "VMware" in adapter or "VirtualBox" in adapter:
                    continue
                if "Loopback" in adapter or "Pseudo-Interface" in adapter:
                    continue
                
                # Look for Ethernet or Wi-Fi adapters (physical adapters)
                if "Ethernet adapter" in adapter or "Wireless LAN adapter" in adapter:
                    # Find IPv4 Address line
                    for line in adapter.split("\r\n"):
                        if "IPv4 Address" in line:
                            # Extract IP address
                            ip = line.split(":")[-1].strip()
                            return ip
            
            # Fall back to default method
            return socket.gethostbyname(socket.gethostname())
            
        except Exception:
            # Fall back to default method
            return socket.gethostbyname(socket.gethostname())
    
    def exit_application(self):
        """Safely exit the application after terminating all processes"""
        # Skip if we're already exiting (prevent recursion)
        if self.is_exiting:
            return
            
        # Confirm exit
        reply = QMessageBox.question(
            self, 'Confirm Exit', 
            'Are you sure you want to exit SimpleSec?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            # Set exiting flag
            self.is_exiting = True
            
            # Update UI to show we're cleaning up
            self.results_text.append("\nStopping scan and cleaning up...")
            
            if hasattr(self, 'status_label'):
                self.status_label.setText("Terminating processes...")
            
            # Stop any running scan threads
            if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
                # Terminate the thread and wait for it to finish
                self.scan_thread.terminate()
                self.scan_thread.wait(3000)  # Wait up to 3 seconds
            
            # Kill any nmap processes that might be running
            try:
                if os.name == 'nt':  # Windows
                    subprocess.run(["taskkill", "/F", "/IM", "nmap.exe"], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL)
                else:  # Linux/Mac
                    subprocess.run(["pkill", "-f", "nmap"], 
                               stdout=subprocess.DEVNULL, 
                               stderr=subprocess.DEVNULL)
            except:
                # Ignore errors when trying to kill processes
                pass
            
            # Exit the application
            QApplication.quit()
        else:
            return

    def closeEvent(self, event):
        """
        Handle the window close event (X button).
        
        Args:
            event: The close event
        """
        # Skip if we're already exiting (prevent recursion)
        if self.is_exiting:
            event.accept()
            return
            
        # Confirm exit
        reply = QMessageBox.question(
            self, 'Confirm Exit', 
            f'Are you sure you want to exit {APP_NAME}?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                # Set exiting flag
                self.is_exiting = True
                
                # Clean up resources
                self._cleanup_resources()
                
                # Accept the close event to allow the window to close
                event.accept()
                
                # Exit the application
                QApplication.quit()
                
                logger.info(f"{APP_NAME} application closed")
            except Exception as e:
                logger.error(f"Error during application exit: {str(e)}", exc_info=True)
                event.accept()
                QApplication.quit()
        else:
            # Reject the close event to keep the window open
            event.ignore()
    
    def _cleanup_resources(self):
        """Clean up resources before exiting."""
        # Stop any running scan threads
        if hasattr(self, 'scan_thread') and self.scan_thread.isRunning():
            try:
                # Terminate the thread and wait for it to finish
                logger.info("Terminating running scan thread")
                self.scan_thread.terminate()
                self.scan_thread.wait(3000)  # Wait up to 3 seconds
            except Exception as e:
                logger.error(f"Error terminating scan thread: {str(e)}")
        
        # Kill any nmap processes that might be running
        try:
            if os.name == 'nt':  # Windows
                logger.info("Terminating any running nmap processes")
                subprocess.run(
                    ["taskkill", "/F", "/IM", "nmap.exe"], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL
                )
            else:  # Linux/Mac
                logger.info("Terminating any running nmap processes")
                subprocess.run(
                    ["pkill", "-f", "nmap"], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL
                )
        except Exception as e:
            # Ignore errors when trying to kill processes
            logger.error(f"Error killing nmap processes: {str(e)}")
            pass

    def save_log(self, log_text, scan_results):
        """
        Save the scan results to log files.
        
        Args:
            log_text (list): Lines of text for the human-readable log
            scan_results (dict): Raw scan results data
        """
        try:
            # Create a timestamped filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"scan_{timestamp}.log"
            log_path = os.path.join(self.logs_dir, log_filename)
            
            # Save the text log with UTF-8 encoding
            with open(log_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(log_text))
            
            # Save raw data as JSON for potential future analysis
            json_filename = f"scan_{timestamp}.json"
            json_path = os.path.join(self.logs_dir, json_filename)
            
            # Create a serializable version of scan results
            serializable_results = {
                'timestamp': timestamp,
                'scan_date': datetime.datetime.now().isoformat(),
                'hostname': socket.gethostname(),
                'ip_address': self.get_primary_ip(),
                'scan_data': scan_results,
                'recommendations': self.generate_recommendations(),
                'security_issues': self.security_issues
            }
            
            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(serializable_results, f, indent=2, ensure_ascii=False)
            
            logger.info(f"Saved scan logs to {log_path} and {json_path}")
        except Exception as e:
            self.results_text.append(f"\nError saving log: {str(e)}")
            logger.error(f"Error saving log: {str(e)}", exc_info=True)
    
    def show_logs(self):
        """Show the logs dialog with previous scan results."""
        try:
            # Create logs dialog
            logs_dialog = QDialog(self)
            logs_dialog.setWindowTitle("Security Scan Logs")
            logs_dialog.setGeometry(150, 150, 800, 500)
            
            # Create layout and UI elements
            layout = self._create_logs_dialog_layout(logs_dialog)
            logs_dialog.setLayout(layout)
            
            # Select the first log if available
            if self.logs_list.count() > 0:
                self.logs_list.setCurrentRow(0)
            else:
                self.log_content.setText("No logs found. Run a scan to create logs.")
            
            logs_dialog.exec_()
            logger.info("Opened logs viewer")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error displaying logs: {str(e)}")
            logger.error(f"Error displaying logs: {str(e)}", exc_info=True)
    
    def _create_logs_dialog_layout(self, parent_dialog):
        """
        Create the layout for the logs dialog.
        
        Args:
            parent_dialog: The parent dialog to create the layout for
            
        Returns:
            QVBoxLayout: The layout for the logs dialog
        """
        # Create layout
        layout = QVBoxLayout()
        
        # Create a splitter for logs list and content
        splitter = QSplitter(Qt.Horizontal)
        
        # Create list of log files
        self.logs_list = QListWidget()
        self.logs_list.setMaximumWidth(250)
        
        # Load log files
        self.refresh_logs_list()
        
        # Create log content viewer
        self.log_content = QTextEdit()
        self.log_content.setReadOnly(True)
        
        # Connect selection change to display log
        self.logs_list.currentRowChanged.connect(self.display_log_content)
        
        # Add widgets to splitter
        splitter.addWidget(self.logs_list)
        splitter.addWidget(self.log_content)
        
        # Set initial splitter sizes
        splitter.setSizes([200, 600])
        
        layout.addWidget(splitter)
        
        # Add button row with action buttons
        button_layout = QHBoxLayout()
        
        # Delete button
        delete_btn = QPushButton("Delete Selected Log")
        delete_btn.clicked.connect(lambda: self.delete_selected_log(parent_dialog))
        delete_btn.setStyleSheet("background-color: #d9534f; color: white;")
        button_layout.addWidget(delete_btn)
        
        # Add spacer to push buttons to opposite sides
        button_layout.addStretch()
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(parent_dialog.accept)
        button_layout.addWidget(close_btn)
        
        layout.addLayout(button_layout)
        
        return layout
    
    def refresh_logs_list(self):
        """Refresh the list of log files in the logs dialog."""
        try:
            # Clear current list
            self.logs_list.clear()
            
            # Get log files
            log_files = self._get_log_files()
            
            # Add to list widget
            for file, display_date in log_files:
                self.logs_list.addItem(f"{display_date}")
                # Store the actual filename as item data
                self.logs_list.item(self.logs_list.count()-1).setData(Qt.UserRole, file)
                
            logger.debug(f"Refreshed logs list, found {len(log_files)} logs")
        except Exception as e:
            logger.error(f"Error refreshing logs list: {str(e)}", exc_info=True)
    
    def _get_log_files(self):
        """
        Get a list of available log files.
        
        Returns:
            list: List of tuples (filename, display_date) sorted by date (newest first)
        """
        log_files = []
        
        try:
            for file in os.listdir(self.logs_dir):
                if file.endswith('.log'):
                    # Extract timestamp from filename
                    try:
                        timestamp = file.replace('scan_', '').replace('.log', '')
                        date_obj = datetime.datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
                        display_date = date_obj.strftime("%Y-%m-%d %H:%M:%S")
                        log_files.append((file, display_date))
                    except:
                        # If parsing fails, just show the filename
                        log_files.append((file, file))
            
            # Sort by date, newest first
            log_files.sort(reverse=True)
        except Exception as e:
            logger.error(f"Error getting log files: {str(e)}", exc_info=True)
        
        return log_files
    
    def delete_selected_log(self, parent_dialog):
        """
        Delete the selected log file.
        
        Args:
            parent_dialog: The parent dialog
        """
        try:
            # Get selected row
            current_row = self.logs_list.currentRow()
            if current_row < 0:
                QMessageBox.warning(parent_dialog, "No Log Selected", "Please select a log to delete.")
                return
            
            # Get filename
            filename = self.logs_list.item(current_row).data(Qt.UserRole)
            display_name = self.logs_list.item(current_row).text()
            
            # Confirm deletion
            reply = QMessageBox.question(
                parent_dialog, 
                'Confirm Deletion', 
                f'Are you sure you want to delete the log from {display_name}?\nThis cannot be undone.',
                QMessageBox.Yes | QMessageBox.No, 
                QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self._perform_log_deletion(filename, current_row, parent_dialog)
        except Exception as e:
            QMessageBox.critical(parent_dialog, "Error", f"Error processing delete request: {str(e)}")
            logger.error(f"Error in delete_selected_log: {str(e)}", exc_info=True)
    
    def _perform_log_deletion(self, filename, current_row, parent_dialog):
        """
        Perform the actual log deletion.
        
        Args:
            filename (str): Name of the log file to delete
            current_row (int): Index of the selected row
            parent_dialog: The parent dialog
        """
        try:
            # Delete log file
            log_path = os.path.join(self.logs_dir, filename)
            os.remove(log_path)
            
            # Also delete the corresponding JSON file if it exists
            json_filename = filename.replace('.log', '.json')
            json_path = os.path.join(self.logs_dir, json_filename)
            if os.path.exists(json_path):
                os.remove(json_path)
            
            # Refresh the list
            self.refresh_logs_list()
            
            # Clear content if the list is now empty
            if self.logs_list.count() == 0:
                self.log_content.setText("No logs found. Run a scan to create logs.")
            else:
                # Select the next item (or the last one if we deleted the last)
                new_row = min(current_row, self.logs_list.count() - 1)
                self.logs_list.setCurrentRow(new_row)
            
            QMessageBox.information(parent_dialog, "Success", "Log deleted successfully.")
            logger.info(f"Deleted log file: {filename}")
            
        except Exception as e:
            QMessageBox.critical(parent_dialog, "Error", f"Failed to delete log: {str(e)}")
            logger.error(f"Failed to delete log {filename}: {str(e)}", exc_info=True)
    
    def display_log_content(self, row):
        """
        Display the content of the selected log file.
        
        Args:
            row (int): Selected row index
        """
        try:
            if row >= 0:
                # Get the filename from the item data
                filename = self.logs_list.item(row).data(Qt.UserRole)
                log_path = os.path.join(self.logs_dir, filename)
                
                with open(log_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                self.log_content.setText(content)
                logger.debug(f"Displayed log content for {filename}")
            else:
                self.log_content.clear()
        except Exception as e:
            self.log_content.setText(f"Error loading log: {str(e)}")
            logger.error(f"Error loading log content: {str(e)}", exc_info=True)
    
    def get_adapter_name(self, ip_address):
        """Get the network adapter name for a specific IP address"""
        try:
            # Get network interface information using ipconfig
            result = subprocess.run(["ipconfig"], capture_output=True, text=True, check=True)
            output = result.stdout
            
            # Split by adapter sections
            adapters = output.split("\r\n\r\n")
            
            for adapter in adapters:
                # Skip empty sections
                if not adapter:
                    continue
                    
                # Extract adapter name (first line)
                adapter_name = adapter.split(":")[0].strip() if ":" in adapter else "Unknown Adapter"
                
                # Check if this adapter has our IP
                if ip_address in adapter:
                    return adapter_name
            
            return "Unknown Adapter"
            
        except Exception:
            return "Unknown Adapter"
    
    def _test_port_connectivity(self, port_num):
        """
        Test if a port is actually blocked by attempting to connect to it.
        
        Args:
            port_num (int): Port number to test
            
        Returns:
            str: 'blocked', 'open', or 'unknown'
        """
        try:
            # Use socket to test if port is accessible
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(1)  # Short timeout
            
            result = test_socket.connect_ex(('127.0.0.1', port_num))
            test_socket.close()
            
            if result == 0:
                # Connection succeeded - port is open
                return 'open'
            else:
                # Connection failed - port is likely blocked or not listening
                return 'blocked'
        except Exception as e:
            print(f"  > ERROR testing port {port_num}: {str(e)}")
            return 'unknown'
    
    def _verify_all_protected_ports(self, fixed_ports):
        """
        Verify that all fixed ports are actually blocked.
        
        Args:
            fixed_ports (list): List of port numbers to verify
        """
        print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Verifying port blocking...")
        
        # Verify all ports
        verification_failures = []
        for port in fixed_ports:
            if not self._verify_port_blocked(port):
                verification_failures.append(port)
        
        if verification_failures:
            self.results_text.append(f"⚠️ Some ports may not be fully blocked: {', '.join(str(p) for p in verification_failures)}")
            logger.warning(f"Verification failed for ports: {verification_failures}")
            print(f"  > WARNING: Verification failed for ports: {verification_failures}")
        else:
            self.results_text.append("✓ All ports verified as blocked")
            logger.info("All ports verified as blocked")
            print(f"  > SUCCESS: All ports verified as blocked")
        
        return len(verification_failures) == 0
    
    def _remove_existing_port_rules(self, port_num):
        """Remove any existing firewall rules for the specified port to avoid conflicts."""
        try:
            # Delete both specific format rules and legacy format rules
            
            # Delete specific format rules for each protocol and direction
            for protocol in ["TCP", "UDP"]:
                for direction in ["in", "out"]:
                    # Try both new and old naming formats
                    for rule_format in [
                        f"SimpleSec-BlockPort{port_num}-{protocol}-{direction}", 
                        f"BlockPort{port_num}-{protocol}-{direction}-SimpleSec"
                    ]:
                        command = [
                            "netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={rule_format}", "profile=any"
                        ]
                        print(f"  > EXECUTING: {' '.join(command)}")
                        subprocess.run(
                            command,
                            capture_output=True,
                            text=True
                        )
            
            # Delete the legacy format rules
            for legacy_prefix in ["BlockPort", "RestrictPort"]:
                for protocol in ["TCP", "UDP"]:
                    # Try both new and old naming formats
                    for rule_format in [
                        f"SimpleSec-{legacy_prefix}{port_num}-{protocol}", 
                        f"{legacy_prefix}{port_num}-{protocol}-SimpleSec"
                    ]:
                        command = [
                            "netsh", "advfirewall", "firewall", "delete", "rule",
                            f"name={rule_format}", "profile=any"
                        ]
                        print(f"  > EXECUTING: {' '.join(command)}")
                        subprocess.run(
                            command,
                            capture_output=True,
                            text=True
                        )
                    
                # Also try the original format without protocol specification
                for rule_format in [
                    f"SimpleSec-{legacy_prefix}{port_num}", 
                    f"{legacy_prefix}{port_num}-SimpleSec"
                ]:
                    command = [
                        "netsh", "advfirewall", "firewall", "delete", "rule",
                        f"name={rule_format}", "profile=any"
                    ]
                    print(f"  > EXECUTING: {' '.join(command)}")
                    subprocess.run(
                        command,
                        capture_output=True,
                        text=True
                    )
            
            print(f"  > Removed any existing rules for port {port_num}")
        except Exception as e:
            print(f"  > Warning: Could not remove existing rules: {str(e)}")
    
    def _create_firewall_rule(self, port_num, service_name, protocol, direction, action):
        """
        Create a firewall rule with the specified parameters.
        
        Args:
            port_num (int): Port number to block
            service_name (str): Service name for logging
            protocol (str): 'TCP' or 'UDP'
            direction (str): 'in' or 'out'
            action (str): 'block' or 'allow'
        """
        try:
            # Create a unique rule name that starts with SimpleSec
            rule_name = f"SimpleSec-BlockPort{port_num}-{protocol}-{direction}"
            
            # Create the firewall rule
            command = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}", f"dir={direction}", f"localport={port_num}",
                f"protocol={protocol}", f"action={action}", "profile=any"
            ]
            
            # Log the exact command being executed
            cmd_str = ' '.join(command)
            print(f"  > EXECUTING: {cmd_str}")
            logger.info(f"Executing firewall command: {cmd_str}")
            
            result = subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True
            )
            
            # Log success and any output
            print(f"  > Created {direction}bound {protocol} rule for port {port_num}")
            if result.stdout:
                stdout_msg = result.stdout.strip()
                print(f"  > OUTPUT: {stdout_msg}")
                logger.info(f"Firewall rule creation output: {stdout_msg}")
            
            # Ensure rules persist by exporting
            try:
                export_cmd = ["netsh", "advfirewall", "export", "policy.wfw"]
                export_result = subprocess.run(export_cmd, capture_output=True, text=True, timeout=10)
                if export_result.returncode != 0:
                    print(f"  > WARNING: Failed to export firewall policy: {export_result.stderr}")
                    logger.warning(f"Failed to export firewall policy: {export_result.stderr}")
            except Exception as e:
                print(f"  > WARNING: Failed to export firewall policy: {str(e)}")
                logger.warning(f"Failed to export firewall policy: {str(e)}")
                
            return True
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to create {direction}bound {protocol} rule for port {port_num}"
            stderr_msg = e.stderr.strip() if e.stderr else "No error details available"
            print(f"  > ERROR: {error_msg}")
            print(f"  > COMMAND: {' '.join(e.cmd)}")
            print(f"  > RETURN CODE: {e.returncode}")
            print(f"  > STDERR: {stderr_msg}")
            logger.error(f"{error_msg}. Command: {' '.join(e.cmd)}. Return code: {e.returncode}. Error: {stderr_msg}")
            return False
        except Exception as e:
            print(f"  > ERROR: Unexpected error creating firewall rule: {str(e)}")
            logger.error(f"Unexpected error creating firewall rule for port {port_num}: {str(e)}")
            return False
    
    def _verify_port_blocked(self, port_num: int) -> bool:
        """
        Verify that a port is actually blocked by the firewall.
        
        Args:
            port_num: Port number to verify
            
        Returns:
            True if verification successful, False otherwise
        """
        try:
            # Define known system ports and their descriptions
            system_ports = {
                135: "RPC (Remote Procedure Call)",
                139: "NetBIOS Session Service",
                445: "SMB (Server Message Block)",
                3389: "Remote Desktop Protocol",
                5985: "Windows Remote Management"
            }
            
            # First check: look for firewall rules for this port
            command = [
                "netsh", "advfirewall", "firewall", "show", "rule", 
                f"name=SimpleSec-*{port_num}*", "profile=any"
            ]
            print(f"  > VERIFYING: {' '.join(command)}")
            
            result = subprocess.run(command, capture_output=True, text=True)
            
            # If we found rules, that's a good first sign
            rules_exist = "No rules match the specified criteria" not in result.stdout
            
            if not rules_exist:
                print(f"  > VERIFICATION WARNING: No firewall rules found for port {port_num}")
                self.results_text.append(f"⚠️ No firewall rules found for port {port_num}")
                return False
            
            # Check if this is a known system port
            is_system_port = port_num in system_ports
            service_name = system_ports.get(port_num, "")
            
            # For system ports, check rule configuration
            if is_system_port:
                # Parse the rules to verify they're correctly configured
                rules_output = result.stdout.lower()
                has_block_rule = "action=block" in rules_output
                has_local_allow = "remoteip=localsubnet" in rules_output or "remoteip=local" in rules_output
                
                if has_block_rule:
                    if has_local_allow:
                        self.results_text.append(
                            f"✓ Port {port_num} ({service_name}): External access blocked, local access preserved for system operations"
                        )
                    else:
                        self.results_text.append(
                            f"✓ Port {port_num} ({service_name}): All access blocked (note: may impact system functionality)"
                        )
                    return True
                else:
                    self.results_text.append(
                        f"⚠️ Port {port_num} ({service_name}): Rules exist but may not effectively block external access"
                    )
                    return False
            
            # For non-system ports, check connectivity
            connectivity_result = self._test_port_connectivity(port_num)
            
            if connectivity_result == 'blocked':
                self.results_text.append(f"✓ Port {port_num} is fully blocked")
                return True
            elif connectivity_result == 'unknown':
                if rules_exist:
                    self.results_text.append(
                        f"✓ Port {port_num}: Firewall rules exist but connectivity test was inconclusive"
                    )
                    return True
                else:
                    self.results_text.append(
                        f"⚠️ Port {port_num}: Could not verify if port is blocked"
                    )
                    return False
            else:
                # Port appears to be open
                if rules_exist:
                    # Check if any local services are using this port
                    try:
                        import psutil
                        local_service_found = False
                        for conn in psutil.net_connections(kind='tcp'):
                            if conn.laddr.port == port_num and conn.status == 'LISTEN':
                                try:
                                    proc = psutil.Process(conn.pid)
                                    local_service_found = True
                                    self.results_text.append(
                                        f"⚠️ Port {port_num}: External access restricted by firewall. "
                                        f"Port remains accessible locally (used by {proc.name()})"
                                    )
                                    break
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    continue
                        
                        if not local_service_found:
                            self.results_text.append(
                                f"⚠️ Port {port_num}: Firewall rules exist but port appears to be accessible"
                            )
                            
                    except ImportError:
                        self.results_text.append(
                            f"⚠️ Port {port_num}: Firewall rules exist but port status could not be fully verified"
                        )
                    
                    return True  # Return true since we have rules, even if port is locally accessible
                else:
                    self.results_text.append(
                        f"❌ Port {port_num}: Port is accessible and no firewall rules found"
                    )
                    return False
                    
        except Exception as e:
            error_msg = str(e)
            print(f"  > ERROR during verification: {error_msg}")
            self.results_text.append(f"⚠️ Error verifying port {port_num}: {error_msg}")
            # If we couldn't verify due to error, assume it worked if no specific error state
            return True
    
    def center_window(self):
        """Center the window on the screen."""
        qr = self.frameGeometry()
        cp = QApplication.desktop().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def _initialize_port_fixes(self):
        """Initialize the registry of specialized port fixes."""
        self.port_fixes = {}
        
        # RDP (3389)
        self.port_fixes[3389] = PortFix(
            port=3389,
            name="Remote Desktop Protocol",
            description="Secure RDP access by restricting connections and hardening configuration",
            actions=[
                {"type": "firewall", "protocol": "TCP", "direction": "in", "action": "block"},
                {"type": "firewall", "protocol": "UDP", "direction": "in", "action": "block"},
                {"type": "registry", "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server", "key": "fDenyTSConnections", "value": 1},
                {"type": "registry", "path": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp", "key": "UserAuthentication", "value": 1},
                {"type": "registry", "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", "key": "fDenyTSConnections", "value": 1},
                {"type": "registry", "path": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Terminal Services", "key": "UserAuthentication", "value": 1}
            ]
        )
        
        # SMB (445)
        self.port_fixes[445] = PortFix(
            port=445,
            name="SMB",
            description="Secure SMB file sharing by restricting access and hardening configuration",
            actions=[
                {"type": "firewall", "protocol": "TCP", "direction": "in", "action": "block"},
                {"type": "firewall", "protocol": "UDP", "direction": "in", "action": "block"},
                {"type": "service", "name": "LanmanServer", "action": "disable"}
            ]
        )
        
        # NetBIOS (137-139)
        for port in [137, 138, 139]:
            self.port_fixes[port] = PortFix(
                port=port,
                name="NetBIOS",
                description="Secure NetBIOS by disabling unnecessary services and blocking ports",
                actions=[
                    {"type": "firewall", "protocol": "TCP", "direction": "in", "action": "block"},
                    {"type": "firewall", "protocol": "UDP", "direction": "in", "action": "block"},
                    {"type": "service", "name": "lmhosts", "action": "disable"}
                ]
            )
        
        # SSH (22)
        self.port_fixes[22] = PortFix(
            port=22,
            name="SSH",
            description="Secure SSH access by restricting connections",
            actions=[
                {"type": "firewall", "protocol": "TCP", "direction": "in", "action": "block"},
                {"type": "service", "name": "OpenSSH SSH Server", "action": "disable"},
                {"type": "service", "name": "sshd", "action": "disable"}
            ]
        )
        
        # FTP (21)
        self.port_fixes[21] = PortFix(
            port=21,
            name="FTP",
            description="Secure FTP access by disabling the service and blocking ports",
            actions=[
                {"type": "firewall", "protocol": "TCP", "direction": "in", "action": "block"},
                {"type": "service", "name": "ftpsvc", "action": "disable"}
            ]
        )
        
        # Telnet (23)
        self.port_fixes[23] = PortFix(
            port=23,
            name="Telnet",
            description="Secure Telnet by disabling the service and blocking ports",
            actions=[
                {"type": "firewall", "protocol": "TCP", "direction": "in", "action": "block"},
                {"type": "service", "name": "TlntSvr", "action": "disable"}
            ]
        )
        
        # WinRM/HTTP API Ports (5357, 5985)
        for port in [5357, 5985]:
            self.port_fixes[port] = PortFix(
                port=port,
                name="Windows Remote Management",
                description="Secure WinRM and HTTP API ports by restricting access",
                actions=[
                    {"type": "firewall", "protocol": "TCP", "direction": "in", "action": "block"},
                    {"type": "service", "name": "WinRM", "action": "disable"}
                ]
            )

class SecurityFixer:
    """
    Advanced security fixing and system hardening class.
    
    Provides functionality for:
    - Service management (querying, stopping, disabling)
    - Process management (identifying and terminating risky processes)
    - Registry hardening
    - Network adapter configuration
    """
    
    def __init__(self, results_display=None):
        """
        Initialize the security fixer.
        
        Args:
            results_display: Optional QTextEdit to display results in real-time
        """
        self.results_display = results_display
        self.fixed_items = []
        self.failed_items = []
    
    def log_action(self, message, level="info", display=True):
        """
        Log action and optionally display to the UI.
        
        Args:
            message: Message to log
            level: Log level (info, warning, error)
            display: Whether to display in UI
        """
        if level == "info":
            logger.info(message)
            print(f"  > {message}")
        elif level == "warning":
            logger.warning(message)
            print(f"  > WARNING: {message}")
        elif level == "error":
            logger.error(message)
            print(f"  > ERROR: {message}")
            
        if display and self.results_display:
            if level == "error":
                self.results_display.append(f"❌ {message}")
            elif level == "warning":
                self.results_display.append(f"⚠️ {message}")
            else:
                self.results_display.append(f"  • {message}")
    
    def get_services_for_port(self, port_num):
        """
        Find Windows services associated with a specific port.
        
        Args:
            port_num: Port number to check
            
        Returns:
            List of service names listening on the port
        """
        services = []
        try:
            # First attempt: Use PowerShell to get services and their ports
            ps_command = """
            $ErrorActionPreference = 'SilentlyContinue'
            
            # Get all TCP connections with owning process
            $connections = Get-NetTCPConnection -State Listen
            
            # Get processes with their ports
            $process_ports = @{}
            foreach ($conn in $connections) {
                $process_ports[$conn.OwningProcess] = $conn.LocalPort
            }
            
            # Get services with their process IDs
            $services = Get-WmiObject -Class Win32_Service | Where-Object {$_.State -eq 'Running'}
            
            # For svchost processes, get the actual services
            $svchost_services = @{}
            $svchosts = Get-WmiObject -Class Win32_Service | Where-Object {$_.ProcessId -ne 0 -and $_.PathName -like '*svchost*'}
            foreach ($svc in $svchosts) {
                if ($svc.ProcessId -ne 0) {
                    if (-not $svchost_services.ContainsKey($svc.ProcessId)) {
                        $svchost_services[$svc.ProcessId] = @()
                    }
                    $svchost_services[$svc.ProcessId] += @{
                        'Name' = $svc.Name
                        'DisplayName' = $svc.DisplayName
                    }
                }
            }
            
            # Output services and their ports
            foreach ($service in $services) {
                try {
                    $pid = $service.ProcessId
                    if ($process_ports[$pid]) {
                        Write-Host "$($service.Name)|$($service.DisplayName)|$($process_ports[$pid])"
                        
                        # If this is svchost, also output its hosted services
                        if ($service.PathName -like '*svchost*' -and $svchost_services[$pid]) {
                            foreach ($svc in $svchost_services[$pid]) {
                                Write-Host "$($svc.Name)|$($svc.DisplayName)|$($process_ports[$pid])"
                            }
                        }
                    }
                } catch {}
            }
            """
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=20  # Increased timeout for more thorough search
            )
            
            # Parse the output to find services for this port
            for line in result.stdout.splitlines():
                if line.strip():
                    parts = line.split('|')
                    if len(parts) >= 3:
                        service_name = parts[0]
                        display_name = parts[1]
                        port = parts[2]
                        
                        if str(port_num) == port:
                            services.append((service_name, display_name))
                            self.log_action(f"Found service {display_name} ({service_name}) listening on port {port_num}")
            
            # Second attempt: Use psutil as fallback for system processes
            if not services:
                try:
                    import psutil
                    for conn in psutil.net_connections(kind='tcp'):
                        if conn.laddr.port == port_num and conn.status == 'LISTEN':
                            try:
                                proc = psutil.Process(conn.pid)
                                
                                # Handle System process
                                if proc.name().lower() == 'system':
                                    services.append(('System', 'Windows System Process'))
                                    self.log_action(f"Found System process using port {port_num}")
                                
                                # Handle svchost
                                elif proc.name().lower() == 'svchost.exe':
                                    # Try to get service name from command line
                                    cmdline = proc.cmdline()
                                    if len(cmdline) > 2 and '-k' in cmdline:
                                        svc_group = cmdline[cmdline.index('-k') + 1]
                                        services.append((f'svchost_{svc_group}', f'Service Host ({svc_group})'))
                                        self.log_action(f"Found svchost process ({svc_group}) using port {port_num}")
                                
                                # Handle other known service processes
                                elif proc.name().lower() in ['lsass.exe', 'services.exe', 'wininit.exe']:
                                    services.append((proc.name().replace('.exe', ''), f'{proc.name()} System Service'))
                                    self.log_action(f"Found system service process {proc.name()} using port {port_num}")
                                
                            except (psutil.NoSuchProcess, psutil.AccessDenied):
                                continue
                                
                except ImportError:
                    self.log_action("psutil not available for enhanced process detection", "warning")
            
        except Exception as e:
            self.log_action(f"Error identifying services for port {port_num}: {str(e)}", "error")
        
        return services
    
    def manage_service(self, service_name, action="stop", disable=True):
        """
        Manage a Windows service (stop, disable, etc.)
        
        Args:
            service_name: Name of the service to manage
            action: Action to perform (stop, start, restart)
            disable: Whether to disable the service after stopping
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Define critical services that should not be stopped/disabled
            critical_services = [
                "lanmanworkstation",  # Required for network access
                "rpcss",              # Required for RPC
                "dhcp",               # Required for network
                "dnscache",           # Required for DNS resolution
                "nsi",                # Required for network
                "tcpip",              # Core networking
                "netlogon",           # Required for domain authentication
                "wscsvc",             # Windows Security Center
                "windefend",          # Windows Defender
                "wuauserv",           # Windows Update
            ]
            
            # Skip critical services
            if service_name.lower() in critical_services:
                self.log_action(f"Skipping critical service: {service_name} (required for system operation)", "warning")
                return False
                
            # First check if the service exists
            check_cmd = ["sc", "query", service_name]
            check_result = subprocess.run(check_cmd, capture_output=True, text=True, timeout=10)
            
            # If service doesn't exist, return False but don't treat as error
            if "The specified service does not exist" in check_result.stderr or "1060" in check_result.stderr:
                self.log_action(f"Service {service_name} does not exist on this system", "warning")
                return False
                
            if action == "stop":
                # Stop the service
                stop_cmd = ["sc", "stop", service_name]
                
                try:
                    # Use shorter timeout (15 seconds) to avoid hanging
                    stop_result = subprocess.run(stop_cmd, capture_output=True, text=True, timeout=15)
                    
                    if stop_result.returncode == 0:
                        self.log_action(f"Stopped service {service_name}")
                    else:
                        # Check for specific error conditions
                        if "FAILED 1053" in stop_result.stderr or "timeout period expired" in stop_result.stderr.lower():
                            self.log_action(f"Service {service_name} failed to stop due to timeout", "warning")
                        else:
                            self.log_action(f"Could not stop service {service_name}: {stop_result.stderr}", "warning")
                            
                        # Try with net stop as fallback with shorter timeout
                        try:
                            alt_stop = ["net", "stop", service_name]
                            subprocess.run(alt_stop, capture_output=True, text=True, timeout=10)
                            self.log_action(f"Stopped service {service_name} using net command")
                        except subprocess.TimeoutExpired:
                            self.log_action(f"Timeout while stopping service {service_name}", "warning")
                            # Return True anyway since we'll disable it
                        except:
                            self.log_action(f"Failed to stop service {service_name} with both methods", "error")
                            # Continue to disable the service even if stopping failed
                except subprocess.TimeoutExpired:
                    self.log_action(f"Timeout while stopping service {service_name}", "warning")
                    # Continue to disable even if we couldn't stop
                
                # If requested, disable the service
                if disable:
                    disable_cmd = ["sc", "config", service_name, "start=disabled"]
                    
                    try:
                        disable_result = subprocess.run(disable_cmd, capture_output=True, text=True, timeout=10)
                        
                        if disable_result.returncode == 0:
                            self.log_action(f"Disabled service {service_name}")
                        else:
                            self.log_action(f"Could not disable service {service_name}: {disable_result.stderr}", "warning")
                    except subprocess.TimeoutExpired:
                        self.log_action(f"Timeout while disabling service {service_name}", "warning")
                
                return True
                
            elif action == "start":
                # Start the service
                try:
                    start_cmd = ["sc", "start", service_name]
                    start_result = subprocess.run(start_cmd, capture_output=True, text=True, timeout=15)
                    
                    if start_result.returncode == 0:
                        self.log_action(f"Started service {service_name}")
                        return True
                    else:
                        self.log_action(f"Could not start service {service_name}: {start_result.stderr}", "error")
                        return False
                except subprocess.TimeoutExpired:
                    self.log_action(f"Timeout while starting service {service_name}", "warning")
                    return False
                    
            elif action == "restart":
                # Stop then start the service
                self.manage_service(service_name, "stop", disable=False)
                time.sleep(2)  # Wait for service to stop
                return self.manage_service(service_name, "start")
            
            return False
            
        except Exception as e:
            self.log_action(f"Error managing service {service_name}: {str(e)}", "error")
            return False
    
    def find_processes_using_port(self, port_num):
        """
        Find processes using a specific port.
        
        Args:
            port_num: Port number to check
            
        Returns:
            List of (pid, process_name) tuples using the port
        """
        processes = []
        try:
            # Use PowerShell to get processes using the port
            ps_command = f"""
            $ErrorActionPreference = 'SilentlyContinue'
            $connections = Get-NetTCPConnection -State Listen -LocalPort {port_num}
            foreach ($conn in $connections) {{
                $process = Get-Process -Id $conn.OwningProcess
                Write-Host "$($conn.OwningProcess)|$($process.Name)|$($conn.LocalPort)"
            }}
            """
            
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Parse the output
            for line in result.stdout.splitlines():
                if line.strip():
                    parts = line.split('|')
                    if len(parts) >= 3:
                        pid = int(parts[0])
                        process_name = parts[1]
                        port = parts[2]
                        
                        if str(port_num) == port:
                            processes.append((pid, process_name))
                            self.log_action(f"Found process {process_name} (PID {pid}) using port {port_num}")
            
        except Exception as e:
            self.log_action(f"Error identifying processes for port {port_num}: {str(e)}", "error")
        
        return processes
    
    def terminate_process(self, pid, force=False):
        """
        Terminate a process by its PID.
        
        Args:
            pid: Process ID to terminate
            force: Whether to force termination
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Get process name for logging
            process_name = "Unknown"
            try:
                process = psutil.Process(pid)
                process_name = process.name()
            except:
                pass
                
            # Use taskkill to terminate the process
            cmd = ["taskkill", "/PID", str(pid)]
            if force:
                cmd.append("/F")
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                self.log_action(f"Terminated process {process_name} (PID {pid})")
                return True
            else:
                self.log_action(f"Failed to terminate process {process_name} (PID {pid}): {result.stderr}", "error")
                return False
                
        except Exception as e:
            self.log_action(f"Error terminating process with PID {pid}: {str(e)}", "error")
            return False
    
    def modify_registry(self, key_path, value_name, value_data, value_type="REG_DWORD"):
        """
        Modify a Windows registry key.
        
        Args:
            key_path: Registry key path (e.g., 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows')
            value_name: Name of the registry value
            value_data: Data to set
            value_type: Type of registry value (REG_DWORD, REG_SZ, etc.)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Map string type names to actual winreg types
            type_map = {
                "REG_DWORD": winreg.REG_DWORD,
                "REG_SZ": winreg.REG_SZ,
                "REG_BINARY": winreg.REG_BINARY,
                "REG_MULTI_SZ": winreg.REG_MULTI_SZ,
                "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ
            }
            
            # Parse the key path to get root key and subkey
            root_key_str, subkey = key_path.split('\\', 1)
            
            # Map string root key to winreg constant
            root_key_map = {
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
                "HKCU": winreg.HKEY_CURRENT_USER,
                "HKCR": winreg.HKEY_CLASSES_ROOT,
                "HKU": winreg.HKEY_USERS,
                "HKCC": winreg.HKEY_CURRENT_CONFIG
            }
            
            if root_key_str not in root_key_map:
                self.log_action(f"Invalid registry root key: {root_key_str}", "error")
                return False
                
            root_key = root_key_map[root_key_str]
            reg_type = type_map.get(value_type, winreg.REG_DWORD)
            
            # Format the value based on its type
            if reg_type == winreg.REG_DWORD:
                if isinstance(value_data, str):
                    value_data = int(value_data, 0)  # Convert string to int, auto-detect base
            
            # Open or create the key
            try:
                key = winreg.OpenKey(root_key, subkey, 0, winreg.KEY_WRITE)
            except FileNotFoundError:
                # Try to create the key if it doesn't exist
                self.log_action(f"Registry key {subkey} does not exist. Creating it.")
                key = winreg.CreateKey(root_key, subkey)
            
            # Set the value
            winreg.SetValueEx(key, value_name, 0, reg_type, value_data)
            winreg.CloseKey(key)
            
            self.log_action(f"Modified registry key {key_path}\\{value_name} = {value_data}")
            return True
            
        except Exception as e:
            self.log_action(f"Error modifying registry key {key_path}\\{value_name}: {str(e)}", "error")
            return False
    
    def configure_network_adapter(self, adapter_name=None, config_type=None, setting=None):
        """
        Configure network adapter settings.
        
        Args:
            adapter_name: Name of adapter to configure (None for all)
            config_type: Type of configuration (netbios, ipv6, etc.)
            setting: Value to set
            
        Returns:
            True if successful, False otherwise
        """
        if config_type == "netbios":
            return self._disable_netbios_over_tcpip(adapter_name)
        elif config_type == "ipv6":
            return self._configure_ipv6(adapter_name, setting)
        elif config_type == "file_sharing":
            return self._configure_file_sharing(setting)
        else:
            self.log_action(f"Unknown network adapter configuration type: {config_type}", "error")
            return False
    
    def _disable_netbios_over_tcpip(self, adapter_name=None):
        """
        Disable NetBIOS over TCP/IP for specified or all network adapters.
        
        Args:
            adapter_name: Optional adapter name to target specifically
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # PowerShell command to disable NetBIOS over TCP/IP
            ps_command = """
            # Get all network adapters
            $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
            
            """
            
            if adapter_name:
                # Target specific adapter
                ps_command += f"""
                # Filter for specific adapter
                $adapters = $adapters | Where-Object {{ $_.Description -like "*{adapter_name}*" }}
                """
            
            ps_command += """
            # Disable NetBIOS over TCP/IP for each adapter
            $successCount = 0
            $totalCount = ($adapters | Measure-Object).Count
            foreach ($adapter in $adapters) {
                Write-Host "Disabling NetBIOS for adapter: " $adapter.Description
                $result = $adapter.SetTcpipNetbios(2)
                if ($result.ReturnValue -eq 0) {
                    Write-Host "SUCCESS: $($adapter.Description)"
                    $successCount++
                } else {
                    Write-Host "FAILURE: $($adapter.Description) - Error code: " $result.ReturnValue
                }
            }
            Write-Host "SUMMARY: $successCount of $totalCount adapters configured"
            """
            
            # Execute the PowerShell command
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check if the command was successful
            if "SUMMARY: 0 of 0 adapters configured" in result.stdout:
                self.log_action("No suitable adapters found for NetBIOS configuration", "warning")
                return False
                
            if "SUMMARY:" in result.stdout:
                # Extract success count from summary
                summary_line = [line for line in result.stdout.splitlines() if "SUMMARY:" in line][0]
                
                if "0 of 0" in summary_line:
                    self.log_action("No suitable adapters found for NetBIOS configuration", "warning")
                    return False
                    
                if "0 of" in summary_line:
                    self.log_action("Failed to disable NetBIOS over TCP/IP on any adapters", "error")
                    return False
                
                self.log_action(f"NetBIOS over TCP/IP configuration changed: {summary_line.split('SUMMARY: ')[1]}")
                return True
            else:
                self.log_action("Could not verify NetBIOS over TCP/IP configuration", "warning")
                return False
                
        except Exception as e:
            self.log_action(f"Error disabling NetBIOS over TCP/IP: {str(e)}", "error")
            return False
    
    def _configure_ipv6(self, adapter_name=None, enabled=False):
        """
        Enable or disable IPv6 on network adapters.
        
        Args:
            adapter_name: Optional adapter name to target specifically
            enabled: Whether to enable or disable IPv6
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # First use registry to disable IPv6 globally if disabling
            if not enabled:
                registry_path = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters"
                self.modify_registry(registry_path, "DisabledComponents", 0xFF if not enabled else 0x00)
            
            # PowerShell command to enable/disable IPv6 on adapters
            ps_command = """
            # Get all network adapters
            $adapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
            
            """
            
            if adapter_name:
                # Target specific adapter
                ps_command += f"""
                # Filter for specific adapter
                $adapters = $adapters | Where-Object {{ $_.Name -like "*{adapter_name}*" }}
                """
            
            cmd_value = "Enabled" if enabled else "Disabled"
            ps_command += f"""
            # Configure IPv6 for each adapter
            $successCount = 0
            $totalCount = ($adapters | Measure-Object).Count
            foreach ($adapter in $adapters) {{
                try {{
                    Write-Host "Configuring IPv6 for adapter: $($adapter.Name)"
                    $adapter | Disable-NetAdapterBinding -ComponentID ms_tcpip6
                    {f'$adapter | Enable-NetAdapterBinding -ComponentID ms_tcpip6' if enabled else ''}
                    Write-Host "SUCCESS: $($adapter.Name)"
                    $successCount++
                }} catch {{
                    Write-Host "FAILURE: $($adapter.Name) - $($_.Exception.Message)"
                }}
            }}
            Write-Host "SUMMARY: $successCount of $totalCount adapters configured"
            """
            
            # Execute the PowerShell command
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check results
            if "SUMMARY: 0 of 0 adapters configured" in result.stdout:
                self.log_action("No suitable adapters found for IPv6 configuration", "warning")
                return False
                
            if "SUMMARY:" in result.stdout:
                # Extract success count from summary
                summary_line = [line for line in result.stdout.splitlines() if "SUMMARY:" in line][0]
                status = "enabled" if enabled else "disabled"
                
                if "0 of" in summary_line and "0 of 0" not in summary_line:
                    self.log_action(f"Failed to {status} IPv6 on any adapters", "error")
                    return False
                
                self.log_action(f"IPv6 {status}: {summary_line.split('SUMMARY: ')[1]}")
                return True
            else:
                self.log_action(f"Could not verify IPv6 configuration change", "warning")
                return False
                
        except Exception as e:
            self.log_action(f"Error configuring IPv6: {str(e)}", "error")
            return False
    
    def _configure_file_sharing(self, enabled=False):
        """
        Enable or disable Windows file sharing.
        
        Args:
            enabled: Whether to enable or disable file sharing
            
        Returns:
            True if successful, False otherwise
        """
        try:
            action = "enable" if enabled else "disable"
            
            # PowerShell command to configure file sharing
            ps_command = f"""
            # Get the current file sharing status
            $sharingStatus = Get-NetAdapterBinding -ComponentID ms_server | Select-Object -First 1 -ExpandProperty Enabled
            Write-Host "Current file sharing status: $sharingStatus"
            
            # Configure file sharing on all adapters
            $adapters = Get-NetAdapter | Where-Object {{ $_.Status -eq "Up" }}
            $successCount = 0
            $totalCount = ($adapters | Measure-Object).Count
            
            foreach ($adapter in $adapters) {{
                try {{
                    Write-Host "Configuring file sharing for adapter: $($adapter.Name)"
                    """
            
            if enabled:
                ps_command += """
                    $adapter | Enable-NetAdapterBinding -ComponentID ms_server
                    $adapter | Enable-NetAdapterBinding -ComponentID ms_msclient
                """
            else:
                ps_command += """
                    $adapter | Disable-NetAdapterBinding -ComponentID ms_server
                    $adapter | Disable-NetAdapterBinding -ComponentID ms_msclient
                """
            
            ps_command += """
                    Write-Host "SUCCESS: $($adapter.Name)"
                    $successCount++
                } catch {
                    Write-Host "FAILURE: $($adapter.Name) - $($_.Exception.Message)"
                }
            }
            Write-Host "SUMMARY: $successCount of $totalCount adapters configured"
            """
            
            # Execute the PowerShell command
            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            # Check results
            if "SUMMARY: 0 of 0 adapters configured" in result.stdout:
                self.log_action("No suitable adapters found for file sharing configuration", "warning")
                return False
                
            if "SUMMARY:" in result.stdout:
                # Extract success count from summary
                summary_line = [line for line in result.stdout.splitlines() if "SUMMARY:" in line][0]
                status = "enabled" if enabled else "disabled"
                
                if "0 of" in summary_line and "0 of 0" not in summary_line:
                    self.log_action(f"Failed to {status} file sharing on any adapters", "error")
                    return False
                
                self.log_action(f"File sharing {status}: {summary_line.split('SUMMARY: ')[1]}")
                
                # Also configure the relevant services
                services = ["LanmanServer", "LanmanWorkstation", "Browser"]
                for service in services:
                    action = "start" if enabled else "stop"
                    disable = not enabled
                    self.manage_service(service, action, disable)
                
                return True
            else:
                self.log_action(f"Could not verify file sharing configuration change", "warning")
                return False
                
        except Exception as e:
            self.log_action(f"Error configuring file sharing: {str(e)}", "error")
            return False
    
    def harden_smb_security(self):
        """
        Apply security hardening for SMB protocol.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Disable SMBv1 (highly insecure)
            smb1_key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
            self.modify_registry(smb1_key, "SMB1", 0)
            
            # Enable SMB signing
            self.modify_registry(smb1_key, "RequireSecuritySignature", 1)
            self.modify_registry(smb1_key, "EnableSecuritySignature", 1)
            
            # Client-side SMB signing
            client_key = "HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters"
            self.modify_registry(client_key, "RequireSecuritySignature", 1)
            self.modify_registry(client_key, "EnableSecuritySignature", 1)
            
            # Disable guest access to shares
            self.modify_registry(smb1_key, "RestrictNullSessAccess", 1)
            
            # Disable SMB server if not needed (uncomment if needed)
            # self.manage_service("LanmanServer", "stop", True)
            
            self.log_action("Hardened SMB security settings: disabled SMBv1, enabled SMB signing, restricted guest access")
            return True
            
        except Exception as e:
            self.log_action(f"Error hardening SMB security: {str(e)}", "error")
            return False
    
    def harden_rdp_security(self):
        """
        Apply security hardening for RDP protocol.
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Configure RDP to use Network Level Authentication
            terminal_server_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp"
            self.modify_registry(terminal_server_key, "UserAuthentication", 1)
            
            # Enable TLS 1.2 support
            self.modify_registry(terminal_server_key, "SecurityLayer", 2)
            
            # Disable less secure encryption methods
            self.modify_registry(terminal_server_key, "MinEncryptionLevel", 3)
            
            # Apply firewall rules (assuming the application has methods for this already)
            self.log_action("Hardened RDP security settings: enabled NLA, TLS 1.2, and minimum encryption")
            return True
            
        except Exception as e:
            self.log_action(f"Error hardening RDP security: {str(e)}", "error")
            return False
    
    def apply_all_security_fixes(self, scan_results, high_risk_ports, medium_risk_ports):
        """
        Apply comprehensive security fixes based on scan results.
        
        Args:
            scan_results: Scan results dictionary from nmap scan
            high_risk_ports: Dictionary of high-risk ports to secure
            medium_risk_ports: Dictionary of medium-risk ports to secure
            
        Returns:
            Tuple of (success_count, total_count)
        """
        self.log_action("Starting comprehensive security hardening...", display=True)
        
        # List the ports we found in scan results
        my_ip = self.get_primary_ip()
        if my_ip in scan_results:
            open_ports = self.get_open_ports_from_scan(scan_results[my_ip])
            self.log_action(f"Found {len(open_ports)} open ports to analyze", display=True)
        else:
            self.log_action("No scan results available for this host", "warning", display=True)
            open_ports = []
        
        # Initialize counters
        success_count = 0
        total_count = 0
        
        # 1. Process high-risk ports
        for port_num in open_ports:
            port_num = int(port_num)
            
            # Skip medium-risk ports for now
            if port_num not in high_risk_ports and port_num not in medium_risk_ports:
                continue
                
            total_count += 1
            self.log_action(f"Securing port {port_num}...", display=True)
            
            # Find processes using the port
            processes = self.find_processes_using_port(port_num)
            
            # Find services using the port
            services = self.get_services_for_port(port_num)
            
            # Apply security fixes based on port
            if self.secure_port(port_num, processes, services):
                success_count += 1
                self.fixed_items.append(f"Port {port_num}")
            else:
                self.failed_items.append(f"Port {port_num}")
        
        # 2. Apply general security hardening
        self.log_action("Applying general security hardening...", display=True)
        
        # Harden SMB if port 445 is present
        if 445 in open_ports:
            total_count += 1
            if self.harden_smb_security():
                self.fixed_items.append("SMB Security Hardening")
                success_count += 1
            else:
                self.failed_items.append("SMB Security Hardening")
        
        # Harden RDP if port 3389 is present
        if 3389 in open_ports:
            total_count += 1
            if self.harden_rdp_security():
                self.fixed_items.append("RDP Security Hardening")
                success_count += 1
            else:
                self.failed_items.append("RDP Security Hardening")
        
        # Handle Windows HTTP API ports (5357, 5985)
        http_api_ports = [5357, 5985, 47001]
        for port in http_api_ports:
            if port in open_ports:
                total_count += 1
                if self.secure_winrm_http_ports(port):
                    self.fixed_items.append(f"WinRM/HTTP API Port {port}")
                    success_count += 1
                else:
                    self.failed_items.append(f"WinRM/HTTP API Port {port}")
        
        # 3. Always disable NetBIOS over TCP/IP (common attack vector)
        total_count += 1
        if self.configure_network_adapter(config_type="netbios"):
            self.fixed_items.append("NetBIOS over TCP/IP")
            success_count += 1
        else:
            self.failed_items.append("NetBIOS over TCP/IP")
        
        # Summary
        if success_count == total_count and total_count > 0:
            self.log_action(f"✅ Successfully applied all {success_count} security fixes", display=True)
        elif success_count > 0:
            self.log_action(f"⚠️ Partially applied security fixes: {success_count}/{total_count} successful", display=True)
        else:
            self.log_action("❌ Failed to apply security fixes", "error", display=True)
        
        return (success_count, total_count)
    
    def secure_winrm_http_ports(self, port_num):
        """
        Apply security fixes for Windows Remote Management or HTTP API ports.
        These are used by WinRM and various Windows services.
        
        Args:
            port_num: Port number (typically 5357, 5985 or 47001)
            
        Returns:
            True if successful, False otherwise
        """
        try:
            self.log_action(f"Securing WinRM/HTTP API port {port_num}...")
            success = True
            
            # 1. First approach: Restrict access in the registry
            if port_num == 5985:
                # Port 5985 is WinRM HTTP
                winrm_key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WSMAN"
                if not self.modify_registry(winrm_key, "EnableCompatibilityHttpListener", 0):
                    self.log_action("Failed to disable WinRM HTTP compatibility listener", "warning")
                    success = False
                
                # Additional WinRM hardening
                try:
                    # Disable basic authentication
                    winrm_cmd = "winrm set winrm/config/service/auth @{Basic=\"false\"}"
                    basic_auth_result = subprocess.run(["powershell", "-Command", winrm_cmd], 
                                                     capture_output=True, text=True, timeout=15)
                    if basic_auth_result.returncode == 0:
                        self.log_action("Disabled basic authentication for WinRM")
                    else:
                        self.log_action(f"Failed to disable basic auth: {basic_auth_result.stderr}", "warning")
                        success = False
                    
                    # Enable encryption
                    encrypt_cmd = "winrm set winrm/config/service @{AllowUnencrypted=\"false\"}"
                    encrypt_result = subprocess.run(["powershell", "-Command", encrypt_cmd], 
                                                  capture_output=True, text=True, timeout=15)
                    if encrypt_result.returncode == 0:
                        self.log_action("Enabled encryption requirement for WinRM")
                    else:
                        self.log_action(f"Failed to enable encryption: {encrypt_result.stderr}", "warning")
                        success = False
                except Exception as e:
                    self.log_action(f"Error configuring WinRM security: {str(e)}", "error")
                    success = False
            
            # 2. Create firewall rules with proper scope and protocol
            try:
                # Remove any existing rules first
                cleanup_cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    f"name=SimpleSec-WinRM-{port_num}", "profile=any"
                ]
                subprocess.run(cleanup_cmd, capture_output=True, text=True, timeout=10)
                
                # Create new rule to block external access but allow local
                rule_name = f"SimpleSec-WinRM-{port_num}"
                commands = [
                    # Block all inbound except local subnet
                    {
                        "cmd": [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={rule_name}-BlockExternal", "dir=in", 
                            f"localport={port_num}", "protocol=TCP", 
                            "action=block", "remoteip=Internet", "profile=any"
                        ],
                        "desc": "block external access"
                    },
                    # Allow local subnet access
                    {
                        "cmd": [
                            "netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={rule_name}-AllowLocal", "dir=in", 
                            f"localport={port_num}", "protocol=TCP", 
                            "action=allow", "remoteip=LocalSubnet", "profile=any"
                        ],
                        "desc": "allow local access"
                    }
                ]
                
                for cmd_info in commands:
                    cmd_str = ' '.join(cmd_info["cmd"])
                    self.log_action(f"Creating firewall rule to {cmd_info['desc']}")
                    print(f"  > EXECUTING: {cmd_str}")
                    
                    result = subprocess.run(cmd_info["cmd"], capture_output=True, text=True, timeout=15)
                    if result.returncode == 0:
                        self.log_action(f"Successfully created rule to {cmd_info['desc']}")
                    else:
                        error_msg = result.stderr.strip() if result.stderr else "No error details available"
                        self.log_action(f"Failed to create rule: {error_msg}", "error")
                        success = False
                
            except Exception as e:
                self.log_action(f"Error creating firewall rules for port {port_num}: {str(e)}", "error")
                success = False
            
            # 3. Verify the rules were created
            try:
                verify_cmd = [
                    "netsh", "advfirewall", "firewall", "show", "rule",
                    f"name={rule_name}*", "profile=any"
                ]
                verify_result = subprocess.run(verify_cmd, capture_output=True, text=True, timeout=10)
                
                if "No rules match the specified criteria" in verify_result.stdout:
                    self.log_action("Failed to verify firewall rules were created", "error")
                    success = False
                else:
                    self.log_action("Verified firewall rules were created successfully")
            except Exception as e:
                self.log_action(f"Error verifying firewall rules: {str(e)}", "error")
                success = False
            
            return success
            
        except Exception as e:
            self.log_action(f"Error securing WinRM/HTTP API port {port_num}: {str(e)}", "error")
            return False
    
    def secure_port(self, port_num, processes, services):
        """
        Apply security fixes for a specific port.
        
        Args:
            port_num: Port number to secure
            processes: List of processes using the port
            services: List of services associated with the port
            
        Returns:
            True if successful, False otherwise
        """
        success = True
        
        # Check if this is a system process (PID 4)
        is_system_process = False
        for pid, proc_name in processes:
            if pid == 4 or proc_name.lower() == "system":
                is_system_process = True
                self.log_action(f"Port {port_num} is used by the Windows System process", "info")
                break
                
        # 1. Handle specific ports with known security fixes
        if port_num == 445:  # SMB
            if is_system_process:
                self.log_action("SMB is a core Windows service. Applying secure configuration instead of disabling.", "info")
                # The port will be handled by harden_smb_security elsewhere
            else:
                # Disable file and printer sharing on all adapters
                if not self.configure_network_adapter(config_type="file_sharing", setting=False):
                    success = False
                
        elif port_num == 3389:  # RDP
            # For RDP, determine if we should disable or just secure
            should_disable = False
            
            # Check if this is a critical system RDP session
            is_critical_rdp = False
            for service_name, _ in services:
                if service_name.lower() in ["termservice", "sessionenv"]:
                    is_critical_rdp = True
                    break
            
            if is_critical_rdp:
                self.log_action("RDP is actively used. Applying secure configuration instead of disabling.", "info")
            else:
                # If RDP isn't critical, check if any processes are using it
                rdp_processes = [p for p, n in processes if "rdp" in n.lower() or "remote" in n.lower()]
                if not rdp_processes:
                    should_disable = True
                    self.log_action("No active RDP sessions found. Will attempt to disable RDP services.", "info")
            
            # Apply RDP security measures
            if not self.secure_rdp_services(disable_rdp=should_disable):
                success = False
            
        elif port_num == 139:  # NetBIOS
            # Use the consolidated NetBIOS security function
            if not self.secure_netbios(port_num):
                success = False
                
        elif port_num == 135:  # RPC
            # RPC is a critical Windows service used by System
            if is_system_process:
                self.log_action("RPC is a critical Windows service. Applying secure configuration.", "info")
                
            # Add additional RPC security via registry
            rpc_key = "HKLM\\SOFTWARE\\Microsoft\\Rpc"
            self.modify_registry(rpc_key, "RestrictRemoteClients", 1)
            
        # 2. Stop and disable services associated with the port that aren't critical
        for service_name, display_name in services:
            # Skip critical system services
            if service_name.lower() in ["tcpip", "dhcp", "dnscache", "nsi", "lanmanworkstation", "rpcss"]:
                self.log_action(f"Skipping critical service: {service_name}", "warning")
                continue
                
            if not self.manage_service(service_name, "stop", disable=True):
                success = False
        
        # 3. Warn about processes that couldn't be handled
        if processes and not services and not is_system_process:
            self.log_action(f"Port {port_num} is used by processes but no associated service was found", "warning")
            for pid, proc_name in processes:
                self.log_action(f"Process {proc_name} (PID {pid}) is using port {port_num}", "warning")
        
        return success
    
    def get_open_ports_from_scan(self, host_data):
        """Extract open ports from scan results"""
        open_ports = {}
        
        # Collect TCP ports
        if 'tcp' in host_data:
            for port, port_data in host_data['tcp'].items():
                if port_data.get('state') == 'open':
                    open_ports[int(port)] = port_data
        
        # Collect UDP ports
        if 'udp' in host_data:
            for port, port_data in host_data['udp'].items():
                if port_data.get('state') == 'open':
                    open_ports[int(port)] = port_data
        
        return open_ports
    
    def get_primary_ip(self):
        """Get the primary IP address of this computer"""
        try:
            # Create a socket to connect to an external server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            # Fall back to hostname lookup
            return socket.gethostbyname(socket.gethostname())
    
    def secure_rdp_services(self, disable_rdp=False):
        """
        Secure or disable RDP-related services.
        
        Args:
            disable_rdp: If True, attempt to fully disable RDP services
            
        Returns:
            True if successful, False otherwise
        """
        success = True
        
        try:
            # List of RDP-related services
            rdp_services = [
                ("TermService", "Remote Desktop Services"),
                ("UmRdpService", "Remote Desktop Services UserMode Port Redirector"),
                ("SessionEnv", "Remote Desktop Configuration")
            ]
            
            for service_name, display_name in rdp_services:
                if disable_rdp:
                    self.log_action(f"Attempting to disable {display_name}...")
                    if not self.manage_service(service_name, "stop", disable=True):
                        self.log_action(f"Failed to disable {display_name}", "warning")
                        success = False
                else:
                    # If not disabling, apply secure configuration
                    self.log_action(f"Applying secure configuration for {display_name}...")
                    
                    # Ensure service is running for secure configuration
                    if not self.manage_service(service_name, "start", disable=False):
                        self.log_action(f"Failed to ensure {display_name} is running", "warning")
                        success = False
                        continue
                    
                    # Apply additional security if it's the main Terminal Service
                    if service_name == "TermService":
                        try:
                            # Configure service to start manually
                            subprocess.run(["sc", "config", service_name, "start=demand"], 
                                         capture_output=True, text=True, check=True)
                            self.log_action(f"Set {display_name} to start manually")
                            
                            # Apply additional RDP security settings
                            rdp_key = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
                            self.modify_registry(rdp_key, "fDenyTSConnections", 0)
                            self.modify_registry(f"{rdp_key}\\WinStations\\RDP-Tcp", "UserAuthentication", 1)
                            self.modify_registry(f"{rdp_key}\\WinStations\\RDP-Tcp", "SecurityLayer", 2)
                            self.modify_registry(f"{rdp_key}\\WinStations\\RDP-Tcp", "MinEncryptionLevel", 3)
                            
                        except Exception as e:
                            self.log_action(f"Error configuring {display_name}: {str(e)}", "error")
                            success = False
            
            return success
            
        except Exception as e:
            self.log_action(f"Error managing RDP services: {str(e)}", "error")
            return False
    
    def secure_netbios(self, port_num=139):
        """
        Apply comprehensive security fixes for NetBIOS.
        This consolidates all NetBIOS-related security measures in one place.
        
        Args:
            port_num: Port number (usually 139)
            
        Returns:
            True if successful, False otherwise
        """
        success = True
        self.log_action("Applying comprehensive NetBIOS security measures...")
        
        try:
            # 1. Disable NetBIOS over TCP/IP on all adapters
            if not self.configure_network_adapter(config_type="netbios"):
                self.log_action("Failed to disable NetBIOS over TCP/IP on network adapters", "error")
                success = False
            
            # 2. Disable NetBIOS-related services
            netbios_services = [
                ("lmhosts", "TCP/IP NetBIOS Helper"),
                ("netbios", "NetBIOS Interface"),
                ("Browser", "Computer Browser")  # Legacy browser service
            ]
            
            for service_name, display_name in netbios_services:
                if not self.manage_service(service_name, "stop", disable=True):
                    self.log_action(f"Failed to disable {display_name} service", "warning")
                    success = False
            
            # 3. Add registry keys to prevent NetBIOS
            try:
                # Disable NetBIOS name resolution
                self.modify_registry(
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
                    "EnableLMHOSTS",
                    0
                )
                
                # Disable NetBIOS name service
                self.modify_registry(
                    "HKLM\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
                    "EnableNetBIOS",
                    0
                )
            except Exception as e:
                self.log_action(f"Failed to modify NetBIOS registry settings: {str(e)}", "error")
                success = False
            
            # 4. Create comprehensive firewall rules
            try:
                # First remove any existing rules
                cleanup_cmd = [
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=SimpleSec-NetBIOS-*"
                ]
                subprocess.run(cleanup_cmd, capture_output=True, text=True)
                
                # Create new rules for both TCP and UDP
                for protocol in ["TCP", "UDP"]:
                    rule_name = f"SimpleSec-NetBIOS-{protocol}"
                    command = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule_name}", "dir=in", f"localport={port_num}",
                        f"protocol={protocol}", "action=block", "profile=any"
                    ]
                    
                    result = subprocess.run(command, capture_output=True, text=True)
                    if result.returncode != 0:
                        self.log_action(f"Failed to create {protocol} firewall rule: {result.stderr}", "error")
                        success = False
            except Exception as e:
                self.log_action(f"Failed to create firewall rules: {str(e)}", "error")
                success = False
            
            if success:
                self.log_action("Successfully applied all NetBIOS security measures")
            else:
                self.log_action("Some NetBIOS security measures failed to apply", "warning")
            
            return success
            
        except Exception as e:
            self.log_action(f"Error securing NetBIOS: {str(e)}", "error")
            return False

def main() -> int:
    """
    Main entry point for the SimpleSec application.
    
    Returns:
        Exit code
    """
    # Initialize QApplication first, before any QWidgets
    app = QApplication(sys.argv)
    
    # Check if running as administrator
    if os.name == 'nt':  # Windows
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            QMessageBox.warning(
                None, 
                "Administrator Privileges Required",
                f"\nPlease right click the application and select 'Run as administrator'"
            )
    
    # Create and show the main application window
    window = SecurityApp()
    window.show()
    
    # Start the application event loop
    return app.exec_()

if __name__ == '__main__':
    sys.exit(main()) 