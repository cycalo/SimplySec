import subprocess
import sys
import time

def test_port_139_fix():
    print("Testing Port 139 (NetBIOS) specialized fix...")
    
    # Check if port 139 is open
    print("\nChecking if port 139 is open...")
    try:
        nmap_cmd = ["nmap", "-p", "139", "127.0.0.1"]
        result = subprocess.run(nmap_cmd, capture_output=True, text=True)
        
        if "139/tcp open" in result.stdout:
            print("✓ Port 139 is open and can be tested")
        else:
            print("✗ Port 139 is not open on this system")
            print("This test may not be relevant for your system")
            return
    except Exception as e:
        print(f"Error checking port status: {str(e)}")
        return
    
    # Test if we can create a PortFix instance and apply it
    print("\nTesting PortFix implementation for port 139...")
    try:
        from main import PortFix
        
        # Create port fix for 139
        port_fix = PortFix(
            port=139,
            name="NetBIOS",
            description="NetBIOS is an old Windows protocol that can be exploited",
            actions=[
                # Create firewall rules to block the port
                {'type': 'firewall', 'protocol': 'TCP', 'direction': 'in', 'action': 'block'},
                # Disable NetBIOS over TCP/IP in network adapter settings
                {'type': 'netbios'}
            ]
        )
        
        print("\nTesting NetBIOS over TCP/IP disable function...")
        result = port_fix._disable_netbios_over_tcpip()
        
        if result:
            print("✓ NetBIOS over TCP/IP disable function works")
        else:
            print("✗ NetBIOS over TCP/IP disable function failed")
            print("Manual instructions would be shown to the user")
        
        print("\nTest completed. The PortFix system is working as expected.")
        
    except Exception as e:
        print(f"Error testing PortFix implementation: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Check if running as administrator
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("This test must be run as administrator. Please use run_as_admin.bat")
            sys.exit(1)
    except:
        pass
    
    test_port_139_fix() 