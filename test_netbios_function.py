import subprocess
import sys

def disable_netbios_over_tcpip():
    """
    Disable NetBIOS over TCP/IP for all network adapters using PowerShell.
    This is needed for completely blocking port 139.
    
    Returns:
        bool: True if successful, False otherwise
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
        
        # Print the output for diagnostic purposes
        print("\nPowerShell Output:")
        print(result.stdout)
        
        if result.stderr:
            print("\nPowerShell Errors:")
            print(result.stderr)
        
        # Check if the command was successful
        if "Successfully disabled NetBIOS over TCP/IP" in result.stdout:
            print("\n✓ NetBIOS over TCP/IP disabled for network adapters")
            return True
        else:
            print("\n⚠ Could not verify NetBIOS over TCP/IP was disabled")
            return False
            
    except Exception as e:
        print(f"\n❌ Error disabling NetBIOS over TCP/IP: {str(e)}")
        return False

if __name__ == "__main__":
    # Check if running as administrator
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("This test must be run as administrator.")
            sys.exit(1)
    except:
        pass
    
    print("Testing NetBIOS over TCP/IP disable function...")
    result = disable_netbios_over_tcpip()
    
    if result:
        print("\nTest passed: NetBIOS over TCP/IP disable function works correctly")
    else:
        print("\nTest failed: NetBIOS over TCP/IP disable function did not work as expected")
        
    input("\nPress Enter to exit...") 