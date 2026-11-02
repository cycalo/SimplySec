import subprocess
import sys
import re

def test_rule_naming():
    """Test if SimplySec firewall rule naming is working correctly."""
    print("Testing SimplySec Firewall Rule Naming")
    print("======================================")
    
    # Create a test rule with the SimpleSec prefix
    test_port = 12345
    rule_name = f"SimpleSec-TestRule{test_port}"
    
    # First, remove any existing test rules
    try:
        print(f"\nRemoving any existing test rules...")
        cleanup_cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}", "profile=any"
        ]
        subprocess.run(cleanup_cmd, capture_output=True, text=True)
    except Exception as e:
        print(f"Error during cleanup: {str(e)}")
    
    # Create a test rule
    try:
        print(f"\nCreating test firewall rule: {rule_name}")
        create_cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", f"localport={test_port}",
            "protocol=TCP", "action=block", "profile=any"
        ]
        result = subprocess.run(create_cmd, capture_output=True, text=True, check=True)
        
        if "Ok." in result.stdout:
            print(f"✓ Successfully created test rule: {rule_name}")
        else:
            print(f"✗ Failed to create test rule. Output: {result.stdout}")
            return False
    except Exception as e:
        print(f"✗ Error creating test rule: {str(e)}")
        return False
    
    # Verify the rule exists and starts with SimpleSec
    try:
        print(f"\nVerifying the rule exists with SimpleSec prefix...")
        verify_cmd = [
            "netsh", "advfirewall", "firewall", "show", "rule",
            f"name=SimpleSec-*", "profile=any"
        ]
        result = subprocess.run(verify_cmd, capture_output=True, text=True, check=True)
        
        # Extract rule names from the output
        rule_names = re.findall(r"Rule Name:\s+(.+?)(?:\r?\n)", result.stdout)
        
        found_test_rule = False
        all_start_with_simplysec = True
        
        print("\nFound rules starting with SimpleSec:")
        for name in rule_names:
            name = name.strip()
            print(f"  - {name}")
            
            if name == rule_name:
                found_test_rule = True
            
            if not name.startswith("SimpleSec-"):
                all_start_with_simplysec = False
        
        if found_test_rule:
            print(f"\n✓ Test rule '{rule_name}' was found")
        else:
            print(f"\n✗ Test rule '{rule_name}' was not found")
            return False
        
        if all_start_with_simplysec:
            print(f"✓ All rules start with 'SimpleSec-' prefix")
        else:
            print(f"✗ Some rules don't start with 'SimpleSec-' prefix")
            return False
        
        return True
    except Exception as e:
        print(f"✗ Error verifying rules: {str(e)}")
        return False
    finally:
        # Clean up - remove the test rule
        try:
            print(f"\nCleaning up test rule...")
            cleanup_cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}", "profile=any"
            ]
            subprocess.run(cleanup_cmd, capture_output=True, text=True)
            print(f"✓ Test rule cleaned up")
        except Exception as e:
            print(f"Error during cleanup: {str(e)}")

if __name__ == "__main__":
    # Check if running as administrator
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("This test must be run as administrator")
            print("Please use run_as_admin.bat or launch with administrator privileges")
            sys.exit(1)
    except Exception:
        pass
    
    # Run the test
    result = test_rule_naming()
    
    if result:
        print("\n✅ TEST PASSED: Firewall rule naming is working correctly")
    else:
        print("\n❌ TEST FAILED: Firewall rule naming is not working correctly")
    
    input("\nPress Enter to exit...") 