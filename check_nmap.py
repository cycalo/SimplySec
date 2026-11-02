import subprocess
import sys
import os

def check_nmap():
    try:
        # Try to run nmap --version
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Nmap is installed and ready to use.")
            print(result.stdout.split("\n")[0])  # Print version info
            return True
        else:
            print("✗ Nmap command failed.")
            return False
    except FileNotFoundError:
        print("✗ Nmap is not installed or not in your PATH.")
        return False

def main():
    print("Checking for Nmap installation...")
    if not check_nmap():
        print("\nTo use SimpleSec, you need to install Nmap:")
        print("1. Download Nmap from https://nmap.org/download.html")
        print("2. Install with default options (this will add Nmap to your PATH)")
        print("3. Restart your computer after installation")
        print("\nAfter installing Nmap, run SimpleSec again.")
        
        if os.name == 'nt':  # Windows
            input("\nPress Enter to open the Nmap download page...")
            os.system("start https://nmap.org/download.html")
        
        sys.exit(1)
    else:
        print("\nAll dependencies are installed. You can run SimpleSec now.")

if __name__ == "__main__":
    main() 