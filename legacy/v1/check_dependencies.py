import sys
import importlib
import subprocess
import pkg_resources

def check_dependency(module_name, package_name=None):
    """
    Check if a Python module is installed.
    
    Args:
        module_name (str): The name of the module to import
        package_name (str, optional): The package name if different from module_name
    """
    if package_name is None:
        package_name = module_name
        
    try:
        importlib.import_module(module_name)
        version = pkg_resources.get_distribution(package_name).version
        print(f"✓ {module_name} is installed (version {version})")
        return True
    except (ImportError, pkg_resources.DistributionNotFound) as e:
        print(f"✗ {module_name} is NOT installed: {str(e)}")
        return False

def main():
    """Check all dependencies required for SimplySec."""
    print("Checking SimplySec Dependencies")
    print("==============================")
    print()
    
    # Required Python modules with their package names
    dependencies = [
        ("psutil", "psutil"),                # System information
        ("nmap", "python-nmap"),             # Python-nmap for network scanning
        ("PyQt5", "PyQt5"),                  # GUI framework
        ("win32api", "pywin32")              # Windows API access (part of pywin32)
    ]
    
    all_installed = True
    missing = []
    
    # Check each dependency
    for module_name, package_name in dependencies:
        if not check_dependency(module_name, package_name):
            all_installed = False
            missing.append(package_name)
    
    # Check if Nmap is installed (external dependency)
    print("\nChecking for Nmap installation...")
    try:
        result = subprocess.run(["nmap", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Nmap is installed and ready to use.")
            print(result.stdout.split("\n")[0])  # Print version info
        else:
            print("✗ Nmap command failed.")
            all_installed = False
            missing.append("Nmap (external)")
    except FileNotFoundError:
        print("✗ Nmap is not installed or not in your PATH.")
        all_installed = False
        missing.append("Nmap (external)")
    
    # Summary
    print("\nDependency Check Summary:")
    if all_installed:
        print("✅ All dependencies are installed. SimplySec should run correctly.")
    else:
        print("❌ Some dependencies are missing:")
        for dep in missing:
            print(f"  - {dep}")
        
        print("\nTo install missing Python dependencies, run:")
        print("pip install -r requirements.txt")
        
        if "Nmap (external)" in missing:
            print("\nTo install Nmap:")
            print("1. Download from https://nmap.org/download.html")
            print("2. Run the installer with default options")
            print("3. Restart your computer after installation")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main() 