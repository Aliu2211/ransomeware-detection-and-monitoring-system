#!/usr/bin/env python3
"""
RMS Setup Verification Tool

This script checks that all required components and dependencies 
for the Ransomware Monitoring System are properly installed and configured.
"""

import os
import sys
import importlib
import platform
import subprocess
import json

# Add colors for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_status(message, status, details=None):
    """Print a status message with color coding"""
    status_color = {
        "OK": Colors.GREEN,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED,
        "INFO": Colors.BLUE
    }
    
    color = status_color.get(status, Colors.BLUE)
    status_str = f"{color}[{status}]{Colors.ENDC}"
    
    print(f"{status_str} {message}")
    if details:
        print(f"     {Colors.BLUE}{details}{Colors.ENDC}")
    
def check_python_version():
    """Check Python version"""
    required_version = (3, 8)
    current_version = sys.version_info
    
    if current_version >= required_version:
        print_status(
            f"Python version: {sys.version.split()[0]}", 
            "OK", 
            f"Required: {required_version[0]}.{required_version[1]}+"
        )
        return True
    else:
        print_status(
            f"Python version: {sys.version.split()[0]}", 
            "ERROR", 
            f"Required: {required_version[0]}.{required_version[1]}+"
        )
        return False

def check_dependencies():
    """Check required Python packages"""
    required_packages = [
        "numpy", 
        "pandas", 
        "sklearn", 
        "psutil", 
        "requests", 
        "watchdog", 
        "joblib", 
        "flask",
        "matplotlib",
        "yaml",
        "dotenv"
    ]
    
    optional_packages = ["RPi.GPIO"]
    
    all_installed = True
    print_status("Checking dependencies...", "INFO")
    
    for package in required_packages:
        try:
            if package == "sklearn":
                importlib.import_module("sklearn")
            elif package == "yaml":
                importlib.import_module("yaml")
            elif package == "dotenv":
                importlib.import_module("dotenv")
            else:
                importlib.import_module(package)
            print_status(f"Package: {package}", "OK")
        except ImportError:
            print_status(f"Package: {package}", "ERROR", "Required but not installed")
            all_installed = False
    
    for package in optional_packages:
        try:
            importlib.import_module(package)
            print_status(f"Package: {package}", "OK", "Optional")
        except ImportError:
            print_status(f"Package: {package}", "WARNING", "Optional but not installed")
    
    return all_installed

def check_directory_structure():
    """Check for required directories"""
    project_root = os.path.dirname(os.path.abspath(__file__))
    required_dirs = [
        "src",
        "config", 
        "data", 
        "data/models", 
        "data/training", 
        "data/logs", 
        "data/alerts", 
        "data/quarantine", 
        "data/threat_intel"
    ]
    
    print_status("Checking directory structure...", "INFO")
    missing_dirs = []
    
    for d in required_dirs:
        dir_path = os.path.join(project_root, d)
        if os.path.exists(dir_path) and os.path.isdir(dir_path):
            print_status(f"Directory: {d}", "OK")
        else:
            print_status(f"Directory: {d}", "ERROR", "Missing directory")
            missing_dirs.append(dir_path)
    
    if missing_dirs:
        print_status("Creating missing directories...", "INFO")
        for d in missing_dirs:
            try:
                os.makedirs(d, exist_ok=True)
                print_status(f"Created directory: {os.path.relpath(d, project_root)}", "OK")
            except Exception as e:
                print_status(f"Failed to create directory: {os.path.relpath(d, project_root)}", "ERROR", str(e))
    
    return True

def check_env_file():
    """Check for .env file"""
    project_root = os.path.dirname(os.path.abspath(__file__))
    env_path = os.path.join(project_root, ".env")
    env_example_path = os.path.join(project_root, ".env.example")
    
    if os.path.exists(env_path):
        print_status(".env file", "OK")
        return True
    elif os.path.exists(env_example_path):
        print_status(".env file", "WARNING", "Not found, but .env.example exists. Copy it to .env and customize.")
        return False
    else:
        print_status(".env file", "ERROR", "Not found. Create .env file with your configuration.")
        return False

def check_system_compatibility():
    """Check system compatibility"""
    system = platform.system()
    
    if system == "Windows":
        print_status(f"Operating System: {system}", "OK", "Windows is fully supported")
    elif system == "Linux":
        print_status(f"Operating System: {system}", "OK", "Linux is fully supported")
    elif system == "Darwin":
        print_status(f"Operating System: {system}", "OK", "macOS is supported")
    else:
        print_status(f"Operating System: {system}", "WARNING", "Untested operating system")
    
    # Check for administrative privileges
    admin = False
    try:
        if system == "Windows":
            from ctypes import windll
            admin = windll.shell32.IsUserAnAdmin() != 0
        elif system in ["Linux", "Darwin"]:
            admin = os.geteuid() == 0
    except:
        pass
    
    if admin:
        print_status("Administrative privileges", "OK", "Running with admin privileges")
    else:
        print_status("Administrative privileges", "WARNING", 
                   "Not running with admin privileges. Some features may be limited. Use --safe-dirs when running.")

def main():
    """Main function"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}Ransomware Monitoring System (RMS) Setup Verification{Colors.ENDC}\n")
    
    all_checks_passed = True
    
    all_checks_passed &= check_python_version()
    all_checks_passed &= check_dependencies()
    check_directory_structure()  # Always returns True, just creates missing dirs
    all_checks_passed &= check_env_file()
    check_system_compatibility()  # Informational only
    
    print("\n" + "-" * 60)
    if all_checks_passed:
        print(f"\n{Colors.GREEN}{Colors.BOLD}All critical checks passed!{Colors.ENDC}")
        print(f"\nYou can now run the system with: {Colors.BLUE}python src/main.py{Colors.ENDC}")
    else:
        print(f"\n{Colors.YELLOW}{Colors.BOLD}Some checks failed or produced warnings.{Colors.ENDC}")
        print("Please address the issues above before running the system.")
    
    print("\nFor more information, see the README.md file.")
    print("-" * 60 + "\n")
    
if __name__ == "__main__":
    main()
