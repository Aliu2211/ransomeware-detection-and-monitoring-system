#!/usr/bin/env python3
"""
Setup script for the Ransomware Detection System on Raspberry Pi
"""
import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

def check_python_version():
    """Check if the Python version is adequate"""
    if sys.version_info < (3, 7):
        logger.error("Python 3.7 or higher is required")
        return False
    return True

def check_raspberry_pi():
    """Check if running on a Raspberry Pi"""
    try:
        with open('/proc/device-tree/model', 'r') as f:
            model = f.read()
        if 'Raspberry Pi' in model:
            logger.info(f"Detected: {model.strip()}")
            return True
    except:
        pass
    
    logger.warning("Not running on a Raspberry Pi or couldn't detect model")
    return False

def install_dependencies():
    """Install system dependencies"""
    logger.info("Installing system dependencies...")
    
    try:
        # Update package lists
        subprocess.run(['sudo', 'apt', 'update'], check=True)
        
        # Install required packages
        packages = [
            'python3-pip',
            'python3-venv',
            'python3-dev',
            'libatlas-base-dev',  # For numpy
            'libjpeg-dev',        # For Pillow
            'zlib1g-dev',         # For Pillow
            'git'
        ]
        
        subprocess.run(['sudo', 'apt', 'install', '-y'] + packages, check=True)
        logger.info("System dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install system dependencies: {str(e)}")
        return False

def setup_virtual_environment(path):
    """Set up a Python virtual environment"""
    logger.info(f"Setting up virtual environment at {path}...")
    
    try:
        # Create virtual environment
        subprocess.run([sys.executable, '-m', 'venv', path], check=True)
        
        # Get path to pip and python in the virtual environment
        if os.name == 'nt':  # Windows
            pip_path = os.path.join(path, 'Scripts', 'pip')
            python_path = os.path.join(path, 'Scripts', 'python')
        else:  # Linux/macOS
            pip_path = os.path.join(path, 'bin', 'pip')
            python_path = os.path.join(path, 'bin', 'python')
        
        # Upgrade pip
        subprocess.run([pip_path, 'install', '--upgrade', 'pip'], check=True)
        
        # Install wheel for binary package building
        subprocess.run([pip_path, 'install', 'wheel'], check=True)
        
        logger.info("Virtual environment set up successfully")
        return pip_path, python_path
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set up virtual environment: {str(e)}")
        return None, None

def install_python_dependencies(pip_path, requirements_file):
    """Install Python dependencies from requirements file"""
    logger.info("Installing Python dependencies...")
    
    try:
        subprocess.run([pip_path, 'install', '-r', requirements_file], check=True)
        logger.info("Python dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install Python dependencies: {str(e)}")
        return False

def create_service_file(python_path, app_path, service_path):
    """Create systemd service file for autostart"""
    logger.info("Creating systemd service file...")
    
    service_content = f"""[Unit]
Description=Ransomware Detection System
After=network.target

[Service]
ExecStart={python_path} {app_path}
WorkingDirectory={os.path.dirname(app_path)}
Restart=always
User={os.getenv('USER')}
Group={os.getenv('USER')}
Environment=PATH={os.path.dirname(python_path)}:$PATH

[Install]
WantedBy=multi-user.target
"""
    
    try:
        with open(service_path, 'w') as f:
            f.write(service_content)
        logger.info(f"Service file created at {service_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to create service file: {str(e)}")
        return False

def setup_autostart(service_path):
    """Enable service to start automatically"""
    logger.info("Setting up autostart...")
    
    try:
        # Copy service file to systemd directory
        dest_path = '/etc/systemd/system/ransomware-detection.service'
        subprocess.run(['sudo', 'cp', service_path, dest_path], check=True)
        
        # Reload systemd
        subprocess.run(['sudo', 'systemctl', 'daemon-reload'], check=True)
        
        # Enable service
        subprocess.run(['sudo', 'systemctl', 'enable', 'ransomware-detection'], check=True)
        
        logger.info("Autostart set up successfully")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to set up autostart: {str(e)}")
        return False

def setup_data_directories(base_dir):
    """Set up data directories"""
    logger.info("Setting up data directories...")
    
    directories = [
        'data',
        'data/models',
        'data/logs',
        'data/alerts',
        'data/training',
        'data/quarantine',
        'data/threat_intel'
    ]
    
    try:
        for directory in directories:
            path = os.path.join(base_dir, directory)
            os.makedirs(path, exist_ok=True)
            logger.info(f"Created directory: {path}")
        return True
    except Exception as e:
        logger.error(f"Failed to create data directories: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Set up Ransomware Detection System on Raspberry Pi')
    parser.add_argument('--venv', default='.venv', help='Path to virtual environment')
    parser.add_argument('--no-deps', action='store_true', help='Skip installing system dependencies')
    parser.add_argument('--no-autostart', action='store_true', help='Skip setting up autostart')
    args = parser.parse_args()
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Check if running on Raspberry Pi
    is_pi = check_raspberry_pi()
    if not is_pi:
        answer = input("Not running on a Raspberry Pi or couldn't detect. Continue anyway? (y/n): ")
        if answer.lower() != 'y':
            logger.info("Setup aborted")
            return 1
    
    # Get base directory
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Set up data directories
    if not setup_data_directories(base_dir):
        return 1
    
    # Install system dependencies
    if not args.no_deps:
        if not install_dependencies():
            logger.error("Failed to install system dependencies")
            return 1
    
    # Set up virtual environment
    venv_path = os.path.join(base_dir, args.venv)
    pip_path, python_path = setup_virtual_environment(venv_path)
    if not pip_path or not python_path:
        logger.error("Failed to set up virtual environment")
        return 1
    
    # Install Python dependencies
    requirements_file = os.path.join(base_dir, 'requirements.txt')
    if not install_python_dependencies(pip_path, requirements_file):
        logger.error("Failed to install Python dependencies")
        return 1
    
    # Set up autostart
    if not args.no_autostart:
        service_path = os.path.join(base_dir, 'ransomware-detection.service')
        app_path = os.path.join(base_dir, 'src', 'main.py')
        
        if not create_service_file(python_path, app_path, service_path):
            logger.error("Failed to create service file")
            return 1
        
        if not setup_autostart(service_path):
            logger.error("Failed to set up autostart")
            return 1
    
    logger.info("Setup completed successfully!")
    logger.info(f"To start the service manually: sudo systemctl start ransomware-detection")
    logger.info(f"To check the service status: sudo systemctl status ransomware-detection")
    logger.info(f"To view logs: sudo journalctl -u ransomware-detection")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())