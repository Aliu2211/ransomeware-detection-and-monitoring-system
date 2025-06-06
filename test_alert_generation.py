import os
import json
import time
from datetime import datetime
import sys
import shutil

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
from src.response.mitigation_actions import MitigationSystem

def create_test_directory():
    """Create a test directory with sample files"""
    test_dir = "test_ransomware_detection"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
        
    # Create sample files
    for i in range(10):
        filename = f"{test_dir}/sample_file_{i}.txt"
        with open(filename, "w") as f:
            f.write(f"This is sample file {i} content.\n")
    
    return test_dir

def generate_test_alerts():
    """Generate test alerts directly to the alerts directory"""
    print("Generating test alerts...")
    
    # Make sure the directory exists
    data_dir = os.path.join(os.path.dirname(__file__), 'data')
    alerts_dir = os.path.join(data_dir, 'alerts')
    logs_dir = os.path.join(data_dir, 'logs') 
    
    os.makedirs(alerts_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)
    
    # Current timestamp
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    alert_timestamp = now.isoformat()
    
    # Create test alerts
    alerts = [
        {
            "timestamp": alert_timestamp,
            "level": "critical",
            "message": "Ransomware activity detected - encryption behavior observed",
            "details": "Multiple files have been encrypted in test_ransomware_detection directory",
            "source": "file_monitor"
        },
        {
            "timestamp": alert_timestamp,
            "level": "critical", 
            "message": "Ransom note created - RANSOM_NOTE.txt",
            "details": "File with name pattern matching ransom note detected",
            "source": "file_monitor"
        },
        {
            "timestamp": alert_timestamp,
            "level": "warning",
            "message": "Suspicious process launched: ransomware_test.py",
            "details": "Process is making rapid file modifications and renaming",
            "source": "process_monitor"
        }
    ]
    
    # Write alerts to file
    alert_file = os.path.join(alerts_dir, f"alerts_{timestamp}.json")
    with open(alert_file, 'w') as f:
        json.dump(alerts, f, indent=2)
    
    # Create log entries
    log_file = os.path.join(logs_dir, f"activity_{timestamp}.log")
    with open(log_file, 'w') as f:
        f.write(f"{alert_timestamp} - FILE_MONITOR - Multiple files renamed with .encrypted extension\n")
        f.write(f"{alert_timestamp} - FILE_MONITOR - Suspicious file created: RANSOM_NOTE.txt\n")
        f.write(f"{alert_timestamp} - PROCESS_MONITOR - Detected process making rapid file modifications\n")
        f.write(f"{alert_timestamp} - SYSTEM - Alert triggered: Ransomware activity detected\n")
        f.write(f"{alert_timestamp} - MITIGATION - Automatic quarantine initiated for suspicious files\n")
    
    print(f"Created test alerts in {alert_file}")
    print(f"Created test logs in {log_file}")

def simulate_and_mitigate():
    """Simulate ransomware behavior and mitigate it"""
    # Create test directory with files
    test_dir = create_test_directory()
    print(f"Created test directory: {test_dir}")
    
    # Initialize mitigation system
    mitigation = MitigationSystem(auto_mitigation=True)
    
    # Create a "suspicious" file
    ransom_note = os.path.join(test_dir, "RANSOM_NOTE.txt")
    with open(ransom_note, "w") as f:
        f.write("THIS IS A TEST RANSOM NOTE\n")
        f.write("Files have been encrypted in this simulation.\n")
    
    # Quarantine the file
    result = mitigation.quarantine_file(ransom_note, "Suspicious ransom note detected")
    print("Quarantine result:", result)
    
    # Encrypt some files (simulate)
    for i in range(5):
        orig_file = f"{test_dir}/sample_file_{i}.txt"
        encrypted_file = f"{test_dir}/sample_file_{i}.txt.encrypted"
        
        # Rename to simulate encryption
        if os.path.exists(orig_file):
            shutil.copy(orig_file, encrypted_file)
            result = mitigation.quarantine_file(encrypted_file, "Suspicious encrypted file")
            print(f"Quarantined {encrypted_file}")
    
    # Generate alerts for dashboard
    generate_test_alerts()

if __name__ == "__main__":
    print("ALERT GENERATION TEST")
    print("This will generate test alerts and activity logs for the dashboard")
    print("-" * 70)
    
    simulate_and_mitigate()
    
    print("\nDone! Please refresh your dashboard to see the alerts and activity logs.")