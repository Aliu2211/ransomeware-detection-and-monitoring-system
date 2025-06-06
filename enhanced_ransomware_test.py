# import os
# import time
# import random
# import string
# import threading
# import sys

# # Import directly from your monitoring system
# sys.path.append(os.path.dirname(__file__))
# from src.monitoring.file_monitor import FileMonitor
# from src.monitoring.system_monitor import SystemMonitor
# from src.analysis.ransomware_detector import RansomwareDetector

# def create_test_directory():
#     """Create a test directory with sample files"""
#     test_dir = "test_ransomware_detection"
#     if not os.path.exists(test_dir):
#         os.makedirs(test_dir)
        
#     # Create sample files
#     for i in range(10):
#         filename = f"{test_dir}/sample_file_{i}.txt"
#         with open(filename, "w") as f:
#             f.write(f"This is sample file {i} content.\n")
    
#     return test_dir

# def simulate_suspicious_behavior(test_dir, detector):
#     """Simulate behavior that should trigger detection and directly notify the detector"""
#     print("Starting suspicious behavior simulation with direct detector notification...")
    
#     # 1. Rapid file modifications
#     for i in range(10):
#         filename = f"{test_dir}/sample_file_{i}.txt"
#         if os.path.exists(filename):
#             # Append random content (like encrypting)
#             with open(filename, "a") as f:
#                 f.write(''.join(random.choices(string.ascii_uppercase + string.digits, k=50)))
            
#             # Simulate encryption and rename
#             new_filename = f"{filename}.encrypted"
#             os.rename(filename, new_filename)
#             print(f"Modified and renamed {filename} to {new_filename}")
            
#             # Directly notify the detector
#             event = {
#                 'type': 'file_rename',
#                 'path': filename,
#                 'new_path': new_filename,
#                 'timestamp': time.time(),
#                 'process_id': os.getpid(),
#                 'process_name': 'ransomware_test.py'
#             }
#             detector.analyze_event(event)
#             time.sleep(0.1)  # Small delay
    
#     # 2. Create ransom note - this is highly suspicious
#     ransom_path = f"{test_dir}/RANSOM_NOTE.txt"
#     with open(ransom_path, "w") as f:
#         f.write("THIS IS A TEST RANSOM NOTE\n")
#         f.write("Your files have been encrypted in this simulation.\n")
#         f.write("This is only a test for the Ransomware Detection System.\n")
    
#     # Notify about the ransom note - this should definitely trigger detection
#     event = {
#         'type': 'file_create',
#         'path': ransom_path,
#         'timestamp': time.time(),
#         'process_id': os.getpid(),
#         'process_name': 'ransomware_test.py',
#         'content_sample': "THIS IS A TEST RANSOM NOTE\nYour files have been encrypted"
#     }
#     detector.analyze_event(event)
    
#     print("Suspicious behavior simulation complete!")

# def test_with_mock_events():
#     """Send mock events directly to the alert system"""
#     from src.detection.alert import AlertSystem
    
#     alert_system = AlertSystem()
    
#     # Create a critical ransomware alert
#     alert_system.add_alert(
#         level="critical",
#         message="RANSOMWARE ACTIVITY DETECTED",
#         details="Multiple files encrypted and ransom note created. Process: ransomware_test.py",
#         source="Simulated Test"
#     )
    
#     # Create activity logs
#     for i in range(5):
#         alert_system.log_activity(
#             message=f"Suspicious file operation detected on sample_file_{i}.txt",
#             event_type="file",
#             details=f"File encrypted with suspicious extension: .encrypted"
#         )
    
#     print("Added direct test alerts and activity logs to the system")

# if __name__ == "__main__":
#     print("ENHANCED RANSOMWARE DETECTION SYSTEM - TEST SCRIPT")
#     print("This script directly interacts with the detection system")
#     print("-" * 70)
    
#     input("Press Enter to begin the test...")
    
#     # Initialize detector
#     try:
#         detector = RansomwareDetector()
#         print("Successfully initialized RansomwareDetector")
#     except Exception as e:
#         print(f"Failed to initialize detector: {str(e)}")
#         print("Falling back to direct alert method")
#         detector = None
    
#     # Create test environment
#     test_dir = create_test_directory()
#     print(f"Created test directory: {test_dir} with sample files")
    
#     # Run the simulation
#     if detector:
#         simulate_suspicious_behavior(test_dir, detector)
#     else:
#         test_with_mock_events()
    
#     print("-" * 70)
#     print("Test complete. Check your Ransomware Detection Dashboard for alerts.")
#     print("If no alerts appear, check that:")
#     print("1. Your monitoring system is enabled in Settings")
#     print("2. The AlertSystem is properly connected to your dashboard")
#     print("3. Your dashboard is properly reloading/refreshing alert data")



import os
import json
import time
from datetime import datetime
import shutil
import random
import string

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
    
    print(f"Created test directory: {test_dir} with sample files")
    return test_dir

def generate_test_alerts():
    """Generate test alerts directly to the data directories"""
    print("Generating test alerts...")
    
    # Make sure the directories exist
    data_dir = os.path.join("data")
    alerts_dir = os.path.join(data_dir, "alerts")
    logs_dir = os.path.join(data_dir, "logs")
    
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
    log_entries = [
        f"{alert_timestamp} - FILE_MONITOR - Multiple files renamed with .encrypted extension",
        f"{alert_timestamp} - FILE_MONITOR - Suspicious file created: RANSOM_NOTE.txt",
        f"{alert_timestamp} - PROCESS_MONITOR - Detected process making rapid file modifications",
        f"{alert_timestamp} - SYSTEM - Alert triggered: Ransomware activity detected",
        f"{alert_timestamp} - MITIGATION - Automatic quarantine initiated for suspicious files"
    ]
    
    log_file = os.path.join(logs_dir, f"activity_{timestamp}.log")
    with open(log_file, 'w') as f:
        for entry in log_entries:
            f.write(entry + "\n")
    
    print(f"Created test alerts in {alert_file}")
    print(f"Created test logs in {log_file}")

def simulate_ransomware_behavior(test_dir):
    """Simulate ransomware-like behavior on the test files"""
    print("Simulating ransomware behavior...")
    
    # Create a quarantine directory if it doesn't exist
    quarantine_dir = os.path.join("data", "quarantine")
    os.makedirs(quarantine_dir, exist_ok=True)
    
    # Create metadata directory for quarantine
    quarantine_meta_dir = os.path.join(quarantine_dir, "metadata")
    os.makedirs(quarantine_meta_dir, exist_ok=True)
    
    # Encrypt some files (simulate)
    for i in range(5):
        orig_file = f"{test_dir}/sample_file_{i}.txt"
        encrypted_file = f"{test_dir}/sample_file_{i}.txt.encrypted"
        
        if os.path.exists(orig_file):
            # Add random content to simulate encryption
            with open(orig_file, "a") as f:
                f.write(''.join(random.choices(string.ascii_uppercase + string.digits, k=50)))
            
            # Rename to simulate encryption
            os.rename(orig_file, encrypted_file)
            print(f"Encrypted {orig_file} to {encrypted_file}")
            
            # Quarantine the file
            quarantine_filename = f"sample_file_{i}.txt.encrypted_{int(time.time())}"
            quarantined_path = os.path.join(quarantine_dir, quarantine_filename)
            shutil.copy(encrypted_file, quarantined_path)
            
            # Create metadata
            metadata = {
                "original_path": encrypted_file,
                "quarantined_at": datetime.now().isoformat(),
                "reason": "Suspicious file encryption detected",
                "checksum": "abcdef1234567890"  # Simplified example
            }
            
            meta_path = os.path.join(quarantine_meta_dir, f"{quarantine_filename}.json")
            with open(meta_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
            print(f"Quarantined file to {quarantined_path}")
    
    # Create a ransom note
    ransom_path = f"{test_dir}/RANSOM_NOTE.txt"
    with open(ransom_path, "w") as f:
        f.write("THIS IS A TEST RANSOM NOTE\n")
        f.write("Your files have been encrypted in this simulation.\n")
        f.write("This is only a test for the Ransomware Detection System.\n")
    
    print(f"Created ransom note at {ransom_path}")
    
    # Quarantine ransom note too
    quarantine_filename = f"RANSOM_NOTE.txt_{int(time.time())}"
    quarantined_path = os.path.join(quarantine_dir, quarantine_filename)
    shutil.copy(ransom_path, quarantined_path)
    
    metadata = {
        "original_path": ransom_path,
        "quarantined_at": datetime.now().isoformat(),
        "reason": "Ransom note detected",
        "checksum": "0987654321fedcba"  # Simplified example
    }
    
    meta_path = os.path.join(quarantine_meta_dir, f"{quarantine_filename}.json")
    with open(meta_path, 'w') as f:
        json.dump(metadata, f, indent=2)
        
    print(f"Quarantined ransom note to {quarantined_path}")

if __name__ == "__main__":
    print("RANSOMWARE DETECTION SYSTEM - TEST SCRIPT")
    print("This script simulates ransomware behavior and generates alerts")
    print("-" * 70)
    
    input("Press Enter to begin the test...")
    
    # Create test directory with files
    test_dir = create_test_directory()
    
    # Simulate ransomware behavior
    simulate_ransomware_behavior(test_dir)
    
    # Generate alerts and logs
    generate_test_alerts()
    
    print("-" * 70)
    print("Test complete! Now check your dashboard:")
    print("1. Refresh http://127.0.0.1:5000/ to see alerts on the main dashboard")
    print("2. Go to http://127.0.0.1:5000/alerts to see all alerts")
    print("3. Go to http://127.0.0.1:5000/activity to see the activity log")
    print("4. Go to http://127.0.0.1:5000/quarantine to see quarantined files")