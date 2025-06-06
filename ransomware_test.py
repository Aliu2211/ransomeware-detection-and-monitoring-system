import os
import time
import random
import string
import threading

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

def simulate_suspicious_behavior(test_dir):
    """Simulate behavior that should trigger detection"""
    print("Starting suspicious behavior simulation...")
    
    # 1. Rapid file modifications
    for i in range(10):
        filename = f"{test_dir}/sample_file_{i}.txt"
        if os.path.exists(filename):
            # Append random content (like encrypting)
            with open(filename, "a") as f:
                f.write(''.join(random.choices(string.ascii_uppercase + string.digits, k=50)))
            
            # Rename with suspicious extension
            new_filename = f"{filename}.encrypted"
            os.rename(filename, new_filename)
            print(f"Modified and renamed {filename} to {new_filename}")
            time.sleep(0.1)  # Small delay
    
    # 2. Create ransom note
    with open(f"{test_dir}/RANSOM_NOTE.txt", "w") as f:
        f.write("THIS IS A TEST RANSOM NOTE\n")
        f.write("Your files have been encrypted in this simulation.\n")
        f.write("This is only a test for the Ransomware Detection System.\n")
    
    # 3. Access unusual system paths (commented out for safety)
    # This just prints paths that would be accessed by real ransomware
    print("Would access system backup locations (simulation only)")
    print("Would access: C:\\Windows\\System32\\")
    print("Would access shadow copy paths")
    
    print("Suspicious behavior simulation complete!")

if __name__ == "__main__":
    print("RANSOMWARE DETECTION SYSTEM - TEST SCRIPT")
    print("WARNING: This script simulates ransomware-like behaviors for testing purposes only.")
    print("It will NOT harm your system but should trigger your detection system.")
    print("-" * 70)
    
    input("Press Enter to begin the test...")
    
    # Create test environment
    test_dir = create_test_directory()
    print(f"Created test directory: {test_dir} with sample files")
    
    # Allow some time for file monitoring to register the new files
    print("Waiting 3 seconds for file monitoring system to detect new files...")
    time.sleep(3)
    
    # Run the simulation
    simulate_suspicious_behavior(test_dir)
    
    print("-" * 70)
    print("Test complete. Check your Ransomware Detection Dashboard for alerts.")
    print("The system should have detected suspicious activity and taken mitigation actions.")