import sys
import os

# Add the src directory to Python's path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from response.mitigation_actions import MitigationSystem

# Initialize the mitigation system
mitigation_system = MitigationSystem(auto_mitigation=True, mitigation_actions=['isolate_file', 'block_process', 'block_network'])

# Test 1: Quarantine a file
test_file_path = "test_file.txt"
with open(test_file_path, "w") as f:
    f.write("This is a test file for quarantine.")

result = mitigation_system.quarantine_file(test_file_path, reason="Test quarantine")
print("Quarantine File Result:", result)

# Test 2: Terminate a process
import subprocess
process = subprocess.Popen(["notepad.exe"])  # Start a test process (Notepad)
result = mitigation_system.terminate_process(process.pid, reason="Test termination")
print("Terminate Process Result:", result)

# Test 3: Block a network connection (simulated)
result = mitigation_system.block_connection("192.168.1.1", reason="Test block")
print("Block Connection Result:", result)

# Clean up
if os.path.exists(test_file_path):
    os.remove(test_file_path)