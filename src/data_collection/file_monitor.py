import os
import time
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

class RansomwareDetectionHandler(FileSystemEventHandler):
    def __init__(self, alert_system=None):
        self.alert_system = alert_system
        self.file_operations = {}  # Track file operations
        self.suspicious_extensions = ['.encrypt', '.locked', '.crypted', '.crypto', '.crypt', '.enc']
        self.suspicious_threshold = 10  # Number of suspicious operations before alerting
        
    def on_modified(self, event):
        if event.is_directory:
            return
        self._process_file_event(event.src_path, "modified")
    
    def on_created(self, event):
        if event.is_directory:
            return
        self._process_file_event(event.src_path, "created")
        
    def on_deleted(self, event):
        if event.is_directory:
            return
        self._process_file_event(event.src_path, "deleted")
    
    def _process_file_event(self, file_path, operation):
        try:
            # Log operation
            logger.info(f"File {operation}: {file_path}")
            
            # Track operation frequency
            if file_path not in self.file_operations:
                self.file_operations[file_path] = []
            
            self.file_operations[file_path].append(time.time())
            
            # Clean old operations (older than 5 minutes)
            self._clean_old_operations()
            
            # Check for suspicious activity
            self._check_suspicious_activity(file_path, operation)
            
        except Exception as e:
            logger.error(f"Error processing {file_path}: {str(e)}")
    
    def _clean_old_operations(self):
        current_time = time.time()
        for file_path in list(self.file_operations.keys()):
            self.file_operations[file_path] = [
                op_time for op_time in self.file_operations[file_path]
                if current_time - op_time < 300  # 5 minutes
            ]
            if not self.file_operations[file_path]:
                del self.file_operations[file_path]
    
    def _check_suspicious_activity(self, file_path, operation):
        # Check for suspicious file extensions
        _, file_extension = os.path.splitext(file_path)
        if file_extension in self.suspicious_extensions:
            self._trigger_alert(f"Suspicious file extension detected: {file_extension} in {file_path}")
            return
        
        # Check for high frequency operations
        operation_count = sum(len(ops) for ops in self.file_operations.values())
        if operation_count > self.suspicious_threshold:
            self._trigger_alert(f"High frequency file operations detected: {operation_count} operations in the last 5 minutes")
            
    def _trigger_alert(self, message):
        logger.warning(f"ALERT: {message}")
        if self.alert_system:
            self.alert_system.trigger_alert(message, level="warning")

def start_monitoring(paths_to_monitor, alert_system=None):
    """
    Start monitoring the specified paths for ransomware-like behavior
    
    Args:
        paths_to_monitor (list): List of directory paths to monitor
        alert_system (object): Alert system object with trigger_alert method
    """
    event_handler = RansomwareDetectionHandler(alert_system)
    observer = Observer()
    
    monitored_paths = []
    for path in paths_to_monitor:
        if os.path.exists(path):
            try:
                observer.schedule(event_handler, path, recursive=True)
                logger.info(f"Monitoring directory: {path}")
                monitored_paths.append(path)
            except PermissionError:
                logger.warning(f"Permission denied: Cannot monitor {path}. Try running with administrator privileges.")
                if alert_system:
                    alert_system.trigger_alert(f"Permission denied: Cannot monitor {path}. Try running with administrator privileges.", level="warning")
            except Exception as e:
                logger.error(f"Error monitoring {path}: {str(e)}")
        else:
            logger.error(f"Directory not found: {path}")
    
    if not monitored_paths:
        logger.warning("No directories could be monitored. Falling back to monitoring the current directory.")
        try:
            current_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            observer.schedule(event_handler, current_dir, recursive=True)
            logger.info(f"Monitoring directory: {current_dir}")
        except Exception as e:
            logger.error(f"Error monitoring fallback directory: {str(e)}")
    
    observer.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    # Example usage
    paths = ["/home", "/var"]  # Adjust for Windows: ["C:\\Users", "D:\\Data"]
    start_monitoring(paths)