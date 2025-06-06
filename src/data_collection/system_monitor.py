import psutil
import os
import time
import logging
import threading
import json
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

class SystemMonitor:
    def __init__(self, anomaly_detector=None, collection_interval=5):
        """
        Initialize the system monitor
        
        Args:
            anomaly_detector: The anomaly detector to use for analysis
            collection_interval (int): Data collection interval in seconds
        """
        self.anomaly_detector = anomaly_detector
        self.collection_interval = collection_interval
        self.running = False
        self.monitor_thread = None
        
        # Initialize counters and metrics
        self.reset_metrics()
        
    def reset_metrics(self):
        """Reset all metrics and counters"""
        self.metrics = {
            'file_operations_count': 0,
            'file_encryption_count': 0,
            'file_deletion_count': 0,
            'file_creation_count': 0,
            'disk_read_rate': 0,
            'disk_write_rate': 0,
            'cpu_usage': 0,
            'memory_usage': 0,
            'network_activity': 0,
            'start_time': datetime.now().isoformat(),
            'end_time': None
        }
        
        # Previous disk and network counters for rate calculation
        self.prev_disk_io = psutil.disk_io_counters()
        self.prev_net_io = psutil.net_io_counters()
        self.prev_time = time.time()
        
    def start(self):
        """Start system monitoring in a separate thread"""
        if self.running:
            logger.warning("System monitor is already running")
            return
            
        self.running = True
        self.reset_metrics()
        self.monitor_thread = threading.Thread(target=self._monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        logger.info("System monitoring started")
        
    def stop(self):
        """Stop the system monitoring"""
        if not self.running:
            logger.warning("System monitor is not running")
            return
            
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=self.collection_interval+1)
        
        self.metrics['end_time'] = datetime.now().isoformat()
        logger.info("System monitoring stopped")
        
    def _monitoring_loop(self):
        """Main monitoring loop that collects system metrics"""
        while self.running:
            try:
                self._collect_metrics()
                
                # If anomaly detector is provided, check for anomalies
                if self.anomaly_detector:
                    prediction, score = self.anomaly_detector.predict(self.metrics)
                    if prediction == -1:  # Anomaly detected
                        logger.warning(f"Possible ransomware activity detected! Anomaly score: {score}")
                        # Here you could trigger alerts or mitigation actions
                
                time.sleep(self.collection_interval)
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                time.sleep(self.collection_interval)  # Sleep and continue
    
    def _collect_metrics(self):
        """Collect system metrics"""
        try:
            # Calculate CPU and memory usage
            self.metrics['cpu_usage'] = psutil.cpu_percent()
            self.metrics['memory_usage'] = psutil.virtual_memory().percent
            
            # Calculate disk I/O rates
            current_time = time.time()
            current_disk_io = psutil.disk_io_counters()
            time_diff = current_time - self.prev_time
            
            if time_diff > 0:
                read_bytes_diff = current_disk_io.read_bytes - self.prev_disk_io.read_bytes
                write_bytes_diff = current_disk_io.write_bytes - self.prev_disk_io.write_bytes
                
                self.metrics['disk_read_rate'] = read_bytes_diff / time_diff
                self.metrics['disk_write_rate'] = write_bytes_diff / time_diff
            
            self.prev_disk_io = current_disk_io
            
            # Calculate network activity
            current_net_io = psutil.net_io_counters()
            if time_diff > 0:
                sent_bytes_diff = current_net_io.bytes_sent - self.prev_net_io.bytes_sent
                recv_bytes_diff = current_net_io.bytes_recv - self.prev_net_io.bytes_recv
                
                self.metrics['network_activity'] = (sent_bytes_diff + recv_bytes_diff) / time_diff
            
            self.prev_net_io = current_net_io
            self.prev_time = current_time
            
            # Log current metrics
            logger.debug(f"System metrics updated: CPU={self.metrics['cpu_usage']}%, "
                        f"Memory={self.metrics['memory_usage']}%, "
                        f"Disk write={self.metrics['disk_write_rate']:.2f} B/s, "
                        f"Network={self.metrics['network_activity']:.2f} B/s")
                
        except Exception as e:
            logger.error(f"Error collecting metrics: {str(e)}")
    
    def increment_file_counter(self, operation_type):
        """
        Increment a specific file operation counter
        
        Args:
            operation_type (str): Type of operation ('operations', 'encryption', 'deletion', 'creation')
        """
        counter_name = f"file_{operation_type}_count"
        if counter_name in self.metrics:
            self.metrics[counter_name] += 1
    
    def get_current_metrics(self):
        """
        Get the current system metrics
        
        Returns:
            dict: Current system metrics
        """
        return self.metrics.copy()
    
    def save_metrics(self, file_path):
        """
        Save current metrics to a file
        
        Args:
            file_path (str): Path to save the metrics
        """
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump(self.metrics, f, indent=2)
            logger.info(f"Metrics saved to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save metrics: {str(e)}")
            return False

if __name__ == "__main__":
    # Example usage
    monitor = SystemMonitor(collection_interval=2)
    monitor.start()
    
    try:
        # Simulate some file operations
        for i in range(5):
            monitor.increment_file_counter('operations')
            time.sleep(1)
            
        # For testing, simulate some suspicious activity
        for i in range(20):
            monitor.increment_file_counter('encryption')
            monitor.increment_file_counter('operations')
            time.sleep(0.1)
        
        time.sleep(5)  # Allow time for metrics collection
        
        # Get and display current metrics
        metrics = monitor.get_current_metrics()
        print(json.dumps(metrics, indent=2))
        
        # Save metrics
        monitor.save_metrics("../../data/metrics/system_metrics.json")
        
    finally:
        monitor.stop()