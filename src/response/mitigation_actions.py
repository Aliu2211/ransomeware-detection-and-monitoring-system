import os
import sys
import logging
import time
import shutil
import json
import platform  # Add this import
import subprocess  # Add this import
from datetime import datetime
import psutil  # Add this import

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MitigationSystem:
    """
    System to mitigate ransomware threats once detected
    """
    def __init__(self, auto_mitigation=False, mitigation_actions=None, alert_system=None):
        """
        Initialize the mitigation system
        
        Args:
            auto_mitigation (bool): Whether to automatically mitigate detected threats
            mitigation_actions (list): Mitigation actions to take ('isolate_file', 'block_process', etc.)
            alert_system: Alert system to notify of mitigation actions
        """
        self.auto_mitigation = auto_mitigation
        self.mitigation_actions = mitigation_actions or []
        self.alert_system = alert_system
        
        # Ensure quarantine directory exists
        self.data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'data'))
        self.quarantine_dir = os.path.join(self.data_dir, 'quarantine')
        os.makedirs(self.quarantine_dir, exist_ok=True)
        
        # System-specific commands
        self.is_windows = platform.system().lower() == 'windows'
    
    def mitigate_threat(self, threat_info):
        """
        Mitigate a detected threat
        
        Args:
            threat_info (dict): Information about the threat including:
                - type: Type of threat ('file', 'process', 'network')
                - path: Path to the file (if type is 'file')
                - pid: Process ID (if type is 'process')
                - ip: IP address (if type is 'network')
                - reason: Reason for detection
                
        Returns:
            dict: Results of mitigation actions
        """
        if not self.auto_mitigation:
            logger.info(f"Auto-mitigation disabled, skipping mitigation for {threat_info['type']}")
            return {'success': False, 'reason': 'Auto-mitigation disabled'}
            
        results = {
            'timestamp': datetime.now().isoformat(),
            'actions_taken': [],
            'success': False
        }
        
        try:
            threat_type = threat_info.get('type')
            
            if threat_type == 'file':
                if 'isolate_file' in self.mitigation_actions:
                    file_result = self.quarantine_file(threat_info['path'], threat_info.get('reason', 'Unknown'))
                    results['actions_taken'].append({
                        'action': 'isolate_file',
                        'success': file_result['success'],
                        'details': file_result
                    })
                    results['success'] = file_result['success']
                    
            elif threat_type == 'process':
                if 'block_process' in self.mitigation_actions:
                    process_result = self.terminate_process(threat_info['pid'], threat_info.get('reason', 'Unknown'))
                    results['actions_taken'].append({
                        'action': 'block_process',
                        'success': process_result['success'],
                        'details': process_result
                    })
                    results['success'] = process_result['success']
                    
            elif threat_type == 'network':
                if 'block_network' in self.mitigation_actions:
                    network_result = self.block_connection(threat_info['ip'], threat_info.get('reason', 'Unknown'))
                    results['actions_taken'].append({
                        'action': 'block_network',
                        'success': network_result['success'],
                        'details': network_result
                    })
                    results['success'] = network_result['success']
            
            # Alert that mitigation was performed
            if self.alert_system:
                action_str = ', '.join([a['action'] for a in results['actions_taken']])
                success_str = "successful" if results['success'] else "failed"
                self.alert_system.trigger_alert(
                    message=f"Mitigation ({action_str}) {success_str} for {threat_type} threat: {threat_info.get('reason', 'Unknown')}",
                    level='warning',
                    source='mitigation',
                    data={'threat_info': threat_info, 'results': results}
                )
                
            return results
            
        except Exception as e:
            logger.error(f"Error during threat mitigation: {str(e)}")
            if self.alert_system:
                self.alert_system.trigger_alert(
                    message=f"Failed to mitigate threat: {str(e)}",
                    level='critical',
                    source='mitigation',
                    data={'threat_info': threat_info, 'error': str(e)}
                )
            return {'success': False, 'error': str(e)}
    
    def quarantine_file(self, file_path, reason):
        """
        Quarantine a suspicious file by moving it to quarantine directory
        
        Args:
            file_path (str): Path to the file
            reason (str): Reason for quarantine
            
        Returns:
            dict: Result of quarantine operation
        """
        result = {
            'success': False,
            'original_path': file_path
        }
        
        try:
            if not os.path.exists(file_path):
                result['error'] = f"File not found: {file_path}"
                return result
                
            # Create a unique filename for quarantine
            filename = os.path.basename(file_path)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            quarantine_filename = f"{timestamp}_{filename}"
            quarantine_path = os.path.join(self.quarantine_dir, quarantine_filename)
            
            # Copy file to quarantine (don't move directly in case we need the original for investigation)
            shutil.copy2(file_path, quarantine_path)
            
            # Create metadata file with quarantine info
            metadata = {
                'original_path': file_path,
                'quarantined_at': datetime.now().isoformat(),
                'reason': reason,
                'checksum': self._get_file_hash(file_path)
            }
            
            with open(f"{quarantine_path}.meta", 'w') as f:
                json.dump(metadata, f, indent=2)
                
            # Try to remove or rename the original file
            try:
                os.remove(file_path)
                result['action'] = "removed"
            except:
                # If removal fails, try to rename
                backup_path = f"{file_path}.malicious"
                os.rename(file_path, backup_path)
                result['action'] = "renamed"
                result['backup_path'] = backup_path
            
            result['success'] = True
            result['quarantine_path'] = quarantine_path
            logger.info(f"File quarantined: {file_path} -> {quarantine_path}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error quarantining file: {str(e)}")
            result['error'] = str(e)
            return result
    
    def terminate_process(self, pid, reason):
        """
        Terminate a suspicious process
        
        Args:
            pid (int): Process ID to terminate
            reason (str): Reason for termination
            
        Returns:
            dict: Result of process termination
        """
        result = {
            'success': False,
            'pid': pid,
            'reason': reason
        }
        
        try:
            # Check if process exists
            process_exists = False
            try:
                process = psutil.Process(pid)
                process_info = {
                    'name': process.name(),
                    'exe': process.exe() if hasattr(process, 'exe') else 'Unknown',
                    'cmdline': process.cmdline() if hasattr(process, 'cmdline') else []
                }
                result['process_info'] = process_info
                process_exists = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                result['error'] = f"Process with PID {pid} not found or access denied"
                return result
                
            if not process_exists:
                result['error'] = f"Process with PID {pid} not found"
                return result
                
            # Terminate the process
            if self.is_windows:
                # On Windows, use taskkill to ensure the process is terminated
                subprocess.call(['taskkill', '/F', '/PID', str(pid)])
            else:
                # On Unix-like systems, use kill with SIGKILL
                subprocess.call(['kill', '-9', str(pid)])
                
            # Verify termination
            try:
                process = psutil.Process(pid)
                result['error'] = f"Failed to terminate process with PID {pid}"
                return result
            except psutil.NoSuchProcess:
                result['success'] = True
                logger.info(f"Process terminated: PID {pid}")
                return result
                
        except Exception as e:
            logger.error(f"Error terminating process: {str(e)}")
            result['error'] = str(e)
            return result
    
    def block_connection(self, ip_address, reason):
        """
        Block a suspicious network connection
        
        Args:
            ip_address (str): IP address to block
            reason (str): Reason for blocking
            
        Returns:
            dict: Result of connection blocking
        """
        result = {
            'success': False,
            'ip_address': ip_address,
            'reason': reason
        }
        
        try:
            # This would typically use platform-specific firewall commands
            # For Windows: netsh advfirewall firewall add rule
            # For Linux: iptables
            # For simplicity, we'll just log the action here
            logger.info(f"Would block connection to IP: {ip_address} (Reason: {reason})")
            logger.info("Note: Actual firewall rule implementation would depend on the target platform")
            
            # In a real implementation, you would add code here to:
            # 1. Check if the IP is already blocked
            # 2. Add a firewall rule to block the IP
            # 3. Verify the rule was added successfully
            
            result['success'] = True
            result['note'] = "Simulated blocking - in real deployment, implement platform-specific firewall rules"
            
            return result
            
        except Exception as e:
            logger.error(f"Error blocking connection: {str(e)}")
            result['error'] = str(e)
            return result
    
    def _get_file_hash(self, file_path):
        """Calculate the SHA-256 hash of a file"""
        import hashlib
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for block in iter(lambda: f.read(4096), b''):
                    hasher.update(block)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating file hash: {str(e)}")
            return "hash_calculation_failed"