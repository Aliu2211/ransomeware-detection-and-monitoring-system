import logging
import os
import json
import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AlertSystem:
    """
    Alert system to notify users of potential ransomware threats
    """
    def __init__(self, alert_level='warning', alert_methods=None, email_alerts=False, email_config=None):
        """
        Initialize the alert system
        
        Args:
            alert_level (str): Minimum level to trigger alerts ('info', 'warning', 'critical')
            alert_methods (list): Methods to use for alerts ('console', 'file', 'email')
            email_alerts (bool): Whether to send email alerts
            email_config (dict): Email configuration including smtp_server, port, username, password, recipients
        """
        self.alert_level = alert_level
        self.alert_methods = alert_methods or ['console', 'file']
        self.email_alerts = email_alerts
        self.email_config = email_config or {}
        
        self.level_priority = {
            'info': 1,
            'warning': 2,
            'critical': 3
        }
        
        # Ensure data directory exists
        self.data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'data'))
        self.alerts_dir = os.path.join(self.data_dir, 'alerts')
        os.makedirs(self.alerts_dir, exist_ok=True)
        
        # Initialize alerts storage
        self.alerts = []
        self._load_previous_alerts()
        
    def _load_previous_alerts(self):
        """Load previously saved alerts"""
        try:
            # Find the most recent alerts file
            alert_files = sorted([f for f in os.listdir(self.alerts_dir) if f.startswith('alerts_')])
            if not alert_files:
                return
                
            latest_file = os.path.join(self.alerts_dir, alert_files[-1])
            with open(latest_file, 'r') as f:
                self.alerts = json.load(f)
                
            logger.info(f"Loaded {len(self.alerts)} previous alerts from {latest_file}")
        except Exception as e:
            logger.error(f"Error loading previous alerts: {str(e)}")
    
    def trigger_alert(self, message, level='info', source=None, data=None):
        """
        Trigger an alert with the given message and level
        
        Args:
            message (str): Alert message
            level (str): Alert level ('info', 'warning', 'critical')
            source (str): Source of the alert (e.g., 'file_monitor', 'system_monitor')
            data (dict): Additional data related to the alert
            
        Returns:
            bool: True if alert was triggered, False otherwise
        """
        # Check if the alert meets the minimum level
        if self.level_priority.get(level, 0) < self.level_priority.get(self.alert_level, 0):
            return False
            
        timestamp = datetime.now().isoformat()
        
        alert = {
            'timestamp': timestamp,
            'level': level,
            'message': message,
            'source': source,
            'data': data
        }
        
        # Add to alerts list
        self.alerts.append(alert)
        
        # Limit the number of stored alerts to prevent memory issues
        if len(self.alerts) > 1000:
            self.alerts = self.alerts[-1000:]
        
        # Process the alert based on configured methods
        if 'console' in self.alert_methods:
            self._console_alert(alert)
            
        if 'file' in self.alert_methods:
            self._file_alert(alert)
            
        if self.email_alerts and 'email' in self.alert_methods:
            self._email_alert(alert)
            
        return True
    
    def _console_alert(self, alert):
        """Output alert to console"""
        level_prefix = {
            'info': '[INFO]',
            'warning': '[WARNING]',
            'critical': '[CRITICAL]'
        }.get(alert['level'], '[INFO]')
        
        logger.warning(f"{level_prefix} {alert['message']}")
    
    def _file_alert(self, alert):
        """Save alert to file"""
        try:
            # Create a filename based on the current date
            date_str = datetime.now().strftime('%Y%m%d')
            filename = f"alerts_{date_str}.json"
            filepath = os.path.join(self.alerts_dir, filename)
            
            # Get all alerts for today
            today_alerts = [a for a in self.alerts if a['timestamp'].startswith(date_str.replace('_', '-'))]
            
            # Write alerts to file
            with open(filepath, 'w') as f:
                json.dump(today_alerts, f, indent=2)
                
        except Exception as e:
            logger.error(f"Error saving alert to file: {str(e)}")
    
    def _email_alert(self, alert):
        """Send alert via email"""
        if not self.email_config:
            logger.warning("Email alerts enabled but configuration missing")
            return
            
        try:
            smtp_server = self.email_config.get('smtp_server')
            smtp_port = self.email_config.get('smtp_port', 587)
            username = self.email_config.get('username')
            password = self.email_config.get('password')
            recipients = self.email_config.get('recipients', [])
            
            if not all([smtp_server, username, password, recipients]):
                logger.warning("Incomplete email configuration, skipping email alert")
                return
                
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = username
            msg['To'] = ", ".join(recipients)
            
            # Set subject based on alert level
            level_prefix = {
                'info': '[INFO]',
                'warning': '[WARNING]',
                'critical': '[CRITICAL]'
            }.get(alert['level'], '[INFO]')
            
            msg['Subject'] = f"Ransomware Detection System: {level_prefix} Alert"
            
            # Create email body
            body = f"""
            Timestamp: {alert['timestamp']}
            Level: {alert['level'].upper()}
            Source: {alert['source'] or 'Unknown'}
            
            {alert['message']}
            """
            
            if alert.get('data'):
                body += f"\nAdditional Details: {json.dumps(alert['data'], indent=2)}"
                
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(username, password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email alert sent to {', '.join(recipients)}")
            
        except Exception as e:
            logger.error(f"Error sending email alert: {str(e)}")
    
    def get_recent_alerts(self, count=10, level=None, source=None):
        """
        Get recent alerts, optionally filtered by level and source
        
        Args:
            count (int): Maximum number of alerts to return
            level (str): Filter by alert level
            source (str): Filter by alert source
            
        Returns:
            list: List of recent alerts
        """
        filtered_alerts = self.alerts
        
        if level:
            filtered_alerts = [a for a in filtered_alerts if a['level'] == level]
            
        if source:
            filtered_alerts = [a for a in filtered_alerts if a['source'] == source]
            
        # Sort by timestamp (newest first) and limit
        return sorted(filtered_alerts, key=lambda x: x['timestamp'], reverse=True)[:count]

if __name__ == "__main__":
    # Test the alert system
    alert_system = AlertSystem(
        alert_level='info',
        alert_methods=['console', 'file']
    )
    
    # Send test alerts
    alert_system.trigger_alert(
        "This is an info message", 
        level='info',
        data={'test_key': 'test_value'}
    )
    
    alert_system.trigger_alert(
        "Suspicious file access detected", 
        level='warning',
        data={
            'file': '/home/user/important.doc',
            'operation': 'encryption',
            'process': 'unknown.exe',
            'timestamp': datetime.now().isoformat()
        }
    )
    
    alert_system.trigger_alert(
        "Multiple ransomware indicators detected!", 
        level='critical',
        data={
            'indicators': {
                'file_encryptions': 58,
                'suspicious_processes': 3,
                'threat_matches': 2
            },
            'affected_files': 'Multiple documents and images',
            'recommended_action': 'Isolate system and investigate immediately'
        }
    )