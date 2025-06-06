import os
import sys
import logging
import time
import argparse
import json
import signal
import yaml
from datetime import datetime
from threading import Thread

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

# Import project modules
from src.data_collection.file_monitor import start_monitoring, RansomwareDetectionHandler
from src.data_collection.system_monitor import SystemMonitor
from src.ml_model.anomaly_detection import RansomwareBehaviorDetector
from src.threat_intelligence.ti_feed_manager import ThreatIntelligenceManager
from src.response.alert_system import AlertSystem
from src.response.mitigation_actions import MitigationSystem
from src.response.gpio_controller import get_gpio_controller

class RansomwareDetectionSystem:
    """Main class for the Ransomware Detection System"""
    def __init__(self, config_path=None):
        """
        Initialize the ransomware detection system
        
        Args:
            config_path (str): Path to the configuration file
        """
        self.config = self._load_config(config_path)
        self.running = False
        
        # Set up logging
        self._setup_logging()
        
        # Initialize components
        self._init_components()
        
        # Register signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _setup_logging(self):
        """Set up logging based on configuration"""
        log_dir = os.path.abspath(os.path.join(project_root, self.config['system']['data_dir'], 'logs'))
        os.makedirs(log_dir, exist_ok=True)
        
        log_file = os.path.join(log_dir, f"rms_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
        
        # Update logging configuration
        level = logging.DEBUG if self.config['system'].get('debug_mode', False) else logging.INFO
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        logger.info(f"Logging to {log_file}")
        
    def _load_config(self, config_path):
        """Load configuration from YAML file"""
        default_config = {
            'monitoring': {
                'paths': ['/home', '/var'],
                'collection_interval': 5,
                'file_monitor_enabled': True,
                'system_monitor_enabled': True
            },
            'model': {
                'model_path': 'data/models/ransomware_detector.joblib',
                'training_data_path': 'data/training/normal_behavior.json',
                'auto_train': True,
                'detection_threshold': -0.5
            },
            'threat_intelligence': {
                'enabled': True,
                'feeds_config': 'config/ti_feeds.json',
                'indicators_path': 'data/threat_intel/indicators.json',
                'update_interval': 3600
            },
            'response': {
                'alert_level': 'warning',
                'alert_methods': ['console', 'file'],
                'email_alerts': False,
                'email_config': {
                    'smtp_server': 'smtp.example.com',
                    'smtp_port': 587,
                    'username': 'alerts@example.com',
                    'password': '',
                    'recipients': ['admin@example.com']
                },
                'auto_mitigation': False,
                'mitigation_actions': ['isolate_file', 'block_process']
            },
            'system': {
                'data_dir': 'data',
                'debug_mode': False,
                'raspberry_pi': {
                    'gpio_enabled': False,
                    'status_led_pin': 17,
                    'alert_led_pin': 27,
                    'activity_led_pin': 22
                }
            },
            'dashboard': {
                'enabled': True,
                'port': 5000,
                'host': '0.0.0.0',
                'debug': False,
                'max_history_points': 50
            }
        }
        
        # Load user config if provided
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                        user_config = yaml.safe_load(f)
                    else:
                        user_config = json.load(f)
                        
                # Merge configs
                self._deep_update(default_config, user_config)
                logger.info(f"Configuration loaded from {config_path}")
            except Exception as e:
                logger.error(f"Failed to load config from {config_path}: {str(e)}")
        
        # Adjust paths for Windows if needed
        if sys.platform == 'win32':
            if default_config['monitoring']['paths'] == ['/home', '/var']:
                default_config['monitoring']['paths'] = ['C:\\Users', 'C:\\Windows\\Temp']
            
            # Convert paths to absolute paths
            for key in ['model_path', 'training_data_path']:
                default_config['model'][key] = os.path.abspath(os.path.join(
                    project_root, default_config['model'][key].replace('/', os.sep)
                ))
                
            default_config['threat_intelligence']['feeds_config'] = os.path.abspath(os.path.join(
                project_root, default_config['threat_intelligence']['feeds_config'].replace('/', os.sep)
            ))
            
            default_config['threat_intelligence']['indicators_path'] = os.path.abspath(os.path.join(
                project_root, default_config['threat_intelligence']['indicators_path'].replace('/', os.sep)
            ))
            
            default_config['system']['data_dir'] = os.path.abspath(os.path.join(
                project_root, default_config['system']['data_dir'].replace('/', os.sep)
            ))
        
        return default_config
    
    def _deep_update(self, d, u):
        """Recursively update a dict"""
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                self._deep_update(d[k], v)
            else:
                d[k] = v
    
    def _init_components(self):
        """Initialize all system components"""
        try:
            # Initialize alert system first as other components need it
            self.alert_system = AlertSystem(
                alert_level=self.config['response']['alert_level'],
                alert_methods=self.config['response']['alert_methods'],
                email_alerts=self.config['response']['email_alerts'],
                email_config=self.config['response']['email_config']
            )
            
            # Set up GPIO controller if enabled
            if self.config['system']['raspberry_pi']['gpio_enabled']:
                self.gpio_controller = get_gpio_controller()
                logger.info("GPIO controller initialized")
            else:
                self.gpio_controller = None
                logger.info("GPIO controller disabled")
            
            # Initialize mitigation system
            self.mitigation_system = MitigationSystem(
                auto_mitigation=self.config['response']['auto_mitigation'],
                mitigation_actions=self.config['response']['mitigation_actions'],
                alert_system=self.alert_system
            )
            
            # Initialize machine learning model
            model_path = self.config['model']['model_path']
            self.detector = RansomwareBehaviorDetector(model_path=model_path if os.path.exists(model_path) else None)
            
            # Train model if auto_train is enabled and no model exists
            if self.config['model']['auto_train'] and not self.detector.is_trained:
                training_data_path = self.config['model']['training_data_path']
                if os.path.exists(training_data_path):
                    try:
                        with open(training_data_path, 'r') as f:
                            training_data = json.load(f)
                        if self.detector.train(training_data):
                            # Ensure directory exists
                            os.makedirs(os.path.dirname(model_path), exist_ok=True)
                            self.detector.save_model(model_path)
                            logger.info(f"Model trained and saved to {model_path}")
                    except Exception as e:
                        logger.error(f"Failed to load training data: {str(e)}")
                        self._generate_and_train_default_model(model_path)
                else:
                    logger.warning(f"Training data not found at {training_data_path}")
                    self._generate_and_train_default_model(model_path)
            
            # Initialize system monitor
            self.system_monitor = SystemMonitor(
                anomaly_detector=self.detector,
                collection_interval=self.config['monitoring']['collection_interval']
            )
            
            # Initialize threat intelligence manager
            ti_config_path = self.config['threat_intelligence']['feeds_config']
            self.ti_manager = ThreatIntelligenceManager(
                config_file=ti_config_path if os.path.exists(ti_config_path) and self.config['threat_intelligence']['enabled'] else None
            )
            
            # Load existing indicators if available
            indicators_path = self.config['threat_intelligence']['indicators_path']
            if os.path.exists(indicators_path):
                self.ti_manager.load_indicators(indicators_path)
                logger.info(f"Loaded threat indicators from {indicators_path}")
            
            # Set up dashboard if enabled
            if self.config['dashboard']['enabled']:
                try:
                    from src.dashboard.app import app as dashboard_app
                    self.dashboard_app = dashboard_app
                    logger.info("Dashboard initialized")
                except ImportError as e:
                    logger.error(f"Failed to import dashboard: {str(e)}")
                    self.dashboard_app = None
            else:
                self.dashboard_app = None
                
            logger.info("All components initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize components: {str(e)}")
            raise
    
    def _generate_and_train_default_model(self, model_path):
        """Generate and train a model with default data when no training data is available"""
        try:
            # Generate default training data
            default_data = self.detector.generate_default_training_data()
            
            # Train model with default data
            if self.detector.train(default_data):
                # Save the training data for future use
                training_data_path = self.config['model']['training_data_path']
                os.makedirs(os.path.dirname(training_data_path), exist_ok=True)
                with open(training_data_path, 'w') as f:
                    json.dump(default_data, f, indent=2)
                logger.info(f"Default training data saved to {training_data_path}")
                
                # Save the model
                os.makedirs(os.path.dirname(model_path), exist_ok=True)
                self.detector.save_model(model_path)
                logger.info(f"Model trained with default data and saved to {model_path}")
            else:
                logger.error("Failed to train model with default data")
        except Exception as e:
            logger.error(f"Error generating default model: {str(e)}")
    
    def start(self):
        """Start the ransomware detection system"""
        if self.running:
            logger.warning("System is already running")
            return
            
        logger.info("Starting ransomware detection system...")
        self.running = True
        
        # Set status LED if GPIO is available
        if self.gpio_controller:
            self.gpio_controller.set_status_led(True)
            logger.info("Status LED activated")
        
        # Start system monitoring if enabled
        if self.config['monitoring']['system_monitor_enabled']:
            self.system_monitor.start()
            logger.info("System monitoring started")
        
        # Start file monitoring in a separate thread if enabled
        if self.config['monitoring']['file_monitor_enabled']:
            self.file_monitor_thread = Thread(
                target=start_monitoring,
                args=(self.config['monitoring']['paths'], self.alert_system)
            )
            self.file_monitor_thread.daemon = True
            self.file_monitor_thread.start()
            logger.info(f"File monitoring started for paths: {', '.join(self.config['monitoring']['paths'])}")
        
        # Start threat intelligence updates if enabled
        if self.config['threat_intelligence']['enabled']:
            self.ti_manager.update_feeds()
            logger.info("Threat intelligence feeds updated")
            
            # Schedule regular updates
            from threading import Timer
            def update_ti():
                if self.running:
                    self.ti_manager.update_feeds()
                    self.ti_timer = Timer(self.config['threat_intelligence']['update_interval'], update_ti)
                    self.ti_timer.daemon = True
                    self.ti_timer.start()
                    
            self.ti_timer = Timer(self.config['threat_intelligence']['update_interval'], update_ti)
            self.ti_timer.daemon = True
            self.ti_timer.start()
        
        # Start dashboard if enabled
        if self.dashboard_app:
            self.dashboard_thread = Thread(
                target=self._run_dashboard,
                args=(self.config['dashboard']['host'], self.config['dashboard']['port'], self.config['dashboard']['debug'])
            )
            self.dashboard_thread.daemon = True
            self.dashboard_thread.start()
            logger.info(f"Dashboard started at http://{self.config['dashboard']['host']}:{self.config['dashboard']['port']}")
        
        logger.info("Ransomware detection system started and running")
        
        # Signal successful start
        if self.gpio_controller:
            self.gpio_controller.blink_led('status_led', count=2, interval=0.2)
        
        # Keep the main thread running
        try:
            while self.running:
                time.sleep(1)
                
                # Simulate activity LED if GPIO is available
                if self.gpio_controller and self.config['monitoring']['system_monitor_enabled']:
                    # Brief activity flash every 5 seconds
                    if int(time.time()) % 5 == 0:
                        self.gpio_controller.blink_led('activity_led', count=1, interval=0.1)
        except KeyboardInterrupt:
            self.stop()
    
    def _run_dashboard(self, host, port, debug):
        """Run the dashboard app in a separate thread"""
        try:
            self.dashboard_app.run(host=host, port=port, debug=debug, use_reloader=False)
        except Exception as e:
            logger.error(f"Dashboard error: {str(e)}")
    
    def stop(self):
        """Stop the ransomware detection system"""
        if not self.running:
            return
            
        logger.info("Stopping ransomware detection system...")
        self.running = False
        
        # Turn off status LED if GPIO is available
        if self.gpio_controller:
            self.gpio_controller.set_status_led(False)
            self.gpio_controller.cleanup()
        
        # Stop system monitoring
        if hasattr(self, 'system_monitor'):
            self.system_monitor.stop()
        
        # Save threat intelligence indicators
        if hasattr(self, 'ti_manager'):
            indicators_path = self.config['threat_intelligence']['indicators_path']
            os.makedirs(os.path.dirname(indicators_path), exist_ok=True)
            self.ti_manager.save_indicators(indicators_path)
        
        # Save metrics
        if hasattr(self, 'system_monitor'):
            metrics_path = os.path.join(
                self.config['system']['data_dir'],
                'metrics',
                f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            # Add metrics saving logic here
        
        logger.info("Ransomware detection system stopped")
    
    def _signal_handler(self, sig, frame):
        """Handle termination signals"""
        logger.info(f"Received signal {sig}, shutting down...")
        self.stop()

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='Ransomware Detection System')
    parser.add_argument('-c', '--config', help='Path to configuration file')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--safe-dirs', action='store_true', help='Use safe directories for monitoring (no admin privileges required)')
    args = parser.parse_args()
    
    try:
        # Create instance and start system
        system = RansomwareDetectionSystem(config_path=args.config)
        
        # Override debug setting if specified
        if args.debug:
            system.config['system']['debug_mode'] = True
            logging.getLogger().setLevel(logging.DEBUG)
        
        # Use safe directories if specified
        if args.safe_dirs:
            user_dir = os.path.expanduser("~")
            documents_dir = os.path.join(user_dir, "Documents")
            desktop_dir = os.path.join(user_dir, "Desktop")
            download_dir = os.path.join(user_dir, "Downloads")
            
            safe_dirs = []
            for dir_path in [documents_dir, desktop_dir, download_dir]:
                if os.path.exists(dir_path):
                    safe_dirs.append(dir_path)
            
            if safe_dirs:
                system.config['monitoring']['paths'] = safe_dirs
                logger.info(f"Using safe directories for monitoring: {', '.join(safe_dirs)}")
            else:
                project_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
                system.config['monitoring']['paths'] = [project_dir]
                logger.info(f"Using project directory for monitoring: {project_dir}")
        
        # Start the system
        system.start()
    except Exception as e:
        logger.error(f"Error starting system: {str(e)}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
