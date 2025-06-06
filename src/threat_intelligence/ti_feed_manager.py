import requests
import json
import os
import time
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)

class ThreatIntelligenceManager:
    def __init__(self, config_file=None):
        """
        Initialize the threat intelligence manager
        
        Args:
            config_file (str): Path to a JSON configuration file
        """
        self.feeds = []
        self.indicators = {
            'domains': set(),
            'ips': set(),
            'hashes': set(),
            'file_names': set()
        }
        self.last_update = None
        
        # Load config if provided
        if config_file and os.path.exists(config_file):
            self.load_config(config_file)
    
    def load_config(self, config_file):
        """
        Load feed configuration from a JSON file
        
        Args:
            config_file (str): Path to a JSON configuration file
        """
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                
            if 'feeds' in config:
                self.feeds = config['feeds']
                logger.info(f"Loaded {len(self.feeds)} feeds from config")
        except Exception as e:
            logger.error(f"Failed to load config: {str(e)}")
    
    def add_feed(self, name, url, type='generic', api_key=None, headers=None):
        """
        Add a new threat intelligence feed
        
        Args:
            name (str): Name of the feed
            url (str): URL of the feed
            type (str): Type of feed ('generic', 'misp', 'alienvault', etc.)
            api_key (str): API key if required
            headers (dict): Additional headers if required
        """
        feed = {
            'name': name,
            'url': url,
            'type': type,
            'api_key': api_key,
            'headers': headers or {},
            'last_updated': None
        }
        self.feeds.append(feed)
        logger.info(f"Added feed: {name}")
    
    def update_feeds(self):
        """
        Update all configured threat intelligence feeds
        
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.feeds:
            logger.warning("No feeds configured")
            return False
        
        success = False
        for feed in self.feeds:
            try:
                logger.info(f"Updating feed: {feed['name']}")
                
                headers = feed.get('headers', {})
                if feed.get('api_key'):
                    # Add API key to headers based on feed type
                    if feed['type'] == 'misp':
                        headers['Authorization'] = feed['api_key']
                    else:
                        headers['API-Key'] = feed['api_key']
                
                response = requests.get(feed['url'], headers=headers, timeout=30)
                response.raise_for_status()
                
                # Process different feed types
                if feed['type'] == 'generic':
                    self._process_generic_feed(response.text)
                elif feed['type'] == 'misp':
                    self._process_misp_feed(response.json())
                elif feed['type'] == 'alienvault':
                    self._process_alienvault_feed(response.json())
                else:
                    self._process_generic_feed(response.text)
                
                feed['last_updated'] = datetime.now().isoformat()
                success = True
                
            except Exception as e:
                logger.error(f"Failed to update feed {feed['name']}: {str(e)}")
        
        if success:
            self.last_update = datetime.now()
            logger.info(f"Feeds updated successfully. Total indicators: " + 
                       f"domains={len(self.indicators['domains'])}, " +
                       f"ips={len(self.indicators['ips'])}, " +
                       f"hashes={len(self.indicators['hashes'])}, " +
                       f"file_names={len(self.indicators['file_names'])}")
        return success
    
    def _process_generic_feed(self, data):
        """Process a generic text-based feed"""
        for line in data.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            # Try to identify the indicator type
            if '.' in line and not ' ' in line:
                # Simple domain/IP detection
                if all(c.isdigit() or c == '.' for c in line):
                    self.indicators['ips'].add(line)
                else:
                    self.indicators['domains'].add(line)
            elif len(line) == 32 or len(line) == 40 or len(line) == 64:
                # Likely a hash (MD5, SHA1, SHA256)
                self.indicators['hashes'].add(line)
    
    def _process_misp_feed(self, data):
        """Process MISP format feed"""
        try:
            if 'response' in data:
                for event in data['response']:
                    if 'Attribute' in event:
                        for attr in event['Attribute']:
                            if attr['type'] == 'domain':
                                self.indicators['domains'].add(attr['value'])
                            elif attr['type'] == 'ip-dst':
                                self.indicators['ips'].add(attr['value'])
                            elif attr['type'] in ['md5', 'sha1', 'sha256']:
                                self.indicators['hashes'].add(attr['value'])
                            elif attr['type'] == 'filename':
                                self.indicators['file_names'].add(attr['value'])
        except Exception as e:
            logger.error(f"Error processing MISP feed: {str(e)}")
    
    def _process_alienvault_feed(self, data):
        """Process AlienVault OTX format feed"""
        try:
            if 'results' in data:
                for pulse in data['results']:
                    if 'indicators' in pulse:
                        for indicator in pulse['indicators']:
                            if indicator['type'] == 'domain':
                                self.indicators['domains'].add(indicator['indicator'])
                            elif indicator['type'] == 'IPv4':
                                self.indicators['ips'].add(indicator['indicator'])
                            elif indicator['type'] in ['FileHash-MD5', 'FileHash-SHA1', 'FileHash-SHA256']:
                                self.indicators['hashes'].add(indicator['indicator'])
                            elif indicator['type'] == 'file_name':
                                self.indicators['file_names'].add(indicator['indicator'])
        except Exception as e:
            logger.error(f"Error processing AlienVault feed: {str(e)}")
    
    def check_indicators(self, indicators):
        """
        Check if given indicators match any known threat
        
        Args:
            indicators (dict): Dictionary with keys 'domains', 'ips', 'hashes', 'file_names'
            
        Returns:
            list: List of matched indicators
        """
        matches = []
        
        # Check domains
        for domain in indicators.get('domains', []):
            if domain in self.indicators['domains']:
                matches.append({'type': 'domain', 'value': domain})
        
        # Check IPs
        for ip in indicators.get('ips', []):
            if ip in self.indicators['ips']:
                matches.append({'type': 'ip', 'value': ip})
        
        # Check file hashes
        for file_hash in indicators.get('hashes', []):
            if file_hash in self.indicators['hashes']:
                matches.append({'type': 'hash', 'value': file_hash})
        
        # Check file names
        for file_name in indicators.get('file_names', []):
            if file_name in self.indicators['file_names']:
                matches.append({'type': 'file_name', 'value': file_name})
        
        return matches
    
    def save_indicators(self, file_path):
        """
        Save the current indicators to a file
        
        Args:
            file_path (str): Path to save the indicators
        """
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w') as f:
                json.dump({
                    'last_update': self.last_update.isoformat() if self.last_update else None,
                    'domains': list(self.indicators['domains']),
                    'ips': list(self.indicators['ips']),
                    'hashes': list(self.indicators['hashes']),
                    'file_names': list(self.indicators['file_names'])
                }, f, indent=2)
            logger.info(f"Indicators saved to {file_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save indicators: {str(e)}")
            return False
    
    def load_indicators(self, file_path):
        """
        Load indicators from a file
        
        Args:
            file_path (str): Path to load the indicators from
        """
        try:
            if not os.path.exists(file_path):
                logger.warning(f"Indicator file not found: {file_path}")
                return False
                
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            self.last_update = datetime.fromisoformat(data['last_update']) if data.get('last_update') else None
            self.indicators['domains'] = set(data.get('domains', []))
            self.indicators['ips'] = set(data.get('ips', []))
            self.indicators['hashes'] = set(data.get('hashes', []))
            self.indicators['file_names'] = set(data.get('file_names', []))
            
            logger.info(f"Loaded indicators: " + 
                       f"domains={len(self.indicators['domains'])}, " +
                       f"ips={len(self.indicators['ips'])}, " +
                       f"hashes={len(self.indicators['hashes'])}, " +
                       f"file_names={len(self.indicators['file_names'])}")
            return True
        except Exception as e:
            logger.error(f"Failed to load indicators: {str(e)}")
            return False

if __name__ == "__main__":
    # Example usage
    manager = ThreatIntelligenceManager()
    
    # Add some example feeds (use actual feeds in real implementation)
    manager.add_feed(
        name="Example Ransomware Domains",
        url="https://example.com/feeds/ransomware-domains.txt",
        type="generic"
    )
    
    # For testing, add some example indicators
    manager.indicators['domains'].add("ransomware-payment.com")
    manager.indicators['domains'].add("cryptolocker.cn")
    manager.indicators['hashes'].add("44d88612fea8a8f36de82e1278abb02f")
    
    # Test checking indicators
    test_indicators = {
        'domains': ['example.com', 'ransomware-payment.com'],
        'ips': ['192.168.1.1'],
        'hashes': ['44d88612fea8a8f36de82e1278abb02f', 'e99a18c428cb38d5f260853678922e03'],
        'file_names': ['ransomware.exe']
    }
    
    matches = manager.check_indicators(test_indicators)
    print(f"Found {len(matches)} threat matches:")
    for match in matches:
        print(f"  - {match['type']}: {match['value']}")
    
    # Save indicators for future use
    manager.save_indicators("../../data/threat_intel/indicators.json")