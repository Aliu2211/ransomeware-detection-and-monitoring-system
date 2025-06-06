from flask import Flask, render_template, jsonify, request, redirect, url_for
import os
import json
import time
import logging
from datetime import datetime, timedelta
import threading
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import io
import base64
import numpy as np
import shutil  # Add this import for file operations
from src.response.mitigation_actions import MitigationSystem  # Fix this import path

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add project root to path
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ransomware-detection-system'

# Initialize MitigationSystem with your app globals
mitigation_system = MitigationSystem(
    auto_mitigation=True, 
    mitigation_actions=['isolate_file', 'block_process', 'block_network']
)

# Global variables
system_status = {
    'running': False,
    'monitoring_since': None,
    'file_monitor': False,
    'system_monitor': False,
    'threat_intel': False,
    'last_update': datetime.now().isoformat()
}

metrics = {
    'file_operations': 0,
    'suspicious_events': 0,
    'alerts_triggered': 0,
    'threats_mitigated': 0,
    'cpu_usage': 0,
    'memory_usage': 0,
    'disk_usage': 0
}

alerts = []
activity_log = []
metrics_history = {
    'timestamps': [],
    'cpu': [],
    'memory': [],
    'disk_write': [],
    'file_ops': []
}

# Maximum history points to store
MAX_HISTORY = 50

# Paths
data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', 'data'))
alerts_dir = os.path.join(data_dir, 'alerts')
logs_dir = os.path.join(data_dir, 'logs')
quarantine_dir = os.path.join(data_dir, 'quarantine')

# Ensure directories exist
for dir_path in [alerts_dir, logs_dir, quarantine_dir]:
    os.makedirs(dir_path, exist_ok=True)

# Functions to load data
def load_alerts(max_alerts=100):
    """Load recent alerts from files"""
    global alerts
    alerts = []
    
    try:
        alert_files = sorted([f for f in os.listdir(alerts_dir) if f.startswith('alerts_')])[-5:]
        
        for file in alert_files:
            file_path = os.path.join(alerts_dir, file)
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        file_alerts = json.load(f)
                        alerts.extend(file_alerts)
                except Exception as e:
                    logger.error(f"Error reading alert file {file}: {str(e)}")
        
        # Sort by timestamp (newest first) and limit
        alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        alerts = alerts[:max_alerts]
        
        # Update metrics
        metrics['alerts_triggered'] = len(alerts)
        
    except Exception as e:
        logger.error(f"Error loading alerts: {str(e)}")

def load_activity_log(max_entries=100):
    """Load system activity logs"""
    global activity_log
    activity_log = []
    
    try:
        # Find the most recent log file
        log_files = sorted([f for f in os.listdir(logs_dir) if f.endswith('.log')])
        if not log_files:
            return
            
        # Read the last few lines from the most recent log
        log_file = os.path.join(logs_dir, log_files[-1])
        with open(log_file, 'r') as f:
            lines = f.readlines()[-max_entries:]
            
        for line in lines:
            # Parse log lines
            if ' - ' in line:
                timestamp = line.split(' - ')[0].strip()
                message = ' - '.join(line.split(' - ')[1:]).strip()
                
                activity_log.append({
                    'timestamp': timestamp,
                    'message': message
                })
        
    except Exception as e:
        logger.error(f"Error loading activity log: {str(e)}")

def load_quarantined_files():
    """Load information about quarantined files"""
    quarantined = []
    
    try:
        if os.path.exists(quarantine_dir):
            files = [f for f in os.listdir(quarantine_dir) if not f.endswith('.meta')]
            
            for filename in files:
                meta_path = os.path.join(quarantine_dir, f"{filename}.meta")
                if os.path.exists(meta_path):
                    with open(meta_path, 'r') as f:
                        metadata = json.load(f)
                        
                    quarantined.append({
                        'filename': filename,
                        'original_path': metadata.get('original_path', 'Unknown'),
                        'quarantined_at': metadata.get('quarantined_at', 'Unknown'),
                        'reason': metadata.get('reason', 'Unknown'),
                        'checksum': metadata.get('checksum', 'Unknown')
                    })
    except Exception as e:
        logger.error(f"Error loading quarantined files: {str(e)}")
        
    return quarantined

def load_threat_intel():
    """Load threat intelligence information"""
    intel = {
        'last_update': 'Never',
        'indicators': {
            'domains': 0,
            'ips': 0,
            'hashes': 0,
            'file_names': 0
        },
        'feeds': []
    }
    
    try:
        indicators_path = os.path.join(data_dir, 'threat_intel', 'indicators.json')
        if os.path.exists(indicators_path):
            with open(indicators_path, 'r') as f:
                data = json.load(f)
                
                if 'last_update' in data:
                    intel['last_update'] = data['last_update']
                
                intel['indicators']['domains'] = len(data.get('domains', []))
                intel['indicators']['ips'] = len(data.get('ips', []))
                intel['indicators']['hashes'] = len(data.get('hashes', []))
                intel['indicators']['file_names'] = len(data.get('file_names', []))
    except Exception as e:
        logger.error(f"Error loading threat intelligence: {str(e)}")
        
    return intel

def save_alerts():
    """Save current alerts to a file"""
    try:
        if not alerts:  # Don't save if empty
            return
            
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"alerts_{timestamp}.json"
        filepath = os.path.join(alerts_dir, filename)
        
        # Write alerts to file
        with open(filepath, 'w') as f:
            json.dump(alerts, f, indent=2)
            
        logger.info(f"Saved {len(alerts)} alerts to {filepath}")
    except Exception as e:
        logger.error(f"Error saving alerts: {str(e)}")

def save_activity_log():
    """Save activity log to a file"""
    try:
        if not activity_log:  # Don't save if empty
            return
            
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"activity_{timestamp}.log"
        filepath = os.path.join(logs_dir, filename)
        
        # Write log entries to file
        with open(filepath, 'w') as f:
            for entry in activity_log:
                # Format: timestamp - message
                f.write(f"{entry.get('timestamp', 'Unknown')} - {entry.get('message', 'No message')}\n")
                
        logger.info(f"Saved {len(activity_log)} log entries to {filepath}")
    except Exception as e:
        logger.error(f"Error saving activity log: {str(e)}")

def update_system_metrics():
    """Update system metrics from current state"""
    try:
        # In a real system, these would come from the actual monitoring components
        # For this example, we'll generate some simulated data
        import psutil
        
        metrics['cpu_usage'] = psutil.cpu_percent()
        metrics['memory_usage'] = psutil.virtual_memory().percent
        metrics['disk_usage'] = psutil.disk_usage('/').percent
        
        # Add to history
        now = datetime.now().isoformat()
        metrics_history['timestamps'].append(now)
        metrics_history['cpu'].append(metrics['cpu_usage'])
        metrics_history['memory'].append(metrics['memory_usage'])
        metrics_history['disk_write'].append(np.random.randint(100, 5000))  # Simulated disk write rate
        metrics_history['file_ops'].append(metrics['file_operations'])
        
        # Limit history length
        if len(metrics_history['timestamps']) > MAX_HISTORY:
            metrics_history['timestamps'] = metrics_history['timestamps'][-MAX_HISTORY:]
            metrics_history['cpu'] = metrics_history['cpu'][-MAX_HISTORY:]
            metrics_history['memory'] = metrics_history['memory'][-MAX_HISTORY:]
            metrics_history['disk_write'] = metrics_history['disk_write'][-MAX_HISTORY:]
            metrics_history['file_ops'] = metrics_history['file_ops'][-MAX_HISTORY:]
            
    except Exception as e:
        logger.error(f"Error updating system metrics: {str(e)}")

def generate_chart():
    """Generate a system metrics chart"""
    try:
        plt.figure(figsize=(10, 6))
        
        timestamps = [datetime.fromisoformat(ts).strftime('%H:%M:%S') for ts in metrics_history['timestamps'][-20:]]
        cpu_values = metrics_history['cpu'][-20:]
        memory_values = metrics_history['memory'][-20:]
        
        plt.plot(timestamps, cpu_values, 'b-', label='CPU Usage (%)')
        plt.plot(timestamps, memory_values, 'g-', label='Memory Usage (%)')
        
        plt.title('System Resource Usage')
        plt.xlabel('Time')
        plt.ylabel('Percentage (%)')
        plt.legend()
        plt.grid(True)
        plt.xticks(rotation=45)
        plt.tight_layout()
        
        # Convert plot to base64 string for embedding in HTML
        buf = io.BytesIO()
        plt.savefig(buf, format='png')
        buf.seek(0)
        chart = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()
        plt.close()
        
        return chart
    except Exception as e:
        logger.error(f"Error generating chart: {str(e)}")
        return None

def background_task():
    """Background task to update data periodically"""
    while True:
        try:
            load_alerts()
            load_activity_log()
            update_system_metrics()
            
            # Simulate some file operations for demonstration
            if system_status['running']:
                metrics['file_operations'] += np.random.randint(0, 5)
                
                # Occasionally add a suspicious event
                if np.random.random() < 0.1:
                    metrics['suspicious_events'] += 1
            
            system_status['last_update'] = datetime.now().isoformat()
            
        except Exception as e:
            logger.error(f"Error in background task: {str(e)}")
            
        time.sleep(5)  # Update every 5 seconds

# Start background task
background_thread = threading.Thread(target=background_task)
background_thread.daemon = True
background_thread.start()

# Routes
@app.route('/')
def index():
    """Dashboard home page"""
    # Reload alerts and activity logs from disk
    load_alerts()  
    load_activity_log()
    
    return render_template('index.html', 
                          system_status=system_status,
                          metrics=metrics,
                          alerts=alerts[:5],
                          activity_log=activity_log[:10],
                          chart=generate_chart())

@app.route('/alerts')
def view_alerts():
    """Alerts page"""
    return render_template('alerts.html',
                          alerts=alerts,
                          system_status=system_status)

@app.route('/activity')
def view_activity():
    """Activity log page"""
    return render_template('activity.html',
                          activity_log=activity_log,
                          system_status=system_status)

@app.route('/settings')
def view_settings():
    """Settings page"""
    return render_template('settings.html',
                          system_status=system_status)

@app.route('/quarantine')
def quarantine_page():
    """Quarantine page"""
    quarantine_items = load_quarantined_files()
    return render_template('quarantine.html',
                          quarantine_items=quarantine_items, 
                          system_status=system_status)

@app.route('/api/status')
def api_status():
    """API endpoint for system status"""
    return jsonify({
        'system_status': system_status,
        'metrics': metrics
    })

@app.route('/api/alerts')
def api_alerts():
    """API endpoint for alerts"""
    return jsonify(alerts)

@app.route('/api/chart')
def api_chart():
    """API endpoint for chart data"""
    return jsonify({
        'chart': generate_chart()
    })

@app.route('/api/toggle_system', methods=['POST'])
def api_toggle_system():
    """Toggle system on/off"""
    system_status['running'] = not system_status['running']
    
    if system_status['running']:
        system_status['monitoring_since'] = datetime.now().isoformat()
        system_status['file_monitor'] = True
        system_status['system_monitor'] = True
        system_status['threat_intel'] = True
    else:
        system_status['file_monitor'] = False
        system_status['system_monitor'] = False
        system_status['threat_intel'] = False
    
    return jsonify({'success': True, 'running': system_status['running']})

@app.route('/api/reset_metrics', methods=['POST'])
def api_reset_metrics():
    """Reset system metrics"""
    metrics['file_operations'] = 0
    metrics['suspicious_events'] = 0
    
    return jsonify({'success': True})

@app.route('/api/quarantine/restore/<filename>', methods=['POST'])
def restore_quarantined_file(filename):
    # Logic to restore a quarantined file
    quarantine_path = os.path.join(quarantine_dir, filename)
    result = {"success": False}
    
    try:
        # Read metadata to find original path
        with open(f"{quarantine_path}.meta", 'r') as f:
            metadata = json.load(f)
        
        original_path = metadata.get('original_path')
        if os.path.exists(original_path):
            # Original path exists, create a restored copy with new name
            restore_path = f"{original_path}.restored"
        else:
            restore_path = original_path
            
        # Copy file back to original/new location
        shutil.copy2(quarantine_path, restore_path)
        result = {
            "success": True, 
            "message": f"File restored to {restore_path}",
            "path": restore_path
        }
        
    except Exception as e:
        result["error"] = str(e)
        
    return jsonify(result)

@app.route('/api/mitigation/action', methods=['POST'])
def take_mitigation_action():
    data = request.json
    action_type = data.get('action')
    result = {"success": False}
    
    try:
        if action_type == 'quarantine_file':
            file_path = data.get('path')
            reason = data.get('reason', 'Manual quarantine')
            result = mitigation_system.quarantine_file(file_path, reason)
        elif action_type == 'terminate_process':
            pid = int(data.get('pid'))
            reason = data.get('reason', 'Manual termination')
            result = mitigation_system.terminate_process(pid, reason)
        elif action_type == 'block_connection':
            ip = data.get('ip')
            reason = data.get('reason', 'Manual block')
            result = mitigation_system.block_connection(ip, reason)
        else:
            result["error"] = "Unknown action type"
    except Exception as e:
        result["error"] = str(e)
        
    return jsonify(result)

# Add these API endpoints after your existing route definitions

@app.route('/api/update_monitoring', methods=['POST'])
def api_update_monitoring():
    """Update monitoring settings"""
    try:
        data = request.get_json()
        system_status['file_monitor'] = data.get('file_monitor', False)
        system_status['system_monitor'] = data.get('system_monitor', False)
        system_status['network_monitor'] = data.get('network_monitor', False)
        system_status['threat_intel'] = data.get('threat_intel', False)
        system_status['last_update'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log the change
        log_entry = f"Updated monitoring settings: file={data.get('file_monitor')}, system={data.get('system_monitor')}, network={data.get('network_monitor')}"
        activity_log.insert(0, {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": log_entry,
            "type": "system",
            "type_color": "secondary"
        })
        
        save_activity_log()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/update_mitigation', methods=['POST'])
def api_update_mitigation():
    """Update mitigation settings"""
    try:
        data = request.get_json()
        system_status['auto_mitigation'] = data.get('auto_mitigation', False)
        system_status['mitigation_actions'] = data.get('actions', [])
        system_status['last_update'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log the change
        log_entry = f"Updated mitigation settings: auto={data.get('auto_mitigation')}, actions={','.join(data.get('actions', []))}"
        activity_log.insert(0, {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": log_entry,
            "type": "system",
            "type_color": "secondary"
        })
        
        save_activity_log()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/update_config', methods=['POST'])
def api_update_config():
    """Update system configuration"""
    try:
        data = request.get_json()
        system_status['alert_threshold'] = data.get('alert_threshold', 'medium')
        system_status['scan_frequency'] = data.get('scan_frequency', 'daily')
        system_status['log_retention'] = data.get('log_retention', '30')
        system_status['update_frequency'] = data.get('update_frequency', 'daily')
        system_status['last_update'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Log the change
        log_entry = "Updated system configuration settings"
        activity_log.insert(0, {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": log_entry,
            "type": "system",
            "type_color": "secondary"
        })
        
        save_activity_log()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/clear_all_data', methods=['POST'])
def api_clear_all_data():
    """Clear all monitoring data"""
    try:
        global alerts, activity_log, metrics
        # Clear alerts
        alerts = []
        save_alerts()
        
        # Clear activity log
        activity_log = []
        save_activity_log()
        
        # Reset metrics
        metrics = {
            "suspicious_events": 0,
            "alerts_triggered": 0,
            "threats_mitigated": 0
        }
        
        # Log the action
        activity_log.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": "All monitoring data has been cleared",
            "type": "system",
            "type_color": "warning"
        })
        save_activity_log()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/reset_settings', methods=['POST'])
def api_reset_settings():
    """Reset to default settings"""
    try:
        # Reset to defaults
        system_status.update({
            'running': True,
            'last_update': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'file_monitor': True,
            'system_monitor': True,
            'network_monitor': True,
            'threat_intel': True,
            'auto_mitigation': False,
            'mitigation_actions': ['isolate_file', 'block_process', 'block_network'],
            'alert_threshold': 'medium',
            'scan_frequency': 'daily',
            'log_retention': '30',
            'update_frequency': 'daily'
        })
        
        # Log the action
        activity_log.insert(0, {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "message": "System settings have been reset to defaults",
            "type": "system",
            "type_color": "warning"
        })
        save_activity_log()
        
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# HTML Templates
@app.route('/templates/index.html')
def template_index():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Ransomware Detection System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/css/bootstrap.min.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        .status-card {
            transition: all 0.3s;
        }
        .system-on {
            background-color: #d4edda;
            border-color: #c3e6cb;
        }
        .system-off {
            background-color: #f8d7da;
            border-color: #f5c6cb;
        }
        .chart-container {
            height: 350px;
        }
        .alert-danger {
            animation: alert-blink 2s infinite;
        }
        @keyframes alert-blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.8; }
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">RMS Dashboard</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link active" href="/">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/alerts">Alerts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/activity">Activity Log</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/quarantine">Quarantine</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/settings">Settings</a>
                    </li>
                </ul>
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <span class="nav-link" id="system-time">{{ system_status.last_update }}</span>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row">
            <div class="col-md-4 mb-4">
                <div class="card status-card {{ 'system-on' if system_status.running else 'system-off' }}" id="status-card">
                    <div class="card-header">
                        <h5 class="card-title">System Status</h5>
                    </div>
                    <div class="card-body">
                        <h2 class="text-center mb-3">{{ 'RUNNING' if system_status.running else 'STOPPED' }}</h2>
                        <div class="d-grid gap-2">
                            <button id="toggle-system" class="btn {{ 'btn-danger' if system_status.running else 'btn-success' }}">
                                {{ 'Stop System' if system_status.running else 'Start System' }}
                            </button>
                        </div>
                        <hr>
                        <ul class="list-group">
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                File Monitoring
                                <span class="badge {{ 'bg-success' if system_status.file_monitor else 'bg-danger' }}">
                                    {{ 'ACTIVE' if system_status.file_monitor else 'INACTIVE' }}
                                </span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                System Monitoring
                                <span class="badge {{ 'bg-success' if system_status.system_monitor else 'bg-danger' }}">
                                    {{ 'ACTIVE' if system_status.system_monitor else 'INACTIVE' }}
                                </span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                Threat Intelligence
                                <span class="badge {{ 'bg-success' if system_status.threat_intel else 'bg-danger' }}">
                                    {{ 'ACTIVE' if system_status.threat_intel else 'INACTIVE' }}
                                </span>
                            </li>
                        </ul>
                    </div>
                    <div class="card-footer text-muted" id="monitoring-since">
                        {% if system_status.monitoring_since %}
                            Monitoring since: {{ system_status.monitoring_since }}
                        {% else %}
                            System is not active
                        {% endif %}
                    </div>
                </div>
            </div>

            <div class="col-md-8 mb-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between">
                        <h5 class="card-title">System Metrics</h5>
                        <button id="refresh-chart" class="btn btn-sm btn-primary">Refresh</button>
                    </div>
                    <div class="card-body chart-container">
                        <img src="data:image/png;base64,{{ chart }}" id="metrics-chart" class="img-fluid" alt="System Metrics Chart">
                    </div>
                    <div class="card-footer">
                        <div class="row">
                            <div class="col-md-3 text-center">
                                <h6>CPU</h6>
                                <h4 id="cpu-usage">{{ metrics.cpu_usage }}%</h4>
                            </div>
                            <div class="col-md-3 text-center">
                                <h6>Memory</h6>
                                <h4 id="memory-usage">{{ metrics.memory_usage }}%</h4>
                            </div>
                            <div class="col-md-3 text-center">
                                <h6>Disk</h6>
                                <h4 id="disk-usage">{{ metrics.disk_usage }}%</h4>
                            </div>
                            <div class="col-md-3 text-center">
                                <h6>File Ops</h6>
                                <h4 id="file-operations">{{ metrics.file_operations }}</h4>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between">
                        <h5 class="card-title">Recent Alerts</h5>
                        <a href="/alerts" class="btn btn-sm btn-primary">View All</a>
                    </div>
                    <div class="card-body" style="max-height: 300px; overflow-y: auto;">
                        <div id="alerts-container">
                            {% if alerts %}
                                {% for alert in alerts[:5] %}
                                    <div class="alert {{ 'alert-danger' if alert.level == 'critical' else 'alert-warning' if alert.level == 'warning' else 'alert-info' }}">
                                        <strong>{{ alert.timestamp }}</strong><br>
                                        {{ alert.message }}
                                    </div>
                                {% endfor %}
                            {% else %}
                                <div class="alert alert-info">No alerts recorded</div>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-6 mb-4">
                <div class="card">
                    <div class="card-header d-flex justify-content-between">
                        <h5 class="card-title">Activity Log</h5>
                        <a href="/activity" class="btn btn-sm btn-primary">View All</a>
                    </div>
                    <div class="card-body" style="max-height: 300px; overflow-y: auto;">
                        <div id="activity-container">
                            {% if activity_log %}
                                {% for entry in activity_log[:10] %}
                                    <div class="mb-2">
                                        <small class="text-muted">{{ entry.timestamp }}</small><br>
                                        {{ entry.message }}
                                    </div>
                                    <hr class="my-2">
                                {% endfor %}
                            {% else %}
                                <div class="alert alert-info">No activity recorded</div>
                            {% endif %}
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="row">
            <div class="col-md-4 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="card-title">Detection Summary</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-6 text-center mb-3">
                                <h6>Suspicious Events</h6>
                                <h3 id="suspicious-events">{{ metrics.suspicious_events }}</h3>
                            </div>
                            <div class="col-6 text-center mb-3">
                                <h6>Alerts Triggered</h6>
                                <h3 id="alerts-triggered">{{ metrics.alerts_triggered }}</h3>
                            </div>
                            <div class="col-6 text-center">
                                <h6>Threats Mitigated</h6>
                                <h3 id="threats-mitigated">{{ metrics.threats_mitigated }}</h3>
                            </div>
                            <div class="col-6 text-center">
                                <button id="reset-metrics" class="btn btn-sm btn-secondary">Reset Counters</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="col-md-8 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h5 class="card-title">Quick Actions</h5>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-4 mb-2">
                                <div class="d-grid">
                                    <a href="/quarantine" class="btn btn-primary">View Quarantine</a>
                                </div>
                            </div>
                            <div class="col-md-4 mb-2">
                                <div class="d-grid">
                                    <a href="/settings" class="btn btn-secondary">System Settings</a>
                                </div>
                            </div>
                            <div class="col-md-4 mb-2">
                                <div class="d-grid">
                                    <button class="btn btn-info" id="update-intelligence">Update Intelligence</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/js/bootstrap.bundle.min.js"></script>
    <script>
        // Update system time
        function updateTime() {
            const now = new Date();
            document.getElementById('system-time').textContent = now.toLocaleString();
        }
        setInterval(updateTime, 1000);
        updateTime();

        // Toggle system button
        document.getElementById('toggle-system').addEventListener('click', function() {
            fetch('/api/toggle_system', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    location.reload();
                }
            });
        });

        // Reset metrics button
        document.getElementById('reset-metrics').addEventListener('click', function() {
            fetch('/api/reset_metrics', {
                method: 'POST'
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.getElementById('suspicious-events').textContent = '0';
                    document.getElementById('file-operations').textContent = '0';
                }
            });
        });

        // Refresh chart
        document.getElementById('refresh-chart').addEventListener('click', function() {
            fetch('/api/chart')
            .then(response => response.json())
            .then(data => {
                document.getElementById('metrics-chart').src = 'data:image/png;base64,' + data.chart;
            });
        });

        // Update dashboard data periodically
        setInterval(function() {
            fetch('/api/status')
            .then(response => response.json())
            .then(data => {
                document.getElementById('cpu-usage').textContent = data.metrics.cpu_usage + '%';
                document.getElementById('memory-usage').textContent = data.metrics.memory_usage + '%';
                document.getElementById('disk-usage').textContent = data.metrics.disk_usage + '%';
                document.getElementById('file-operations').textContent = data.metrics.file_operations;
                document.getElementById('suspicious-events').textContent = data.metrics.suspicious_events;
                document.getElementById('alerts-triggered').textContent = data.metrics.alerts_triggered;
                document.getElementById('threats-mitigated').textContent = data.metrics.threats_mitigated;
            });
        }, 5000);
    </script>
</body>
</html>
"""

@app.route('/templates/alerts.html')
def template_alerts():
    return """
<!DOCTYPE html>
<html>
<head>
    <title>Alerts - Ransomware Detection System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/css/bootstrap.min.css">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        .alert-critical {
            background-color: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
        }
        .alert-warning {
            background-color: #fff3cd;
            border-color: #ffecb5;
            color: #856404;
        }
        .alert-info {
            background-color: #d1ecf1;
            border-color: #bee5eb;
            color: #0c5460;
        }
        .alert-card {
            transition: all 0.2s;
        }
        .alert-card:hover {
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">RMS Dashboard</a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <li class="nav-item">
                        <a class="nav-link" href="/">Dashboard</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="/alerts">Alerts</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/activity">Activity Log</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/quarantine">Quarantine</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="/settings">Settings</a>
                    </li>
                </ul>
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <span class="nav-link" id="system-time">{{ system_status.last_update }}</span>
                    </li>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container mt-4">
        <div class="row mb-4">
            <div class="col">
                <h1>System Alerts</h1>
                <p>View and manage alerts generated by the ransomware detection system.</p>
            </div>
        </div>

        <div class="row mb-3">
            <div class="col-md-6">
                <div class="input-group">
                    <input type="text" id="alert-search" class="form-control" placeholder="Search alerts...">
                    <button class="btn btn-outline-secondary" type="button" id="search-btn">Search</button>
                </div>
            </div>
            <div class="col-md-3">
                <select id="level-filter" class="form-select">
                    <option value="all">All Levels</option>
                    <option value="critical">Critical</option>
                    <option value="warning">Warning</option>
                    <option value="info">Info</option>
                </select>
            </div>
            <div class="col-md-3">
                <button id="refresh-alerts" class="btn btn-primary w-100">Refresh Alerts</button>
            </div>
        </div>

        <div class="row">
            <div class="col">
                <div id="alerts-container">
                    {% if alerts %}
                        {% for alert in alerts %}
                            <div class="card mb-3 alert-card alert-{{ alert.level }}">
                                <div class="card-header d-flex justify-content-between">
                                    <span class="fw-bold text-uppercase">{{ alert.level }}</span>
                                    <span>{{ alert.timestamp }}</span>
                                </div>
                                <div class="card-body">
                                    <p class="card-text">{{ alert.message }}</p>
                                    {% if alert.details %}
                                        <hr>
                                        <small>{{ alert.details }}</small>
                                    {% endif %}
                                </div>
                                <div class="card-footer">
                                    <div class="d-flex justify-content-end">
                                        <button class="btn btn-sm btn-secondary me-2">Mark Resolved</button>
                                        <button class="btn btn-sm btn-danger">Delete</button>
                                    </div>
                                </div>
                            </div>
                        {% endfor %}
                    {% else %}
                        <div class="alert alert-info">No alerts found.</div>
                    {% endif %}
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.1.3/js/bootstrap.bundle.min.js"></script>
    <script>
        // Update system time
        function updateTime() {
            const now = new Date();
            document.getElementById('system-time').textContent = now.toLocaleString();
        }
        setInterval(updateTime, 1000);
        updateTime();
        
        // Alert filtering
        document.getElementById('search-btn').addEventListener('click', filterAlerts);
        document.getElementById('level-filter').addEventListener('change', filterAlerts);
        
        function filterAlerts() {
            const searchTerm = document.getElementById('alert-search').value.toLowerCase();
            const levelFilter = document.getElementById('level-filter').value;
            
            const alerts = document.querySelectorAll('.alert-card');
            alerts.forEach(alert => {
                const level = alert.classList.contains('alert-critical') ? 'critical' : 
                             alert.classList.contains('alert-warning') ? 'warning' : 'info';
                const text = alert.textContent.toLowerCase();
                
                const levelMatch = levelFilter === 'all' || level === levelFilter;
                const textMatch = searchTerm === '' || text.includes(searchTerm);
                
                alert.style.display = levelMatch && textMatch ? 'block' : 'none';
            });
        }
        
        // Refresh alerts
        document.getElementById('refresh-alerts').addEventListener('click', function() {
            location.reload();
        });
    </script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)