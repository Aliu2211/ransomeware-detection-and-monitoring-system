# Ransomware Monitoring System (RMS)

![RMS Logo](docs/images/rms_logo.png) <!-- You can create and add a logo later -->

A comprehensive real-time ransomware detection and mitigation system with a web dashboard, built using Python.

## Overview

The Ransomware Monitoring System (RMS) is designed to detect and mitigate ransomware attacks in real-time. It uses machine learning, file system monitoring, and system resource analysis to identify suspicious activities that may indicate ransomware behavior.

### Key Features

- **Real-time Monitoring**: Detects file operations, system resource usage, and network activities
- **Machine Learning**: Uses anomaly detection to identify unusual system behavior
- **Threat Intelligence**: Integrates with threat feeds to identify known malicious indicators
- **Web Dashboard**: Provides a visual interface for monitoring and management
- **Alerting System**: Sends notifications via multiple channels when threats are detected
- **Mitigation**: Automatically quarantines suspicious files and can block processes
- **Raspberry Pi Support**: Optional LED indicators for physical status display

## System Requirements

- Python 3.8+ 
- Windows, macOS, or Linux operating system
- 4GB RAM minimum (8GB recommended)
- 100MB disk space for the application (plus space for quarantined files)
- Admin privileges for system monitoring (optional, can run with reduced functionality)

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git (optional, for cloning the repository)

### Step 1: Clone the Repository

```powershell
git clone https://github.com/yourusername/RMS.git
cd RMS
```

Or download and extract the ZIP file from the repository.

### Step 2: Install Dependencies

```powershell
pip install -r requirements.txt
```

For Raspberry Pi support (optional):
```powershell
pip install RPi.GPIO
```

### Step 3: Configure the Environment

Copy the example environment file:
```powershell
Copy-Item .env.example .env
```

Edit the `.env` file to configure your settings:
```powershell
notepad .env
```

## Configuration

The system can be configured through the `.env` file or using command-line arguments:

### Key Configuration Options

- **Monitoring Paths**: Directories to monitor for suspicious file operations
- **Alert Level**: Minimum level for alerts (info, warning, critical)
- **Auto Mitigation**: Enable/disable automatic threat mitigation
- **Dashboard**: Configure the web interface settings

### Safe Mode

To run the system without requiring admin privileges:
```powershell
python src/main.py --safe-dirs
```

This will monitor only user-accessible directories.

## Usage

### Starting the System

```powershell
python src/main.py
```

With debug mode:
```powershell
python src/main.py --debug
```

With a specific configuration file:
```powershell
python src/main.py --config path/to/config.yaml
```

### Accessing the Dashboard

Once running, access the dashboard at:
```
http://localhost:5000
```

Or from another device on the same network:
```
http://<your-ip-address>:5000
```

### Dashboard Features

1. **Home**: Overview of system status and recent alerts
2. **Alerts**: Detailed list of all detected threats
3. **Activity**: System activity logs and metrics
4. **Quarantine**: Manage quarantined files
5. **Settings**: Configure system parameters

## Testing

### Running Tests

```powershell
python test_alert_generation.py
```

### Simulating Ransomware Behavior

The project includes scripts to simulate ransomware behavior for testing:

```powershell
python ransomware_test.py
```

For a more comprehensive test:
```powershell
python enhanced_ransomware_test.py
```

> **WARNING**: These test scripts simulate ransomware behavior by encrypting sample files in the test directory. Do not run them on important files.

## Development

### Project Structure

```
RMS/
├── config/                # Configuration files
├── data/                  # Data storage
│   ├── alerts/            # Alert history
│   ├── logs/              # System logs
│   ├── metrics/           # System metrics
│   ├── models/            # ML models
│   ├── quarantine/        # Quarantined files
│   ├── threat_intel/      # Threat intelligence data
│   └── training/          # ML training data
├── src/                   # Source code
│   ├── dashboard/         # Web dashboard
│   ├── data_collection/   # Monitoring modules
│   ├── ml_model/          # Machine learning components
│   ├── response/          # Alert and mitigation modules
│   ├── threat_intelligence/ # Threat intel integration
│   └── main.py            # Main application entry point
├── test_ransomware_detection/ # Test files and scripts
├── .env                   # Environment configuration
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

### Adding New Features

To contribute new features:

1. Create a new branch for your feature
2. Implement the feature with appropriate tests
3. Submit a pull request with a detailed description

## Troubleshooting

### Common Issues

#### Permission Errors

If you encounter permission errors:
```
PermissionError: [WinError 5] Access is denied
```

Try running with the `--safe-dirs` flag or run the application with administrator privileges.

#### Model Training Errors

If the model fails to train:
```
Model not trained yet
```

Check that the training data is available at the path specified in your configuration or use the auto-generation feature.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Watchdog](https://github.com/gorakhargosh/watchdog) for file system monitoring
- [Scikit-learn](https://scikit-learn.org/) for machine learning components
- [Flask](https://flask.palletsprojects.com/) for the web dashboard
- All contributors and supporters of the project
