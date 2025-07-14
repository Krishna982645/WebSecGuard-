# WebSecGuard - Advanced Cybersecurity Web-Based Project

## 🛡️ Project Overview

**WebSecGuard** is a comprehensive desktop cybersecurity application built with PyQt5 that serves as a secure browser interface with integrated threat detection, network monitoring, malware analysis, and incident response capabilities. It provides a complete security ecosystem for protecting users from various cyber threats.

## 🚀 Key Features

### 🌐 Secure Web Browser
- **Chromium-based WebEngine** with integrated security features
- **Real-time URL threat scanning** with heuristic analysis
- **Automatic blocking** of malicious websites
- **Security alerts** and user warnings
- **Navigation controls** with security logging

### 🔍 Threat Detection & Analysis
- **URL Analysis**: Pattern matching, homograph detection, suspicious TLD analysis
- **Content Scanning**: JavaScript analysis, form security checks, external resource monitoring
- **Network Scanning**: Port scanning, service detection, vulnerability assessment
- **Malware Detection**: Signature-based and behavioral analysis
- **Password Leak Checking**: Breach database integration

### 🛡️ Security Management
- **Firewall Management**: Rule-based traffic filtering, intrusion detection
- **Encryption Management**: Key management, data encryption/decryption
- **Vulnerability Scanning**: Web application and network vulnerability assessment
- **Security Monitoring**: Real-time threat detection and alerting
- **Incident Response**: Automated incident management and response procedures

### 📊 Security Intelligence
- **Comprehensive Logging**: All security events and activities
- **Blacklist/Whitelist Management**: URL and IP filtering
- **Security Statistics**: Detailed analytics and reporting
- **Educational Content**: Cybersecurity awareness and best practices

## 🏗️ Architecture

```
WebSecGuard/
├── main.py                    # Main application entry point
├── browser.py                 # Secure browser component
├── threat_scanner.py          # URL and content threat analysis
├── logger.py                  # Security logging and database management
├── requirements.txt           # Python dependencies
├── utils/
│   ├── __init__.py           # Utils package
│   ├── url_parser.py         # URL parsing and analysis
│   ├── password_checker.py   # Password breach detection
│   ├── network_scanner.py    # Network security scanning
│   ├── malware_detector.py   # Malware detection engine
│   ├── firewall_manager.py   # Firewall configuration
│   ├── encryption_manager.py # Encryption and key management
│   ├── vulnerability_scanner.py # Vulnerability assessment
│   ├── security_monitor.py   # Real-time security monitoring
│   └── incident_response.py  # Incident response management
└── README.md                 # Project documentation
```

## 🛠️ Installation

### Prerequisites
- Python 3.7 or higher
- Windows 10/11 (tested on Windows 10.0.22631)

### Setup Instructions

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd WebSecGuard
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   python main.py
   ```

## 📋 Dependencies

```
PyQt5==5.15.9              # GUI framework
PyQtWebEngine==5.15.6      # Web browser engine
requests==2.31.0           # HTTP requests
beautifulsoup4==4.12.2     # HTML parsing
urllib3==2.0.7             # HTTP client
```

## 🎯 Core Components

### 1. Main Application (`main.py`)
- **PyQt5 GUI** with tabbed interface
- **Security score** tracking and display
- **Settings management** (auto-scan, strict mode, dark mode)
- **Password leak checker** integration
- **Log management** and export functionality

### 2. Secure Browser (`browser.py`)
- **QWebEngineView** with security interceptor
- **Real-time URL analysis** and blocking
- **JavaScript monitoring** for suspicious activity
- **Page load security** analysis
- **Navigation logging** and threat detection

### 3. Threat Scanner (`threat_scanner.py`)
- **URL pattern analysis** (IP addresses, suspicious TLDs)
- **Homograph attack detection**
- **Keyword-based threat identification**
- **HTTP vs HTTPS security checks**
- **Subdomain and query parameter analysis**

### 4. Security Logger (`logger.py`)
- **SQLite database** for security events
- **Blacklist/whitelist management**
- **Comprehensive logging** of all activities
- **Export functionality** (CSV, JSON)
- **Statistics and reporting**

### 5. Utility Components

#### URL Parser (`utils/url_parser.py`)
- **Domain extraction** and analysis
- **Suspicious keyword detection**
- **TLD security assessment**
- **URL normalization** and comparison

#### Password Checker (`utils/password_checker.py`)
- **Multiple breach database** integration
- **Password strength analysis**
- **Breach statistics** and recommendations
- **Email security assessment**

#### Network Scanner (`utils/network_scanner.py`)
- **Port scanning** and service detection
- **Host discovery** and analysis
- **Threat detection** on network level
- **Traffic monitoring** and analysis

#### Malware Detector (`utils/malware_detector.py`)
- **Signature-based detection**
- **Behavioral analysis**
- **File quarantine** functionality
- **Scan scheduling** and management

#### Firewall Manager (`utils/firewall_manager.py`)
- **Rule-based traffic filtering**
- **Intrusion detection**
- **Security policy management**
- **Traffic logging** and analysis

#### Encryption Manager (`utils/encryption_manager.py`)
- **Key generation** and management
- **Data encryption/decryption**
- **Password-based key derivation**
- **Key rotation** and backup

#### Vulnerability Scanner (`utils/vulnerability_scanner.py`)
- **Web application vulnerability** assessment
- **Network vulnerability** scanning
- **CVE database** integration
- **Remediation recommendations**

#### Security Monitor (`utils/security_monitor.py`)
- **Real-time threat detection**
- **Alert generation** and management
- **Event correlation** and analysis
- **Performance monitoring**

#### Incident Response (`utils/incident_response.py`)
- **Incident creation** and management
- **Response procedure** automation
- **Evidence collection** and tracking
- **Lessons learned** documentation

## 🔧 Configuration

### Security Settings
- **Auto-scan URLs**: Enable/disable automatic threat scanning
- **Strict detection mode**: More aggressive threat detection
- **Dark mode**: UI theme preference
- **Security score tracking**: Monitor overall security posture

### Database Configuration
- **SQLite databases** are automatically created
- **Backup functionality** available
- **Export capabilities** for logs and data

## 📊 Security Features

### Threat Detection
- **Real-time URL analysis** with multiple detection methods
- **Content security scanning** for malicious elements
- **Network traffic monitoring** for suspicious patterns
- **Malware signature matching** and behavioral analysis

### Protection Mechanisms
- **Automatic blocking** of known malicious sites
- **User warnings** for suspicious content
- **Quarantine system** for malicious files
- **Firewall rules** for network protection

### Intelligence & Reporting
- **Comprehensive logging** of all security events
- **Statistical analysis** and reporting
- **Threat intelligence** integration
- **Incident response** automation

## 🎓 Educational Features

### Security Awareness
- **Built-in educational content** about cybersecurity
- **Real-time security tips** and recommendations
- **Threat explanation** for detected issues
- **Best practices** guidance

### Interactive Learning
- **Security score tracking** to gamify security awareness
- **Password strength analysis** with improvement suggestions
- **Breach notification** with actionable advice
- **Incident response** training through real scenarios

## 🔍 Usage Examples

### Basic Web Browsing
1. Launch WebSecGuard
2. Enter URL in the address bar
3. System automatically scans for threats
4. Receive security alerts if threats detected
5. Choose to proceed or block based on warnings

### Security Scanning
1. Navigate to "Logs" tab to view security events
2. Check "Lists" tab to manage blacklist/whitelist
3. Use "Education" tab for security learning
4. Monitor security score for overall posture

### Advanced Features
1. **Network Scanning**: Use network scanner for infrastructure assessment
2. **Malware Detection**: Scan files and directories for threats
3. **Vulnerability Assessment**: Test web applications for security issues
4. **Incident Response**: Manage security incidents through automated procedures

## 📈 Performance & Scalability

### System Requirements
- **Minimum**: 4GB RAM, 2GB disk space
- **Recommended**: 8GB RAM, 5GB disk space
- **Network**: Internet connection for threat intelligence

### Performance Optimizations
- **Background scanning** to minimize UI impact
- **Database indexing** for fast queries
- **Memory management** for large scan results
- **Threading** for concurrent operations

## 🔒 Security Considerations

### Privacy
- **Local processing** of sensitive data
- **No external data transmission** without user consent
- **Encrypted storage** of security logs
- **User control** over data collection

### Data Protection
- **Secure key management** for encryption
- **Access controls** for sensitive operations
- **Audit logging** for all activities
- **Data retention** policies

## 🐛 Troubleshooting

### Common Issues

1. **PyQt5 Installation Issues**
   ```bash
   pip install --upgrade pip
   pip install PyQt5 PyQtWebEngine
   ```

2. **Database Errors**
   - Delete existing database files to reset
   - Check file permissions in project directory

3. **Browser Loading Issues**
   - Ensure internet connection
   - Check firewall settings
   - Verify PyQtWebEngine installation

### Debug Mode
- Enable debug logging in settings
- Check console output for error messages
- Review database logs for detailed information

## 🤝 Contributing

### Development Setup
1. Fork the repository
2. Create feature branch
3. Implement changes with proper testing
4. Submit pull request with detailed description

### Code Standards
- Follow PEP 8 Python style guide
- Add comprehensive docstrings
- Include unit tests for new features
- Update documentation for changes

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **PyQt5** team for the excellent GUI framework
- **Chromium** project for the web engine
- **Security community** for threat intelligence
- **Open source contributors** for various security tools

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review troubleshooting section
- Contact the development team

---

**WebSecGuard** - Protecting your digital world with advanced cybersecurity technology.

*Built with ❤️ for the security community* 