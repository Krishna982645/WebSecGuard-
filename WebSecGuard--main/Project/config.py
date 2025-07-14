#!/usr/bin/env python3
"""
Configuration Management for WebSecGuard
Centralized configuration for all components and settings
"""

import json
import os
from datetime import datetime
from typing import Dict, Any, Optional

class WebSecGuardConfig:
    """Centralized configuration management for WebSecGuard"""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = self._load_default_config()
        self._load_config()
        
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration"""
        return {
            # Application settings
            'app': {
                'name': 'WebSecGuard',
                'version': '1.0.0',
                'description': 'Advanced Cybersecurity Web-Based Project',
                'author': 'WebSecGuard Team',
                'debug': False,
                'log_level': 'INFO',
                'max_log_size': 10485760,  # 10MB
                'backup_retention_days': 30
            },
            
            # Database settings
            'database': {
                'main_db': 'config.db',
                'malware_db': 'malware_data.db',
                'network_db': 'network_data.db',
                'encryption_db': 'encryption_data.db',
                'vulnerability_db': 'vulnerability_data.db',
                'firewall_db': 'firewall_data.db',
                'monitor_db': 'security_monitor.db',
                'incident_db': 'incident_response.db',
                'backup_enabled': True,
                'backup_interval_hours': 24,
                'auto_cleanup_days': 90
            },
            
            # Browser settings
            'browser': {
                'home_page': 'https://www.google.com',
                'user_agent': 'WebSecGuard/1.0',
                'javascript_enabled': True,
                'plugins_enabled': False,
                'auto_load_images': True,
                'javascript_can_open_windows': False,
                'javascript_can_access_clipboard': False,
                'default_encoding': 'UTF-8',
                'cache_size': 100 * 1024 * 1024,  # 100MB
                'session_timeout_minutes': 30
            },
            
            # Security settings
            'security': {
                'auto_scan_urls': True,
                'strict_detection_mode': False,
                'dark_mode': False,
                'security_score_enabled': True,
                'threat_intelligence_enabled': True,
                'real_time_protection': True,
                'auto_quarantine': True,
                'auto_block_malicious': True,
                'password_breach_checking': True,
                'network_monitoring': True,
                'file_monitoring': True,
                'process_monitoring': True
            },
            
            # Threat detection settings
            'threat_detection': {
                'url_analysis': {
                    'enabled': True,
                    'check_ip_addresses': True,
                    'check_suspicious_tlds': True,
                    'check_homograph_attacks': True,
                    'check_keywords': True,
                    'check_http_vs_https': True,
                    'check_subdomains': True,
                    'check_query_parameters': True
                },
                'content_analysis': {
                    'enabled': True,
                    'check_javascript': True,
                    'check_forms': True,
                    'check_iframes': True,
                    'check_external_resources': True,
                    'check_ssl_certificates': True
                },
                'network_analysis': {
                    'enabled': True,
                    'port_scanning': True,
                    'service_detection': True,
                    'traffic_analysis': True,
                    'intrusion_detection': True
                },
                'malware_detection': {
                    'enabled': True,
                    'signature_based': True,
                    'behavioral_analysis': True,
                    'heuristic_analysis': True,
                    'sandbox_analysis': False
                }
            },
            
            # Firewall settings
            'firewall': {
                'enabled': True,
                'default_policy': 'deny',
                'auto_block_suspicious': True,
                'log_all_traffic': True,
                'block_known_malicious': True,
                'rate_limiting': True,
                'ddos_protection': True,
                'intrusion_prevention': True
            },
            
            # Encryption settings
            'encryption': {
                'default_algorithm': 'AES-256-GCM',
                'key_rotation_days': 90,
                'password_derivation': 'PBKDF2',
                'key_storage': 'secure',
                'auto_encrypt_logs': True,
                'backup_encryption': True
            },
            
            # Vulnerability scanning settings
            'vulnerability_scanning': {
                'enabled': True,
                'auto_scan_interval_hours': 24,
                'web_application_scanning': True,
                'network_vulnerability_scanning': True,
                'port_scanning': True,
                'service_enumeration': True,
                'cve_checking': True,
                'false_positive_reduction': True
            },
            
            # Monitoring settings
            'monitoring': {
                'real_time_monitoring': True,
                'event_correlation': True,
                'alert_generation': True,
                'performance_monitoring': True,
                'resource_usage_tracking': True,
                'anomaly_detection': True,
                'baseline_analysis': True
            },
            
            # Incident response settings
            'incident_response': {
                'auto_incident_creation': True,
                'escalation_enabled': True,
                'auto_response_procedures': True,
                'evidence_collection': True,
                'communication_automation': True,
                'lessons_learned_tracking': True,
                'sla_monitoring': True
            },
            
            # Logging settings
            'logging': {
                'enabled': True,
                'log_level': 'INFO',
                'log_rotation': True,
                'log_compression': True,
                'log_retention_days': 365,
                'audit_logging': True,
                'performance_logging': True,
                'security_logging': True
            },
            
            # UI settings
            'ui': {
                'theme': 'light',
                'language': 'en',
                'auto_save_settings': True,
                'show_security_alerts': True,
                'show_progress_indicators': True,
                'enable_tooltips': True,
                'enable_context_menus': True,
                'window_size': {'width': 1400, 'height': 900},
                'window_position': {'x': 100, 'y': 100}
            },
            
            # Network settings
            'network': {
                'proxy_enabled': False,
                'proxy_host': '',
                'proxy_port': 0,
                'proxy_username': '',
                'proxy_password': '',
                'timeout_seconds': 30,
                'max_retries': 3,
                'connection_pool_size': 10
            },
            
            # Performance settings
            'performance': {
                'max_threads': 10,
                'scan_timeout_seconds': 60,
                'memory_limit_mb': 512,
                'cpu_limit_percent': 80,
                'disk_cache_size_mb': 100,
                'optimize_for_speed': True
            },
            
            # Update settings
            'updates': {
                'auto_check_updates': True,
                'check_interval_hours': 24,
                'auto_download_updates': False,
                'update_channel': 'stable',
                'backup_before_update': True
            },
            
            # Privacy settings
            'privacy': {
                'telemetry_enabled': False,
                'crash_reporting': False,
                'usage_statistics': False,
                'data_collection': False,
                'anonymize_logs': True,
                'secure_data_deletion': True
            }
        }
        
    def _load_config(self):
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    file_config = json.load(f)
                    self._merge_config(file_config)
        except Exception as e:
            print(f"Error loading config: {e}")
            
    def _merge_config(self, file_config: Dict[str, Any]):
        """Merge file configuration with default config"""
        def merge_dicts(default: Dict, override: Dict):
            for key, value in override.items():
                if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                    merge_dicts(default[key], value)
                else:
                    default[key] = value
                    
        merge_dicts(self.config, file_config)
        
    def save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving config: {e}")
            
    def get(self, key_path: str, default: Any = None) -> Any:
        """Get configuration value by dot-separated path"""
        keys = key_path.split('.')
        value = self.config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
            
    def set(self, key_path: str, value: Any):
        """Set configuration value by dot-separated path"""
        keys = key_path.split('.')
        config = self.config
        
        # Navigate to parent of target key
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
            
        # Set the value
        config[keys[-1]] = value
        
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get entire configuration section"""
        return self.config.get(section, {})
        
    def set_section(self, section: str, values: Dict[str, Any]):
        """Set entire configuration section"""
        self.config[section] = values
        
    def reset_to_defaults(self):
        """Reset configuration to default values"""
        self.config = self._load_default_config()
        self.save_config()
        
    def export_config(self, filename: str):
        """Export configuration to file"""
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error exporting config: {e}")
            
    def import_config(self, filename: str):
        """Import configuration from file"""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                imported_config = json.load(f)
                self._merge_config(imported_config)
                self.save_config()
        except Exception as e:
            print(f"Error importing config: {e}")
            
    def validate_config(self) -> Dict[str, Any]:
        """Validate configuration and return issues"""
        issues = []
        
        # Check required sections
        required_sections = ['app', 'database', 'browser', 'security']
        for section in required_sections:
            if section not in self.config:
                issues.append(f"Missing required section: {section}")
                
        # Check database paths
        db_section = self.config.get('database', {})
        for db_key, db_path in db_section.items():
            if db_key.endswith('_db') and not isinstance(db_path, str):
                issues.append(f"Invalid database path for {db_key}")
                
        # Check security settings
        security_section = self.config.get('security', {})
        if not isinstance(security_section.get('auto_scan_urls'), bool):
            issues.append("auto_scan_urls must be boolean")
            
        # Check browser settings
        browser_section = self.config.get('browser', {})
        if not isinstance(browser_section.get('cache_size'), int):
            issues.append("cache_size must be integer")
            
        return {
            'valid': len(issues) == 0,
            'issues': issues
        }
        
    def get_database_paths(self) -> Dict[str, str]:
        """Get all database file paths"""
        db_config = self.config.get('database', {})
        return {key: value for key, value in db_config.items() if key.endswith('_db')}
        
    def get_security_settings(self) -> Dict[str, Any]:
        """Get security-related settings"""
        return {
            'security': self.config.get('security', {}),
            'threat_detection': self.config.get('threat_detection', {}),
            'firewall': self.config.get('firewall', {}),
            'encryption': self.config.get('encryption', {}),
            'vulnerability_scanning': self.config.get('vulnerability_scanning', {}),
            'monitoring': self.config.get('monitoring', {}),
            'incident_response': self.config.get('incident_response', {})
        }
        
    def get_ui_settings(self) -> Dict[str, Any]:
        """Get UI-related settings"""
        return self.config.get('ui', {})
        
    def get_performance_settings(self) -> Dict[str, Any]:
        """Get performance-related settings"""
        return self.config.get('performance', {})
        
    def update_security_score(self, score: int):
        """Update security score in configuration"""
        self.set('security.security_score', score)
        self.save_config()
        
    def get_security_score(self) -> int:
        """Get current security score"""
        return self.get('security.security_score', 100)
        
    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled"""
        return self.get('app.debug', False)
        
    def is_dark_mode(self) -> bool:
        """Check if dark mode is enabled"""
        return self.get('security.dark_mode', False)
        
    def is_auto_scan_enabled(self) -> bool:
        """Check if auto-scan is enabled"""
        return self.get('security.auto_scan_urls', True)
        
    def is_strict_mode_enabled(self) -> bool:
        """Check if strict detection mode is enabled"""
        return self.get('security.strict_detection_mode', False)
        
    def get_home_page(self) -> str:
        """Get browser home page"""
        return self.get('browser.home_page', 'https://www.google.com')
        
    def get_log_level(self) -> str:
        """Get logging level"""
        return self.get('logging.log_level', 'INFO')
        
    def get_max_threads(self) -> int:
        """Get maximum number of threads"""
        return self.get('performance.max_threads', 10)
        
    def get_scan_timeout(self) -> int:
        """Get scan timeout in seconds"""
        return self.get('performance.scan_timeout_seconds', 60)
        
    def get_cache_size(self) -> int:
        """Get browser cache size in bytes"""
        return self.get('browser.cache_size', 100 * 1024 * 1024)
        
    def get_window_size(self) -> Dict[str, int]:
        """Get window size"""
        return self.get('ui.window_size', {'width': 1400, 'height': 900})
        
    def set_window_size(self, width: int, height: int):
        """Set window size"""
        self.set('ui.window_size', {'width': width, 'height': height})
        self.save_config()
        
    def get_window_position(self) -> Dict[str, int]:
        """Get window position"""
        return self.get('ui.window_position', {'x': 100, 'y': 100})
        
    def set_window_position(self, x: int, y: int):
        """Set window position"""
        self.set('ui.window_position', {'x': x, 'y': y})
        self.save_config()
        
    def get_config_summary(self) -> Dict[str, Any]:
        """Get configuration summary for display"""
        return {
            'app_info': {
                'name': self.get('app.name'),
                'version': self.get('app.version'),
                'debug_mode': self.is_debug_mode()
            },
            'security_status': {
                'auto_scan': self.is_auto_scan_enabled(),
                'strict_mode': self.is_strict_mode_enabled(),
                'dark_mode': self.is_dark_mode_enabled(),
                'security_score': self.get_security_score()
            },
            'features_enabled': {
                'threat_detection': self.get('threat_detection.url_analysis.enabled'),
                'malware_detection': self.get('threat_detection.malware_detection.enabled'),
                'network_monitoring': self.get('security.network_monitoring'),
                'file_monitoring': self.get('security.file_monitoring'),
                'vulnerability_scanning': self.get('vulnerability_scanning.enabled'),
                'firewall': self.get('firewall.enabled'),
                'encryption': self.get('encryption.auto_encrypt_logs'),
                'incident_response': self.get('incident_response.auto_incident_creation')
            },
            'performance': {
                'max_threads': self.get_max_threads(),
                'scan_timeout': self.get_scan_timeout(),
                'cache_size_mb': self.get_cache_size() // (1024 * 1024)
            },
            'last_updated': datetime.now().isoformat()
        }

# Global configuration instance
config = WebSecGuardConfig()

def get_config() -> WebSecGuardConfig:
    """Get global configuration instance"""
    return config

def reload_config():
    """Reload configuration from file"""
    config._load_config()

def save_config():
    """Save current configuration"""
    config.save_config() 