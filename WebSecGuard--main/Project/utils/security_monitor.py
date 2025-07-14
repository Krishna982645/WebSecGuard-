#!/usr/bin/env python3
"""
Security Monitor Utility for WebSecGuard
Real-time security monitoring and threat detection
"""

import sqlite3
import json
import threading
import time
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable
import queue

class SecurityMonitor:
    """Real-time security monitoring system"""
    
    def __init__(self, db_path="security_monitor.db"):
        self.db_path = db_path
        self.init_monitor_database()
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_thread = None
        self.alert_queue = queue.Queue()
        self.alert_callbacks = []
        
        # Security thresholds
        self.thresholds = {
            'failed_login_attempts': 5,
            'suspicious_connections': 10,
            'data_exfiltration_size': 1000000,  # 1MB
            'unusual_activity_score': 75,
            'threat_detection_rate': 0.1  # 10%
        }
        
        # Alert levels
        self.alert_levels = {
            'info': 0,
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        
        # Monitoring rules
        self.monitoring_rules = {
            'authentication': {
                'enabled': True,
                'events': ['login_success', 'login_failure', 'logout', 'password_change'],
                'thresholds': {'failed_attempts': 5, 'time_window': 300}
            },
            'network': {
                'enabled': True,
                'events': ['connection_attempt', 'data_transfer', 'port_scan', 'ddos_attack'],
                'thresholds': {'suspicious_connections': 10, 'time_window': 60}
            },
            'file_system': {
                'enabled': True,
                'events': ['file_access', 'file_modification', 'file_deletion', 'file_creation'],
                'thresholds': {'suspicious_operations': 20, 'time_window': 300}
            },
            'process': {
                'enabled': True,
                'events': ['process_start', 'process_stop', 'process_injection', 'privilege_escalation'],
                'thresholds': {'suspicious_processes': 5, 'time_window': 60}
            }
        }
        
    def init_monitor_database(self):
        """Initialize the security monitor database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create security events table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_type TEXT NOT NULL,
                event_category TEXT NOT NULL,
                source_ip TEXT,
                source_user TEXT,
                target_resource TEXT,
                event_data TEXT,
                severity TEXT DEFAULT 'low',
                threat_score REAL DEFAULT 0.0,
                timestamp TEXT NOT NULL,
                processed BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # Create security alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_id TEXT UNIQUE NOT NULL,
                alert_type TEXT NOT NULL,
                alert_level TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                source_events TEXT,
                threat_indicators TEXT,
                recommended_actions TEXT,
                is_acknowledged BOOLEAN DEFAULT FALSE,
                is_resolved BOOLEAN DEFAULT FALSE,
                acknowledged_by TEXT,
                resolved_by TEXT,
                created_at TEXT NOT NULL,
                acknowledged_at TEXT,
                resolved_at TEXT
            )
        ''')
        
        # Create threat intelligence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_intelligence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                threat_family TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                confidence_score REAL DEFAULT 0.0,
                source TEXT,
                description TEXT,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Create monitoring sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT UNIQUE NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                status TEXT DEFAULT 'active',
                events_processed INTEGER DEFAULT 0,
                alerts_generated INTEGER DEFAULT 0,
                threats_detected INTEGER DEFAULT 0,
                performance_metrics TEXT
            )
        ''')
        
        # Create baseline profiles table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS baseline_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_name TEXT UNIQUE NOT NULL,
                profile_type TEXT NOT NULL,
                baseline_data TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def start_monitoring(self) -> bool:
        """Start security monitoring"""
        if self.is_monitoring:
            return False
            
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitoring_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Create monitoring session
        session_id = self._create_monitoring_session()
        
        return True
        
    def stop_monitoring(self) -> bool:
        """Stop security monitoring"""
        if not self.is_monitoring:
            return False
            
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)
            
        # End monitoring session
        self._end_monitoring_session()
        
        return True
        
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Generate simulated security events
                events = self._generate_security_events()
                
                # Process events
                for event in events:
                    self._process_security_event(event)
                    
                # Check for threats
                self._check_threat_patterns()
                
                # Generate alerts
                self._generate_alerts()
                
                # Sleep for monitoring interval
                time.sleep(1)
                
            except Exception as e:
                print(f"Error in monitoring loop: {e}")
                time.sleep(5)
                
    def _generate_security_events(self) -> List[Dict]:
        """Generate simulated security events"""
        events = []
        
        # Authentication events
        if self.monitoring_rules['authentication']['enabled']:
            auth_events = self._generate_auth_events()
            events.extend(auth_events)
            
        # Network events
        if self.monitoring_rules['network']['enabled']:
            network_events = self._generate_network_events()
            events.extend(network_events)
            
        # File system events
        if self.monitoring_rules['file_system']['enabled']:
            file_events = self._generate_file_events()
            events.extend(file_events)
            
        # Process events
        if self.monitoring_rules['process']['enabled']:
            process_events = self._generate_process_events()
            events.extend(process_events)
            
        return events
        
    def _generate_auth_events(self) -> List[Dict]:
        """Generate authentication events"""
        events = []
        
        # Simulate login attempts
        if random.choice([True, False, False]):  # 33% chance
            events.append({
                'event_type': 'login_success',
                'event_category': 'authentication',
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'source_user': f"user{random.randint(1, 100)}",
                'target_resource': 'web_application',
                'event_data': {'method': 'password', 'session_id': f"sess_{random.randint(1000, 9999)}"},
                'severity': 'low',
                'threat_score': 0.0
            })
            
        # Simulate failed login attempts
        if random.choice([True, False, False, False]):  # 25% chance
            events.append({
                'event_type': 'login_failure',
                'event_category': 'authentication',
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'source_user': f"user{random.randint(1, 100)}",
                'target_resource': 'web_application',
                'event_data': {'method': 'password', 'reason': 'invalid_credentials'},
                'severity': 'medium',
                'threat_score': 0.3
            })
            
        return events
        
    def _generate_network_events(self) -> List[Dict]:
        """Generate network events"""
        events = []
        
        # Simulate connection attempts
        if random.choice([True, True, False]):  # 66% chance
            events.append({
                'event_type': 'connection_attempt',
                'event_category': 'network',
                'source_ip': f"192.168.1.{random.randint(1, 254)}",
                'target_resource': f"server{random.randint(1, 10)}",
                'event_data': {'port': random.choice([80, 443, 22, 21, 25, 53])},
                'severity': 'low',
                'threat_score': 0.1
            })
            
        # Simulate suspicious connections
        if random.choice([True, False, False, False, False]):  # 20% chance
            events.append({
                'event_type': 'suspicious_connection',
                'event_category': 'network',
                'source_ip': f"10.0.0.{random.randint(1, 254)}",
                'target_resource': 'internal_server',
                'event_data': {'port': random.choice([3389, 1433, 3306, 5900])},
                'severity': 'high',
                'threat_score': 0.7
            })
            
        return events
        
    def _generate_file_events(self) -> List[Dict]:
        """Generate file system events"""
        events = []
        
        # Simulate file access
        if random.choice([True, True, False]):  # 66% chance
            events.append({
                'event_type': 'file_access',
                'event_category': 'file_system',
                'source_user': f"user{random.randint(1, 100)}",
                'target_resource': f"/home/user{random.randint(1, 100)}/document{random.randint(1, 50)}.txt",
                'event_data': {'operation': 'read', 'size': random.randint(100, 10000)},
                'severity': 'low',
                'threat_score': 0.0
            })
            
        # Simulate suspicious file operations
        if random.choice([True, False, False, False, False]):  # 20% chance
            events.append({
                'event_type': 'suspicious_file_operation',
                'event_category': 'file_system',
                'source_user': f"user{random.randint(1, 100)}",
                'target_resource': f"/etc/passwd",
                'event_data': {'operation': 'read', 'size': 1024},
                'severity': 'high',
                'threat_score': 0.8
            })
            
        return events
        
    def _generate_process_events(self) -> List[Dict]:
        """Generate process events"""
        events = []
        
        # Simulate process start
        if random.choice([True, True, False]):  # 66% chance
            events.append({
                'event_type': 'process_start',
                'event_category': 'process',
                'source_user': f"user{random.randint(1, 100)}",
                'target_resource': random.choice(['chrome.exe', 'firefox.exe', 'notepad.exe']),
                'event_data': {'pid': random.randint(1000, 9999), 'parent_pid': random.randint(1, 999)},
                'severity': 'low',
                'threat_score': 0.0
            })
            
        # Simulate suspicious process
        if random.choice([True, False, False, False, False, False]):  # 16% chance
            events.append({
                'event_type': 'suspicious_process',
                'event_category': 'process',
                'source_user': f"user{random.randint(1, 100)}",
                'target_resource': random.choice(['cmd.exe', 'powershell.exe', 'wscript.exe']),
                'event_data': {'pid': random.randint(1000, 9999), 'command_line': 'suspicious_command'},
                'severity': 'medium',
                'threat_score': 0.6
            })
            
        return events
        
    def _process_security_event(self, event: Dict):
        """Process a security event"""
        # Generate event ID
        event['event_id'] = f"evt_{int(time.time())}_{random.randint(1000, 9999)}"
        event['timestamp'] = datetime.now().isoformat()
        
        # Store event in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events 
            (event_id, event_type, event_category, source_ip, source_user, target_resource,
             event_data, severity, threat_score, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            event['event_id'], event['event_type'], event['event_category'],
            event.get('source_ip'), event.get('source_user'), event.get('target_resource'),
            json.dumps(event.get('event_data', {})), event['severity'], event['threat_score'],
            event['timestamp']
        ))
        
        conn.commit()
        conn.close()
        
        # Update session metrics
        self._update_session_metrics()
        
    def _check_threat_patterns(self):
        """Check for threat patterns in recent events"""
        # Get recent events
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check for failed login attempts
        cursor.execute('''
            SELECT COUNT(*) FROM security_events 
            WHERE event_type = 'login_failure' 
            AND timestamp >= datetime('now', '-5 minutes')
        ''')
        
        failed_logins = cursor.fetchone()[0]
        if failed_logins >= self.thresholds['failed_login_attempts']:
            self._create_alert('brute_force_attempt', 'high', 
                             f"Multiple failed login attempts detected: {failed_logins}")
                             
        # Check for suspicious connections
        cursor.execute('''
            SELECT COUNT(*) FROM security_events 
            WHERE event_type = 'suspicious_connection' 
            AND timestamp >= datetime('now', '-1 minute')
        ''')
        
        suspicious_conns = cursor.fetchone()[0]
        if suspicious_conns >= self.thresholds['suspicious_connections']:
            self._create_alert('network_attack', 'critical',
                             f"High number of suspicious connections: {suspicious_conns}")
                             
        # Check for unusual activity
        cursor.execute('''
            SELECT AVG(threat_score) FROM security_events 
            WHERE timestamp >= datetime('now', '-5 minutes')
        ''')
        
        avg_threat_score = cursor.fetchone()[0] or 0
        if avg_threat_score > self.thresholds['unusual_activity_score'] / 100:
            self._create_alert('unusual_activity', 'medium',
                             f"Unusual activity detected with threat score: {avg_threat_score:.2f}")
                             
        conn.close()
        
    def _create_alert(self, alert_type: str, alert_level: str, description: str):
        """Create a security alert"""
        alert_id = f"alert_{int(time.time())}_{random.randint(1000, 9999)}"
        
        # Get source events
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT event_id FROM security_events 
            WHERE timestamp >= datetime('now', '-5 minutes')
            ORDER BY timestamp DESC LIMIT 10
        ''')
        
        source_events = [row[0] for row in cursor.fetchall()]
        
        # Create alert
        cursor.execute('''
            INSERT INTO security_alerts 
            (alert_id, alert_type, alert_level, title, description, source_events, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert_id, alert_type, alert_level, f"{alert_type.replace('_', ' ').title()}",
            description, json.dumps(source_events), datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        # Add to alert queue
        alert = {
            'alert_id': alert_id,
            'alert_type': alert_type,
            'alert_level': alert_level,
            'title': f"{alert_type.replace('_', ' ').title()}",
            'description': description,
            'timestamp': datetime.now().isoformat()
        }
        
        self.alert_queue.put(alert)
        
        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Error in alert callback: {e}")
                
    def _generate_alerts(self):
        """Generate alerts based on current state"""
        # This method can be extended to generate more sophisticated alerts
        pass
        
    def _create_monitoring_session(self) -> str:
        """Create a new monitoring session"""
        session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO monitoring_sessions 
            (session_id, start_time, status)
            VALUES (?, ?, ?)
        ''', (session_id, datetime.now().isoformat(), 'active'))
        
        conn.commit()
        conn.close()
        
        return session_id
        
    def _end_monitoring_session(self):
        """End the current monitoring session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE monitoring_sessions 
            SET end_time = ?, status = 'completed'
            WHERE status = 'active'
        ''', (datetime.now().isoformat(),))
        
        conn.commit()
        conn.close()
        
    def _update_session_metrics(self):
        """Update session metrics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM security_events 
            WHERE timestamp >= datetime('now', '-1 minute')
        ''')
        
        events_processed = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM security_alerts 
            WHERE created_at >= datetime('now', '-1 minute')
        ''')
        
        alerts_generated = cursor.fetchone()[0]
        
        cursor.execute('''
            UPDATE monitoring_sessions 
            SET events_processed = events_processed + ?, alerts_generated = alerts_generated + ?
            WHERE status = 'active'
        ''', (events_processed, alerts_generated))
        
        conn.commit()
        conn.close()
        
    def add_alert_callback(self, callback: Callable):
        """Add alert callback function"""
        self.alert_callbacks.append(callback)
        
    def get_alerts(self, limit: int = 100) -> List[Dict]:
        """Get recent security alerts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT alert_id, alert_type, alert_level, title, description, 
                   is_acknowledged, is_resolved, created_at
            FROM security_alerts ORDER BY created_at DESC LIMIT ?
        ''', (limit,))
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'alert_id': row[0],
                'alert_type': row[1],
                'alert_level': row[2],
                'title': row[3],
                'description': row[4],
                'is_acknowledged': bool(row[5]),
                'is_resolved': bool(row[6]),
                'created_at': row[7]
            })
            
        conn.close()
        return alerts
        
    def acknowledge_alert(self, alert_id: str, acknowledged_by: str) -> bool:
        """Acknowledge a security alert"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE security_alerts 
                SET is_acknowledged = TRUE, acknowledged_by = ?, acknowledged_at = ?
                WHERE alert_id = ?
            ''', (acknowledged_by, datetime.now().isoformat(), alert_id))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error acknowledging alert: {e}")
            return False
            
    def resolve_alert(self, alert_id: str, resolved_by: str) -> bool:
        """Resolve a security alert"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE security_alerts 
                SET is_resolved = TRUE, resolved_by = ?, resolved_at = ?
                WHERE alert_id = ?
            ''', (resolved_by, datetime.now().isoformat(), alert_id))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error resolving alert: {e}")
            return False
            
    def get_monitoring_statistics(self) -> Dict:
        """Get monitoring statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM security_events')
        total_events = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM security_alerts')
        total_alerts = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM security_alerts WHERE is_resolved = FALSE')
        active_alerts = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT alert_level, COUNT(*) 
            FROM security_alerts 
            GROUP BY alert_level
        ''')
        alerts_by_level = dict(cursor.fetchall())
        
        cursor.execute('''
            SELECT event_category, COUNT(*) 
            FROM security_events 
            GROUP BY event_category
        ''')
        events_by_category = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_events': total_events,
            'total_alerts': total_alerts,
            'active_alerts': active_alerts,
            'alerts_by_level': alerts_by_level,
            'events_by_category': events_by_category,
            'is_monitoring': self.is_monitoring,
            'last_updated': datetime.now().isoformat()
        } 