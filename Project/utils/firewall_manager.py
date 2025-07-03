#!/usr/bin/env python3
"""
Firewall Manager Utility for WebSecGuard
Advanced firewall configuration and rule management
"""

import sqlite3
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import random
import threading
import time

class FirewallManager:
    """Advanced firewall management system"""
    
    def __init__(self, db_path="firewall_data.db"):
        self.db_path = db_path
        self.init_firewall_database()
        
        # Firewall rules
        self.active_rules = {}
        self.rule_counters = {}
        
        # Network protocols
        self.protocols = {
            'TCP': 6,
            'UDP': 17,
            'ICMP': 1,
            'HTTP': 80,
            'HTTPS': 443,
            'SSH': 22,
            'FTP': 21,
            'SMTP': 25,
            'DNS': 53
        }
        
        # Default security policies
        self.security_policies = {
            'strict': {
                'default_inbound': 'deny',
                'default_outbound': 'allow',
                'allowed_ports': [80, 443, 22, 53],
                'blocked_ports': [23, 3389, 1433, 3306],
                'allowed_ips': [],
                'blocked_ips': []
            },
            'moderate': {
                'default_inbound': 'deny',
                'default_outbound': 'allow',
                'allowed_ports': [80, 443, 22, 21, 25, 53, 110, 143],
                'blocked_ports': [23, 3389],
                'allowed_ips': [],
                'blocked_ips': []
            },
            'permissive': {
                'default_inbound': 'allow',
                'default_outbound': 'allow',
                'allowed_ports': [],
                'blocked_ports': [],
                'allowed_ips': [],
                'blocked_ips': []
            }
        }
        
    def init_firewall_database(self):
        """Initialize the firewall database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create firewall rules table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT UNIQUE NOT NULL,
                rule_type TEXT NOT NULL,
                direction TEXT NOT NULL,
                protocol TEXT,
                source_ip TEXT,
                source_port TEXT,
                destination_ip TEXT,
                destination_port TEXT,
                action TEXT NOT NULL,
                priority INTEGER DEFAULT 100,
                is_active BOOLEAN DEFAULT TRUE,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # Create firewall logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS firewall_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                rule_id INTEGER,
                rule_name TEXT,
                source_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_ip TEXT NOT NULL,
                destination_port INTEGER,
                protocol TEXT NOT NULL,
                action TEXT NOT NULL,
                packet_size INTEGER,
                flags TEXT,
                is_blocked BOOLEAN DEFAULT FALSE,
                threat_level TEXT DEFAULT 'low',
                FOREIGN KEY (rule_id) REFERENCES firewall_rules (id)
            )
        ''')
        
        # Create security policies table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                policy_name TEXT UNIQUE NOT NULL,
                policy_type TEXT NOT NULL,
                default_inbound TEXT NOT NULL,
                default_outbound TEXT NOT NULL,
                allowed_ports TEXT,
                blocked_ports TEXT,
                allowed_ips TEXT,
                blocked_ips TEXT,
                is_active BOOLEAN DEFAULT FALSE,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # Create intrusion detection table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intrusion_detection (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                attack_signature TEXT,
                threat_level TEXT NOT NULL,
                action_taken TEXT,
                description TEXT,
                is_blocked BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # Insert default policies
        default_policies = [
            ('strict_policy', 'strict', 'deny', 'allow', 
             json.dumps([80, 443, 22, 53]), json.dumps([23, 3389, 1433, 3306]),
             json.dumps([]), json.dumps([]), True,
             datetime.now().isoformat(), datetime.now().isoformat()),
            ('moderate_policy', 'moderate', 'deny', 'allow',
             json.dumps([80, 443, 22, 21, 25, 53, 110, 143]), json.dumps([23, 3389]),
             json.dumps([]), json.dumps([]), False,
             datetime.now().isoformat(), datetime.now().isoformat()),
            ('permissive_policy', 'permissive', 'allow', 'allow',
             json.dumps([]), json.dumps([]), json.dumps([]), json.dumps([]), False,
             datetime.now().isoformat(), datetime.now().isoformat())
        ]
        
        cursor.executemany('''
            INSERT OR IGNORE INTO security_policies 
            (policy_name, policy_type, default_inbound, default_outbound,
             allowed_ports, blocked_ports, allowed_ips, blocked_ips,
             is_active, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', default_policies)
        
        conn.commit()
        conn.close()
        
    def create_rule(self, rule_name: str, rule_type: str, direction: str, 
                   action: str, **kwargs) -> bool:
        """
        Create a new firewall rule
        Args:
            rule_name: Name of the rule
            rule_type: Type of rule (allow, deny, log)
            direction: inbound or outbound
            action: allow, deny, log
            **kwargs: Additional rule parameters
        Returns: Success status
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO firewall_rules 
                (rule_name, rule_type, direction, protocol, source_ip, source_port,
                 destination_ip, destination_port, action, priority, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule_name, rule_type, direction,
                kwargs.get('protocol'),
                kwargs.get('source_ip'),
                kwargs.get('source_port'),
                kwargs.get('destination_ip'),
                kwargs.get('destination_port'),
                action,
                kwargs.get('priority', 100),
                kwargs.get('description', ''),
                datetime.now().isoformat(),
                datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            
            # Add to active rules
            self.active_rules[rule_name] = {
                'type': rule_type,
                'direction': direction,
                'action': action,
                **kwargs
            }
            
            return True
            
        except Exception as e:
            print(f"Error creating rule: {e}")
            return False
            
    def delete_rule(self, rule_name: str) -> bool:
        """Delete a firewall rule"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM firewall_rules WHERE rule_name = ?', (rule_name,))
            
            conn.commit()
            conn.close()
            
            # Remove from active rules
            if rule_name in self.active_rules:
                del self.active_rules[rule_name]
                
            return True
            
        except Exception as e:
            print(f"Error deleting rule: {e}")
            return False
            
    def enable_rule(self, rule_name: str) -> bool:
        """Enable a firewall rule"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE firewall_rules 
                SET is_active = TRUE, updated_at = ?
                WHERE rule_name = ?
            ''', (datetime.now().isoformat(), rule_name))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            print(f"Error enabling rule: {e}")
            return False
            
    def disable_rule(self, rule_name: str) -> bool:
        """Disable a firewall rule"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE firewall_rules 
                SET is_active = FALSE, updated_at = ?
                WHERE rule_name = ?
            ''', (datetime.now().isoformat(), rule_name))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            print(f"Error disabling rule: {e}")
            return False
            
    def get_all_rules(self) -> List[Dict]:
        """Get all firewall rules"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT rule_name, rule_type, direction, protocol, source_ip, source_port,
                   destination_ip, destination_port, action, priority, is_active, description
            FROM firewall_rules ORDER BY priority DESC, created_at DESC
        ''')
        
        rules = []
        for row in cursor.fetchall():
            rules.append({
                'rule_name': row[0],
                'rule_type': row[1],
                'direction': row[2],
                'protocol': row[3],
                'source_ip': row[4],
                'source_port': row[5],
                'destination_ip': row[6],
                'destination_port': row[7],
                'action': row[8],
                'priority': row[9],
                'is_active': bool(row[10]),
                'description': row[11]
            })
            
        conn.close()
        return rules
        
    def apply_security_policy(self, policy_name: str) -> bool:
        """Apply a security policy"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get policy
            cursor.execute('''
                SELECT policy_type, default_inbound, default_outbound,
                       allowed_ports, blocked_ports, allowed_ips, blocked_ips
                FROM security_policies WHERE policy_name = ?
            ''', (policy_name,))
            
            policy_row = cursor.fetchone()
            if not policy_row:
                conn.close()
                return False
                
            policy_type, default_inbound, default_outbound, allowed_ports, blocked_ports, allowed_ips, blocked_ips = policy_row
            
            # Clear existing rules
            cursor.execute('DELETE FROM firewall_rules WHERE rule_type = "policy"')
            
            # Create default rules
            cursor.execute('''
                INSERT INTO firewall_rules 
                (rule_name, rule_type, direction, action, priority, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                f"{policy_name}_inbound_default", "policy", "inbound", default_inbound,
                1, f"Default inbound policy for {policy_name}",
                datetime.now().isoformat(), datetime.now().isoformat()
            ))
            
            cursor.execute('''
                INSERT INTO firewall_rules 
                (rule_name, rule_type, direction, action, priority, description, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                f"{policy_name}_outbound_default", "policy", "outbound", default_outbound,
                1, f"Default outbound policy for {policy_name}",
                datetime.now().isoformat(), datetime.now().isoformat()
            ))
            
            # Create port rules
            if allowed_ports:
                ports = json.loads(allowed_ports)
                for port in ports:
                    cursor.execute('''
                        INSERT INTO firewall_rules 
                        (rule_name, rule_type, direction, destination_port, action, priority, description, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        f"{policy_name}_allow_port_{port}", "policy", "inbound", str(port), "allow",
                        10, f"Allow port {port} for {policy_name}",
                        datetime.now().isoformat(), datetime.now().isoformat()
                    ))
                    
            if blocked_ports:
                ports = json.loads(blocked_ports)
                for port in ports:
                    cursor.execute('''
                        INSERT INTO firewall_rules 
                        (rule_name, rule_type, direction, destination_port, action, priority, description, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        f"{policy_name}_block_port_{port}", "policy", "inbound", str(port), "deny",
                        5, f"Block port {port} for {policy_name}",
                        datetime.now().isoformat(), datetime.now().isoformat()
                    ))
                    
            # Update policy status
            cursor.execute('''
                UPDATE security_policies 
                SET is_active = CASE WHEN policy_name = ? THEN TRUE ELSE FALSE END,
                    updated_at = ?
            ''', (policy_name, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            print(f"Error applying policy: {e}")
            return False
            
    def check_packet(self, source_ip: str, source_port: int, destination_ip: str, 
                    destination_port: int, protocol: str, direction: str) -> Dict:
        """
        Check if a packet should be allowed or blocked
        Returns: Dict with action and rule information
        """
        result = {
            'action': 'allow',  # Default action
            'rule_name': 'default',
            'is_blocked': False,
            'threat_level': 'low'
        }
        
        # Get active rules
        rules = self.get_all_rules()
        
        # Check rules in priority order
        for rule in rules:
            if not rule['is_active']:
                continue
                
            if self._rule_matches_packet(rule, source_ip, source_port, destination_ip, 
                                       destination_port, protocol, direction):
                result['action'] = rule['action']
                result['rule_name'] = rule['rule_name']
                result['is_blocked'] = (rule['action'] == 'deny')
                break
                
        # Log the packet
        self._log_packet(source_ip, source_port, destination_ip, destination_port, 
                        protocol, direction, result)
                        
        return result
        
    def _rule_matches_packet(self, rule: Dict, source_ip: str, source_port: int,
                           destination_ip: str, destination_port: int, 
                           protocol: str, direction: str) -> bool:
        """Check if a rule matches a packet"""
        # Check direction
        if rule['direction'] != direction:
            return False
            
        # Check protocol
        if rule['protocol'] and rule['protocol'] != protocol:
            return False
            
        # Check source IP
        if rule['source_ip'] and not self._ip_matches_pattern(source_ip, rule['source_ip']):
            return False
            
        # Check source port
        if rule['source_port'] and not self._port_matches_pattern(source_port, rule['source_port']):
            return False
            
        # Check destination IP
        if rule['destination_ip'] and not self._ip_matches_pattern(destination_ip, rule['destination_ip']):
            return False
            
        # Check destination port
        if rule['destination_port'] and not self._port_matches_pattern(destination_port, rule['destination_port']):
            return False
            
        return True
        
    def _ip_matches_pattern(self, ip: str, pattern: str) -> bool:
        """Check if IP matches pattern"""
        if pattern == 'any':
            return True
        elif pattern == ip:
            return True
        elif '/' in pattern:  # CIDR notation
            try:
                import ipaddress
                return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern)
            except:
                return False
        else:
            return False
            
    def _port_matches_pattern(self, port: int, pattern: str) -> bool:
        """Check if port matches pattern"""
        if pattern == 'any':
            return True
        elif pattern == str(port):
            return True
        elif '-' in pattern:  # Port range
            try:
                start, end = map(int, pattern.split('-'))
                return start <= port <= end
            except:
                return False
        else:
            return False
            
    def _log_packet(self, source_ip: str, source_port: int, destination_ip: str,
                   destination_port: int, protocol: str, direction: str, result: Dict):
        """Log packet information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO firewall_logs 
            (timestamp, rule_name, source_ip, source_port, destination_ip, destination_port,
             protocol, action, packet_size, flags, is_blocked, threat_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(), result['rule_name'], source_ip, source_port,
            destination_ip, destination_port, protocol, result['action'],
            random.randint(64, 1500), random.choice(['SYN', 'ACK', 'FIN', 'RST']),
            result['is_blocked'], result['threat_level']
        ))
        
        conn.commit()
        conn.close()
        
    def get_firewall_logs(self, limit: int = 100) -> List[Dict]:
        """Get firewall logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, rule_name, source_ip, source_port, destination_ip, destination_port,
                   protocol, action, is_blocked, threat_level
            FROM firewall_logs ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'timestamp': row[0],
                'rule_name': row[1],
                'source_ip': row[2],
                'source_port': row[3],
                'destination_ip': row[4],
                'destination_port': row[5],
                'protocol': row[6],
                'action': row[7],
                'is_blocked': bool(row[8]),
                'threat_level': row[9]
            })
            
        conn.close()
        return logs
        
    def detect_intrusion(self, source_ip: str, attack_type: str, 
                        attack_signature: str = None) -> bool:
        """Detect and log intrusion attempts"""
        threat_level = 'medium'
        
        # Determine threat level based on attack type
        if attack_type in ['brute_force', 'sql_injection', 'xss']:
            threat_level = 'high'
        elif attack_type in ['port_scan', 'ping_flood']:
            threat_level = 'medium'
        else:
            threat_level = 'low'
            
        # Log intrusion
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO intrusion_detection 
            (timestamp, source_ip, attack_type, attack_signature, threat_level, action_taken, description)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(), source_ip, attack_type, attack_signature,
            threat_level, 'logged', f"Detected {attack_type} attack from {source_ip}"
        ))
        
        conn.commit()
        conn.close()
        
        # Auto-block if high threat
        if threat_level == 'high':
            self.create_rule(
                f"block_{source_ip}_{int(time.time())}",
                "block",
                "inbound",
                "deny",
                source_ip=source_ip,
                description=f"Auto-blocked due to {attack_type} attack"
            )
            return True
            
        return False
        
    def get_firewall_statistics(self) -> Dict:
        """Get firewall statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM firewall_rules')
        total_rules = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM firewall_rules WHERE is_active = TRUE')
        active_rules = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM firewall_logs')
        total_logs = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM firewall_logs WHERE is_blocked = TRUE')
        blocked_packets = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM intrusion_detection')
        intrusions = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_rules': total_rules,
            'active_rules': active_rules,
            'total_logs': total_logs,
            'blocked_packets': blocked_packets,
            'intrusions_detected': intrusions,
            'last_updated': datetime.now().isoformat()
        } 