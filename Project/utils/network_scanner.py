#!/usr/bin/env python3
"""
Network Scanner Utility for WebSecGuard
Comprehensive network security analysis and threat detection
"""

import socket
import threading
import time
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
import ipaddress
import struct
import random

class NetworkScanner:
    """Advanced network security scanner"""
    
    def __init__(self, db_path="network_data.db"):
        self.db_path = db_path
        self.init_network_database()
        
        # Common ports and services
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP',
            5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        
        # Known malicious IPs (simulated)
        self.malicious_ips = {
            '192.168.1.100': 'malware_c2',
            '10.0.0.50': 'phishing_server',
            '172.16.0.25': 'botnet_controller'
        }
        
        # Suspicious port patterns
        self.suspicious_ports = {
            22: 'SSH brute force attempts',
            23: 'Telnet (insecure)',
            3389: 'RDP attacks',
            1433: 'SQL injection attempts',
            3306: 'Database attacks'
        }
        
        # Network protocols
        self.protocols = {
            1: 'ICMP', 6: 'TCP', 17: 'UDP'
        }
        
    def init_network_database(self):
        """Initialize the network database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create network scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                target_network TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT,
                status TEXT DEFAULT 'running',
                total_hosts INTEGER DEFAULT 0,
                live_hosts INTEGER DEFAULT 0,
                open_ports INTEGER DEFAULT 0,
                threats_found INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Create host discovery table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS host_discovery (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                hostname TEXT,
                mac_address TEXT,
                vendor TEXT,
                os_detection TEXT,
                response_time REAL,
                is_live BOOLEAN DEFAULT FALSE,
                last_seen TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES network_scans (scan_id)
            )
        ''')
        
        # Create port scan table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS port_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                service TEXT,
                version TEXT,
                state TEXT NOT NULL,
                banner TEXT,
                vulnerability_score INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES network_scans (scan_id)
            )
        ''')
        
        # Create threat detection table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_detection (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                cve_references TEXT,
                remediation TEXT,
                detected_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES network_scans (scan_id)
            )
        ''')
        
        # Create network traffic table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_traffic (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip TEXT NOT NULL,
                destination_ip TEXT NOT NULL,
                source_port INTEGER,
                destination_port INTEGER,
                protocol TEXT NOT NULL,
                packet_size INTEGER,
                flags TEXT,
                timestamp TEXT NOT NULL,
                is_suspicious BOOLEAN DEFAULT FALSE,
                threat_indicators TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def generate_scan_id(self) -> str:
        """Generate unique scan ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_suffix = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=6))
        return f"scan_{timestamp}_{random_suffix}"
        
    def scan_network(self, network: str, scan_type: str = 'comprehensive') -> str:
        """
        Start a network scan
        Args:
            network: Network range (e.g., '192.168.1.0/24')
            scan_type: Type of scan ('quick', 'comprehensive', 'stealth')
        Returns: Scan ID
        """
        scan_id = self.generate_scan_id()
        
        # Initialize scan record
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO network_scans 
            (scan_id, target_network, scan_type, start_time, created_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (scan_id, network, scan_type, datetime.now().isoformat(), datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        # Start scan in background thread
        scan_thread = threading.Thread(
            target=self._run_network_scan,
            args=(scan_id, network, scan_type)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return scan_id
        
    def _run_network_scan(self, scan_id: str, network: str, scan_type: str):
        """Run the actual network scan"""
        try:
            # Parse network range
            network_obj = ipaddress.IPv4Network(network, strict=False)
            total_hosts = network_obj.num_addresses
            
            # Update scan with total hosts
            self._update_scan_progress(scan_id, total_hosts=total_hosts)
            
            live_hosts = 0
            open_ports = 0
            threats_found = 0
            
            # Scan each host
            for ip in network_obj.hosts():
                ip_str = str(ip)
                
                # Host discovery
                if self._is_host_live(ip_str, scan_type):
                    live_hosts += 1
                    self._record_host_discovery(scan_id, ip_str)
                    
                    # Port scanning
                    if scan_type in ['comprehensive', 'stealth']:
                        host_open_ports = self._scan_host_ports(scan_id, ip_str, scan_type)
                        open_ports += host_open_ports
                        
                        # Threat detection
                        host_threats = self._detect_host_threats(scan_id, ip_str)
                        threats_found += host_threats
                        
                # Update progress
                self._update_scan_progress(scan_id, live_hosts=live_hosts, 
                                         open_ports=open_ports, threats_found=threats_found)
                
            # Mark scan as complete
            self._complete_scan(scan_id)
            
        except Exception as e:
            self._fail_scan(scan_id, str(e))
            
    def _is_host_live(self, ip: str, scan_type: str) -> bool:
        """Check if host is live using various methods"""
        if scan_type == 'quick':
            # Quick ping scan
            return self._ping_host(ip)
        elif scan_type == 'comprehensive':
            # Multiple detection methods
            return (self._ping_host(ip) or 
                   self._tcp_connect(ip, 80) or 
                   self._tcp_connect(ip, 443))
        else:  # stealth
            # Stealth detection
            return self._stealth_detection(ip)
            
    def _ping_host(self, ip: str) -> bool:
        """Ping host to check if live"""
        try:
            # Simulate ping response
            response_time = random.uniform(1, 100)
            return response_time < 50  # Simulate some hosts being unreachable
        except:
            return False
            
    def _tcp_connect(self, ip: str, port: int) -> bool:
        """Attempt TCP connection to check if host is live"""
        try:
            # Simulate TCP connection
            return random.choice([True, False, False])  # 33% success rate
        except:
            return False
            
    def _stealth_detection(self, ip: str) -> bool:
        """Stealth host detection"""
        try:
            # Simulate stealth detection
            return random.choice([True, True, False])  # 66% success rate
        except:
            return False
            
    def _scan_host_ports(self, scan_id: str, ip: str, scan_type: str) -> int:
        """Scan ports on a host"""
        open_ports = 0
        
        # Determine which ports to scan
        if scan_type == 'comprehensive':
            ports_to_scan = list(self.common_ports.keys())
        else:  # stealth
            ports_to_scan = [80, 443, 22, 21, 23, 25, 53, 110, 143]
            
        for port in ports_to_scan:
            if self._is_port_open(ip, port):
                open_ports += 1
                self._record_port_scan(scan_id, ip, port)
                
        return open_ports
        
    def _is_port_open(self, ip: str, port: int) -> bool:
        """Check if port is open"""
        try:
            # Simulate port check
            if port in [80, 443, 22, 21]:
                return random.choice([True, True, False])  # 66% success for common ports
            else:
                return random.choice([True, False, False, False])  # 25% success for other ports
        except:
            return False
            
    def _detect_host_threats(self, scan_id: str, ip: str) -> int:
        """Detect threats on a host"""
        threats_found = 0
        
        # Check for known malicious IPs
        if ip in self.malicious_ips:
            self._record_threat(scan_id, ip, 'malicious_ip', 'high', 
                              f"IP is known {self.malicious_ips[ip]}")
            threats_found += 1
            
        # Check for suspicious open ports
        suspicious_ports = self._get_suspicious_ports(ip)
        for port in suspicious_ports:
            self._record_threat(scan_id, ip, 'suspicious_port', 'medium',
                              f"Suspicious port {port} open: {self.suspicious_ports.get(port, 'Unknown')}")
            threats_found += 1
            
        # Check for vulnerable services
        vulnerable_services = self._check_service_vulnerabilities(ip)
        for service in vulnerable_services:
            self._record_threat(scan_id, ip, 'vulnerable_service', 'high',
                              f"Vulnerable service detected: {service}")
            threats_found += 1
            
        return threats_found
        
    def _get_suspicious_ports(self, ip: str) -> List[int]:
        """Get suspicious open ports for an IP"""
        # Simulate finding suspicious ports
        suspicious = []
        if random.choice([True, False]):
            suspicious.append(22)  # SSH
        if random.choice([True, False, False]):
            suspicious.append(23)  # Telnet
        if random.choice([True, False, False, False]):
            suspicious.append(3389)  # RDP
        return suspicious
        
    def _check_service_vulnerabilities(self, ip: str) -> List[str]:
        """Check for vulnerable services"""
        vulnerabilities = []
        
        # Simulate vulnerability detection
        if random.choice([True, False, False, False]):
            vulnerabilities.append("Outdated SSH version")
        if random.choice([True, False, False, False, False]):
            vulnerabilities.append("Weak SSL/TLS configuration")
        if random.choice([True, False, False, False, False, False]):
            vulnerabilities.append("Default credentials")
            
        return vulnerabilities
        
    def _record_host_discovery(self, scan_id: str, ip: str):
        """Record host discovery"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO host_discovery 
            (scan_id, ip_address, hostname, mac_address, vendor, os_detection, 
             response_time, is_live, last_seen, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id, ip, f"host-{ip.replace('.', '-')}", 
            f"AA:BB:CC:DD:EE:{random.randint(10, 99):02X}",
            "Unknown Vendor", "Unknown OS", random.uniform(1, 50),
            True, datetime.now().isoformat(), datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
    def _record_port_scan(self, scan_id: str, ip: str, port: int):
        """Record port scan result"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        service = self.common_ports.get(port, 'Unknown')
        banner = f"{service} Server" if service != 'Unknown' else ''
        
        cursor.execute('''
            INSERT INTO port_scans 
            (scan_id, ip_address, port, protocol, service, version, state, banner, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_id, ip, port, 'TCP', service, '1.0', 'open', banner, datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
    def _record_threat(self, scan_id: str, ip: str, threat_type: str, 
                      threat_level: str, description: str):
        """Record threat detection"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO threat_detection 
            (scan_id, ip_address, threat_type, threat_level, description, detected_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            scan_id, ip, threat_type, threat_level, description, datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
    def _update_scan_progress(self, scan_id: str, **kwargs):
        """Update scan progress"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        update_fields = []
        values = []
        for key, value in kwargs.items():
            update_fields.append(f"{key} = ?")
            values.append(value)
            
        if update_fields:
            values.append(scan_id)
            cursor.execute(f'''
                UPDATE network_scans 
                SET {', '.join(update_fields)}
                WHERE scan_id = ?
            ''', values)
            
        conn.commit()
        conn.close()
        
    def _complete_scan(self, scan_id: str):
        """Mark scan as complete"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE network_scans 
            SET status = 'completed', end_time = ?
            WHERE scan_id = ?
        ''', (datetime.now().isoformat(), scan_id))
        
        conn.commit()
        conn.close()
        
    def _fail_scan(self, scan_id: str, error: str):
        """Mark scan as failed"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE network_scans 
            SET status = 'failed', end_time = ?
            WHERE scan_id = ?
        ''', (datetime.now().isoformat(), scan_id))
        
        conn.commit()
        conn.close()
        
    def get_scan_status(self, scan_id: str) -> Dict:
        """Get scan status and results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get scan info
        cursor.execute('''
            SELECT target_network, scan_type, start_time, end_time, status,
                   total_hosts, live_hosts, open_ports, threats_found
            FROM network_scans WHERE scan_id = ?
        ''', (scan_id,))
        
        scan_row = cursor.fetchone()
        if not scan_row:
            conn.close()
            return {'error': 'Scan not found'}
            
        scan_info = {
            'scan_id': scan_id,
            'target_network': scan_row[0],
            'scan_type': scan_row[1],
            'start_time': scan_row[2],
            'end_time': scan_row[3],
            'status': scan_row[4],
            'total_hosts': scan_row[5],
            'live_hosts': scan_row[6],
            'open_ports': scan_row[7],
            'threats_found': scan_row[8]
        }
        
        # Get discovered hosts
        cursor.execute('''
            SELECT ip_address, hostname, mac_address, vendor, os_detection, response_time
            FROM host_discovery WHERE scan_id = ?
        ''', (scan_id,))
        
        hosts = []
        for row in cursor.fetchall():
            hosts.append({
                'ip_address': row[0],
                'hostname': row[1],
                'mac_address': row[2],
                'vendor': row[3],
                'os_detection': row[4],
                'response_time': row[5]
            })
            
        # Get open ports
        cursor.execute('''
            SELECT ip_address, port, protocol, service, version, state, banner
            FROM port_scans WHERE scan_id = ?
        ''', (scan_id,))
        
        ports = []
        for row in cursor.fetchall():
            ports.append({
                'ip_address': row[0],
                'port': row[1],
                'protocol': row[2],
                'service': row[3],
                'version': row[4],
                'state': row[5],
                'banner': row[6]
            })
            
        # Get threats
        cursor.execute('''
            SELECT ip_address, threat_type, threat_level, description
            FROM threat_detection WHERE scan_id = ?
        ''', (scan_id,))
        
        threats = []
        for row in cursor.fetchall():
            threats.append({
                'ip_address': row[0],
                'threat_type': row[1],
                'threat_level': row[2],
                'description': row[3]
            })
            
        conn.close()
        
        return {
            **scan_info,
            'hosts': hosts,
            'ports': ports,
            'threats': threats
        }
        
    def get_all_scans(self) -> List[Dict]:
        """Get all network scans"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT scan_id, target_network, scan_type, start_time, end_time, status,
                   total_hosts, live_hosts, open_ports, threats_found
            FROM network_scans ORDER BY start_time DESC
        ''')
        
        scans = []
        for row in cursor.fetchall():
            scans.append({
                'scan_id': row[0],
                'target_network': row[1],
                'scan_type': row[2],
                'start_time': row[3],
                'end_time': row[4],
                'status': row[5],
                'total_hosts': row[6],
                'live_hosts': row[7],
                'open_ports': row[8],
                'threats_found': row[9]
            })
            
        conn.close()
        return scans
        
    def monitor_network_traffic(self, duration: int = 300) -> Dict:
        """
        Monitor network traffic for suspicious activity
        Args:
            duration: Monitoring duration in seconds
        Returns: Traffic analysis results
        """
        start_time = datetime.now()
        end_time = start_time + timedelta(seconds=duration)
        
        traffic_data = []
        suspicious_connections = []
        
        # Simulate traffic monitoring
        while datetime.now() < end_time:
            # Generate simulated traffic
            traffic = self._generate_simulated_traffic()
            traffic_data.append(traffic)
            
            # Check for suspicious patterns
            if self._is_suspicious_traffic(traffic):
                suspicious_connections.append(traffic)
                self._record_suspicious_traffic(traffic)
                
            time.sleep(1)  # Simulate real-time monitoring
            
        return {
            'monitoring_duration': duration,
            'total_connections': len(traffic_data),
            'suspicious_connections': len(suspicious_connections),
            'traffic_summary': self._analyze_traffic_patterns(traffic_data),
            'suspicious_patterns': self._identify_suspicious_patterns(suspicious_connections)
        }
        
    def _generate_simulated_traffic(self) -> Dict:
        """Generate simulated network traffic"""
        protocols = ['TCP', 'UDP', 'ICMP']
        protocol = random.choice(protocols)
        
        # Generate random IPs
        source_ip = f"192.168.1.{random.randint(1, 254)}"
        dest_ip = f"192.168.1.{random.randint(1, 254)}"
        
        # Generate random ports for TCP/UDP
        source_port = random.randint(1024, 65535) if protocol in ['TCP', 'UDP'] else None
        dest_port = random.randint(1, 65535) if protocol in ['TCP', 'UDP'] else None
        
        return {
            'source_ip': source_ip,
            'destination_ip': dest_ip,
            'source_port': source_port,
            'destination_port': dest_port,
            'protocol': protocol,
            'packet_size': random.randint(64, 1500),
            'flags': random.choice(['SYN', 'ACK', 'FIN', 'RST', 'PSH', 'URG']),
            'timestamp': datetime.now().isoformat(),
            'is_suspicious': False
        }
        
    def _is_suspicious_traffic(self, traffic: Dict) -> bool:
        """Check if traffic is suspicious"""
        # Check for known malicious patterns
        if traffic['destination_ip'] in self.malicious_ips:
            return True
            
        # Check for suspicious port combinations
        if (traffic['destination_port'] in [22, 23, 3389] and 
            traffic['packet_size'] < 100):
            return True  # Potential brute force attack
            
        # Check for unusual packet sizes
        if traffic['packet_size'] > 1400:
            return True  # Potential data exfiltration
            
        # Check for rapid connections
        return random.choice([True, False, False, False, False])  # 20% suspicious
        
    def _record_suspicious_traffic(self, traffic: Dict):
        """Record suspicious traffic in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO network_traffic 
            (source_ip, destination_ip, source_port, destination_port, protocol,
             packet_size, flags, timestamp, is_suspicious, threat_indicators)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            traffic['source_ip'], traffic['destination_ip'], traffic['source_port'],
            traffic['destination_port'], traffic['protocol'], traffic['packet_size'],
            traffic['flags'], traffic['timestamp'], True, json.dumps(['suspicious_pattern'])
        ))
        
        conn.commit()
        conn.close()
        
    def _analyze_traffic_patterns(self, traffic_data: List[Dict]) -> Dict:
        """Analyze traffic patterns"""
        protocols = {}
        ports = {}
        ips = {}
        
        for traffic in traffic_data:
            # Protocol analysis
            protocol = traffic['protocol']
            protocols[protocol] = protocols.get(protocol, 0) + 1
            
            # Port analysis
            if traffic['destination_port']:
                port = traffic['destination_port']
                ports[port] = ports.get(port, 0) + 1
                
            # IP analysis
            dest_ip = traffic['destination_ip']
            ips[dest_ip] = ips.get(dest_ip, 0) + 1
            
        return {
            'protocol_distribution': protocols,
            'top_ports': sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10],
            'top_destinations': sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10],
            'total_packets': len(traffic_data)
        }
        
    def _identify_suspicious_patterns(self, suspicious_connections: List[Dict]) -> List[Dict]:
        """Identify suspicious traffic patterns"""
        patterns = []
        
        # Group by source IP
        source_groups = {}
        for conn in suspicious_connections:
            source_ip = conn['source_ip']
            if source_ip not in source_groups:
                source_groups[source_ip] = []
            source_groups[source_ip].append(conn)
            
        # Analyze patterns
        for source_ip, connections in source_groups.items():
            if len(connections) > 5:
                patterns.append({
                    'pattern_type': 'high_connection_rate',
                    'source_ip': source_ip,
                    'connection_count': len(connections),
                    'description': f"High connection rate from {source_ip}"
                })
                
        return patterns 