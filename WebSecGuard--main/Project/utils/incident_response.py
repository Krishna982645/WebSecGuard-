#!/usr/bin/env python3
"""
Incident Response Utility for WebSecGuard
Comprehensive incident response and management system
"""

import sqlite3
import json
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import random
import hashlib

class IncidentResponse:
    """Advanced incident response and management system"""
    
    def __init__(self, db_path="incident_response.db"):
        self.db_path = db_path
        self.init_incident_database()
        
        # Incident severity levels
        self.severity_levels = {
            'low': {
                'response_time': 24,  # hours
                'escalation_time': 48,
                'auto_resolution': True
            },
            'medium': {
                'response_time': 4,
                'escalation_time': 8,
                'auto_resolution': False
            },
            'high': {
                'response_time': 1,
                'escalation_time': 2,
                'auto_resolution': False
            },
            'critical': {
                'response_time': 0.5,
                'escalation_time': 1,
                'auto_resolution': False
            }
        }
        
        # Incident types
        self.incident_types = {
            'malware_infection': {
                'severity': 'high',
                'category': 'malware',
                'response_team': 'malware_response',
                'procedures': ['isolate_system', 'scan_for_malware', 'remove_threat', 'restore_system']
            },
            'data_breach': {
                'severity': 'critical',
                'category': 'data_security',
                'response_team': 'incident_response',
                'procedures': ['contain_breach', 'assess_damage', 'notify_stakeholders', 'implement_remediation']
            },
            'network_intrusion': {
                'severity': 'high',
                'category': 'network_security',
                'response_team': 'network_security',
                'procedures': ['block_intruder', 'analyze_attack', 'patch_vulnerabilities', 'monitor_network']
            },
            'phishing_attack': {
                'severity': 'medium',
                'category': 'social_engineering',
                'response_team': 'security_awareness',
                'procedures': ['block_phishing_urls', 'notify_users', 'update_filters', 'conduct_training']
            },
            'ddos_attack': {
                'severity': 'high',
                'category': 'network_security',
                'response_team': 'network_operations',
                'procedures': ['activate_ddos_protection', 'monitor_traffic', 'contact_isp', 'implement_mitigation']
            },
            'insider_threat': {
                'severity': 'critical',
                'category': 'internal_security',
                'response_team': 'hr_security',
                'procedures': ['investigate_employee', 'restrict_access', 'gather_evidence', 'take_disciplinary_action']
            }
        }
        
        # Response teams
        self.response_teams = {
            'incident_response': {
                'members': ['security_analyst', 'incident_manager', 'forensic_analyst'],
                'contact': 'incident-response@company.com',
                'phone': '+1-555-0123'
            },
            'malware_response': {
                'members': ['malware_analyst', 'system_admin', 'security_engineer'],
                'contact': 'malware-response@company.com',
                'phone': '+1-555-0124'
            },
            'network_security': {
                'members': ['network_admin', 'security_engineer', 'network_analyst'],
                'contact': 'network-security@company.com',
                'phone': '+1-555-0125'
            },
            'hr_security': {
                'members': ['hr_manager', 'security_manager', 'legal_counsel'],
                'contact': 'hr-security@company.com',
                'phone': '+1-555-0126'
            }
        }
        
    def init_incident_database(self):
        """Initialize the incident response database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create incidents table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT UNIQUE NOT NULL,
                incident_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT DEFAULT 'open',
                title TEXT NOT NULL,
                description TEXT,
                affected_systems TEXT,
                affected_users TEXT,
                initial_impact TEXT,
                current_impact TEXT,
                response_team TEXT,
                assigned_to TEXT,
                reported_by TEXT,
                reported_at TEXT NOT NULL,
                detected_at TEXT,
                resolved_at TEXT,
                sla_deadline TEXT,
                escalation_deadline TEXT
            )
        ''')
        
        # Create incident timeline table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS incident_timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT,
                performed_by TEXT,
                evidence TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')
        
        # Create response procedures table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS response_procedures (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                procedure_name TEXT NOT NULL,
                procedure_description TEXT,
                status TEXT DEFAULT 'pending',
                assigned_to TEXT,
                started_at TEXT,
                completed_at TEXT,
                notes TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')
        
        # Create evidence table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS evidence (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                evidence_id TEXT UNIQUE NOT NULL,
                evidence_type TEXT NOT NULL,
                description TEXT,
                file_path TEXT,
                hash_value TEXT,
                collected_by TEXT,
                collected_at TEXT NOT NULL,
                chain_of_custody TEXT,
                is_analyzed BOOLEAN DEFAULT FALSE,
                analysis_results TEXT,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')
        
        # Create communications table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS communications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                communication_type TEXT NOT NULL,
                recipient TEXT,
                subject TEXT,
                message TEXT,
                sent_by TEXT,
                sent_at TEXT NOT NULL,
                status TEXT DEFAULT 'sent',
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')
        
        # Create lessons learned table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS lessons_learned (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                lesson_category TEXT NOT NULL,
                lesson_description TEXT,
                recommendations TEXT,
                implemented_changes TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (incident_id) REFERENCES incidents (incident_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def create_incident(self, incident_type: str, title: str, description: str,
                       affected_systems: List[str] = None, affected_users: List[str] = None,
                       reported_by: str = None) -> str:
        """
        Create a new security incident
        Args:
            incident_type: Type of incident
            title: Incident title
            description: Incident description
            affected_systems: List of affected systems
            affected_users: List of affected users
            reported_by: Person who reported the incident
        Returns: Incident ID
        """
        if incident_type not in self.incident_types:
            raise ValueError(f"Unknown incident type: {incident_type}")
            
        incident_info = self.incident_types[incident_type]
        severity = incident_info['severity']
        response_team = incident_info['response_team']
        
        # Calculate deadlines
        response_time = self.severity_levels[severity]['response_time']
        escalation_time = self.severity_levels[severity]['escalation_time']
        
        detected_at = datetime.now()
        sla_deadline = detected_at + timedelta(hours=response_time)
        escalation_deadline = detected_at + timedelta(hours=escalation_time)
        
        # Generate incident ID
        incident_id = f"inc_{detected_at.strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
        
        # Store incident
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO incidents 
            (incident_id, incident_type, severity, title, description, affected_systems,
             affected_users, response_team, reported_by, reported_at, detected_at,
             sla_deadline, escalation_deadline)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident_id, incident_type, severity, title, description,
            json.dumps(affected_systems or []), json.dumps(affected_users or []),
            response_team, reported_by or 'system', detected_at.isoformat(),
            detected_at.isoformat(), sla_deadline.isoformat(), escalation_deadline.isoformat()
        ))
        
        # Create initial timeline entry
        cursor.execute('''
            INSERT INTO incident_timeline 
            (incident_id, timestamp, event_type, description, performed_by)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            incident_id, detected_at.isoformat(), 'incident_created',
            f"Incident created: {title}", reported_by or 'system'
        ))
        
        # Create response procedures
        for procedure in incident_info['procedures']:
            cursor.execute('''
                INSERT INTO response_procedures 
                (incident_id, procedure_name, procedure_description)
                VALUES (?, ?, ?)
            ''', (incident_id, procedure, f"Execute {procedure} procedure"))
            
        conn.commit()
        conn.close()
        
        # Auto-assign if low severity
        if self.severity_levels[severity]['auto_resolution']:
            self.auto_resolve_incident(incident_id)
            
        return incident_id
        
    def assign_incident(self, incident_id: str, assigned_to: str) -> bool:
        """Assign incident to a responder"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE incidents 
                SET assigned_to = ?
                WHERE incident_id = ?
            ''', (assigned_to, incident_id))
            
            # Add timeline entry
            cursor.execute('''
                INSERT INTO incident_timeline 
                (incident_id, timestamp, event_type, description, performed_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                incident_id, datetime.now().isoformat(), 'incident_assigned',
                f"Incident assigned to {assigned_to}", 'system'
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error assigning incident: {e}")
            return False
            
    def update_incident_status(self, incident_id: str, status: str, 
                             description: str = None, performed_by: str = None) -> bool:
        """Update incident status"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE incidents 
                SET status = ?
                WHERE incident_id = ?
            ''', (status, incident_id))
            
            # Add timeline entry
            cursor.execute('''
                INSERT INTO incident_timeline 
                (incident_id, timestamp, event_type, description, performed_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                incident_id, datetime.now().isoformat(), 'status_updated',
                f"Status updated to {status}: {description or ''}", performed_by or 'system'
            ))
            
            # Set resolved_at if status is resolved
            if status == 'resolved':
                cursor.execute('''
                    UPDATE incidents 
                    SET resolved_at = ?
                    WHERE incident_id = ?
                ''', (datetime.now().isoformat(), incident_id))
                
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error updating incident status: {e}")
            return False
            
    def add_timeline_event(self, incident_id: str, event_type: str, description: str,
                          performed_by: str = None, evidence: str = None) -> bool:
        """Add event to incident timeline"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO incident_timeline 
                (incident_id, timestamp, event_type, description, performed_by, evidence)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                incident_id, datetime.now().isoformat(), event_type, description,
                performed_by or 'system', evidence
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error adding timeline event: {e}")
            return False
            
    def collect_evidence(self, incident_id: str, evidence_type: str, description: str,
                        file_path: str = None, collected_by: str = None) -> str:
        """Collect evidence for incident"""
        evidence_id = f"evid_{int(time.time())}_{random.randint(1000, 9999)}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO evidence 
            (incident_id, evidence_id, evidence_type, description, file_path,
             hash_value, collected_by, collected_at, chain_of_custody)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            incident_id, evidence_id, evidence_type, description, file_path,
            hashlib.sha256(f"{evidence_id}{description}".encode()).hexdigest(),
            collected_by or 'system', datetime.now().isoformat(),
            f"Collected by {collected_by or 'system'} at {datetime.now().isoformat()}"
        ))
        
        conn.commit()
        conn.close()
        
        return evidence_id
        
    def send_communication(self, incident_id: str, communication_type: str,
                          recipient: str, subject: str, message: str,
                          sent_by: str = None) -> bool:
        """Send communication for incident"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO communications 
                (incident_id, communication_type, recipient, subject, message, sent_by, sent_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident_id, communication_type, recipient, subject, message,
                sent_by or 'system', datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error sending communication: {e}")
            return False
            
    def complete_procedure(self, incident_id: str, procedure_name: str,
                          notes: str = None, completed_by: str = None) -> bool:
        """Mark a response procedure as completed"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE response_procedures 
                SET status = 'completed', completed_at = ?, notes = ?
                WHERE incident_id = ? AND procedure_name = ?
            ''', (datetime.now().isoformat(), notes, incident_id, procedure_name))
            
            # Add timeline entry
            cursor.execute('''
                INSERT INTO incident_timeline 
                (incident_id, timestamp, event_type, description, performed_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                incident_id, datetime.now().isoformat(), 'procedure_completed',
                f"Completed procedure: {procedure_name}", completed_by or 'system'
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error completing procedure: {e}")
            return False
            
    def auto_resolve_incident(self, incident_id: str) -> bool:
        """Automatically resolve low-severity incidents"""
        try:
            # Get incident info
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT severity FROM incidents WHERE incident_id = ?
            ''', (incident_id,))
            
            row = cursor.fetchone()
            if not row:
                conn.close()
                return False
                
            severity = row[0]
            
            # Only auto-resolve low severity incidents
            if severity != 'low':
                conn.close()
                return False
                
            # Auto-complete procedures
            cursor.execute('''
                UPDATE response_procedures 
                SET status = 'completed', completed_at = ?, notes = 'Auto-completed'
                WHERE incident_id = ?
            ''', (datetime.now().isoformat(), incident_id))
            
            # Resolve incident
            cursor.execute('''
                UPDATE incidents 
                SET status = 'resolved', resolved_at = ?
                WHERE incident_id = ?
            ''', (datetime.now().isoformat(), incident_id))
            
            # Add timeline entry
            cursor.execute('''
                INSERT INTO incident_timeline 
                (incident_id, timestamp, event_type, description, performed_by)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                incident_id, datetime.now().isoformat(), 'incident_auto_resolved',
                'Incident automatically resolved', 'system'
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error auto-resolving incident: {e}")
            return False
            
    def get_incident_details(self, incident_id: str) -> Dict:
        """Get detailed incident information"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get incident info
        cursor.execute('''
            SELECT incident_type, severity, status, title, description, affected_systems,
                   affected_users, response_team, assigned_to, reported_by, reported_at,
                   detected_at, resolved_at, sla_deadline, escalation_deadline
            FROM incidents WHERE incident_id = ?
        ''', (incident_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {'error': 'Incident not found'}
            
        incident_info = {
            'incident_id': incident_id,
            'incident_type': row[0],
            'severity': row[1],
            'status': row[2],
            'title': row[3],
            'description': row[4],
            'affected_systems': json.loads(row[5]) if row[5] else [],
            'affected_users': json.loads(row[6]) if row[6] else [],
            'response_team': row[7],
            'assigned_to': row[8],
            'reported_by': row[9],
            'reported_at': row[10],
            'detected_at': row[11],
            'resolved_at': row[12],
            'sla_deadline': row[13],
            'escalation_deadline': row[14]
        }
        
        # Get timeline
        cursor.execute('''
            SELECT timestamp, event_type, description, performed_by, evidence
            FROM incident_timeline WHERE incident_id = ? ORDER BY timestamp
        ''', (incident_id,))
        
        timeline = []
        for timeline_row in cursor.fetchall():
            timeline.append({
                'timestamp': timeline_row[0],
                'event_type': timeline_row[1],
                'description': timeline_row[2],
                'performed_by': timeline_row[3],
                'evidence': timeline_row[4]
            })
            
        # Get procedures
        cursor.execute('''
            SELECT procedure_name, procedure_description, status, assigned_to,
                   started_at, completed_at, notes
            FROM response_procedures WHERE incident_id = ?
        ''', (incident_id,))
        
        procedures = []
        for proc_row in cursor.fetchall():
            procedures.append({
                'procedure_name': proc_row[0],
                'procedure_description': proc_row[1],
                'status': proc_row[2],
                'assigned_to': proc_row[3],
                'started_at': proc_row[4],
                'completed_at': proc_row[5],
                'notes': proc_row[6]
            })
            
        # Get evidence
        cursor.execute('''
            SELECT evidence_id, evidence_type, description, file_path, hash_value,
                   collected_by, collected_at, is_analyzed, analysis_results
            FROM evidence WHERE incident_id = ?
        ''', (incident_id,))
        
        evidence = []
        for evid_row in cursor.fetchall():
            evidence.append({
                'evidence_id': evid_row[0],
                'evidence_type': evid_row[1],
                'description': evid_row[2],
                'file_path': evid_row[3],
                'hash_value': evid_row[4],
                'collected_by': evid_row[5],
                'collected_at': evid_row[6],
                'is_analyzed': bool(evid_row[7]),
                'analysis_results': evid_row[8]
            })
            
        conn.close()
        
        return {
            **incident_info,
            'timeline': timeline,
            'procedures': procedures,
            'evidence': evidence
        }
        
    def get_all_incidents(self, status: str = None) -> List[Dict]:
        """Get all incidents"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute('''
                SELECT incident_id, incident_type, severity, status, title, reported_at,
                       assigned_to, response_team
                FROM incidents WHERE status = ? ORDER BY reported_at DESC
            ''', (status,))
        else:
            cursor.execute('''
                SELECT incident_id, incident_type, severity, status, title, reported_at,
                       assigned_to, response_team
                FROM incidents ORDER BY reported_at DESC
            ''')
        
        incidents = []
        for row in cursor.fetchall():
            incidents.append({
                'incident_id': row[0],
                'incident_type': row[1],
                'severity': row[2],
                'status': row[3],
                'title': row[4],
                'reported_at': row[5],
                'assigned_to': row[6],
                'response_team': row[7]
            })
            
        conn.close()
        return incidents
        
    def add_lesson_learned(self, incident_id: str, lesson_category: str,
                          lesson_description: str, recommendations: str,
                          implemented_changes: str = None, created_by: str = None) -> bool:
        """Add lesson learned from incident"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO lessons_learned 
                (incident_id, lesson_category, lesson_description, recommendations,
                 implemented_changes, created_by, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                incident_id, lesson_category, lesson_description, recommendations,
                implemented_changes, created_by or 'system', datetime.now().isoformat()
            ))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error adding lesson learned: {e}")
            return False
            
    def get_incident_statistics(self) -> Dict:
        """Get incident response statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM incidents')
        total_incidents = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM incidents WHERE status = "open"')
        open_incidents = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM incidents WHERE status = "resolved"')
        resolved_incidents = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM incidents 
            GROUP BY severity
        ''')
        incidents_by_severity = dict(cursor.fetchall())
        
        cursor.execute('''
            SELECT incident_type, COUNT(*) 
            FROM incidents 
            GROUP BY incident_type
        ''')
        incidents_by_type = dict(cursor.fetchall())
        
        cursor.execute('''
            SELECT AVG(
                (julianday(resolved_at) - julianday(reported_at)) * 24
            ) FROM incidents WHERE resolved_at IS NOT NULL
        ''')
        avg_resolution_time = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_incidents': total_incidents,
            'open_incidents': open_incidents,
            'resolved_incidents': resolved_incidents,
            'incidents_by_severity': incidents_by_severity,
            'incidents_by_type': incidents_by_type,
            'average_resolution_time_hours': round(avg_resolution_time, 2),
            'last_updated': datetime.now().isoformat()
        } 