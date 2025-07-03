#!/usr/bin/env python3
"""
Security Logger Component for WebSecGuard
Handles logging, database operations, and list management
"""

import sqlite3
import json
import csv
from datetime import datetime
import os

class SecurityLogger:
    """Main logging and database management class"""
    
    def __init__(self, db_path="config.db"):
        self.db_path = db_path
        self.init_database()
        
    def init_database(self):
        """Initialize the SQLite database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create security logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                url TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                action TEXT NOT NULL,
                details TEXT,
                threat_score INTEGER DEFAULT 0
            )
        ''')
        
        # Create blacklist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                date_added TEXT NOT NULL,
                reason TEXT,
                added_by TEXT DEFAULT 'user'
            )
        ''')
        
        # Create whitelist table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL,
                date_added TEXT NOT NULL,
                reason TEXT,
                added_by TEXT DEFAULT 'user'
            )
        ''')
        
        # Create settings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        
        # Insert default settings
        default_settings = [
            ('auto_scan', 'true', datetime.now().isoformat()),
            ('strict_mode', 'false', datetime.now().isoformat()),
            ('dark_mode', 'false', datetime.now().isoformat()),
            ('security_score', '100', datetime.now().isoformat())
        ]
        
        cursor.executemany('''
            INSERT OR REPLACE INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
        ''', default_settings)
        
        conn.commit()
        conn.close()
        
    def log_security_event(self, url, action, details, threat_level, threat_score=0):
        """Log a security event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_logs (timestamp, url, threat_level, action, details, threat_score)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            url,
            threat_level,
            action,
            details,
            threat_score
        ))
        
        conn.commit()
        conn.close()
        
    def get_logs(self, limit=100, offset=0):
        """Get security logs with pagination"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, url, threat_level, action, details
            FROM security_logs
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'timestamp': row[0],
                'url': row[1],
                'threat_level': row[2],
                'action': row[3],
                'details': row[4]
            })
            
        conn.close()
        return logs
        
    def get_logs_by_threat_level(self, threat_level):
        """Get logs filtered by threat level"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, url, threat_level, action, details
            FROM security_logs
            WHERE threat_level = ?
            ORDER BY timestamp DESC
        ''', (threat_level,))
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'timestamp': row[0],
                'url': row[1],
                'threat_level': row[2],
                'action': row[3],
                'details': row[4]
            })
            
        conn.close()
        return logs
        
    def search_logs(self, search_term):
        """Search logs by URL or details"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, url, threat_level, action, details
            FROM security_logs
            WHERE url LIKE ? OR details LIKE ?
            ORDER BY timestamp DESC
        ''', (f'%{search_term}%', f'%{search_term}%'))
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'timestamp': row[0],
                'url': row[1],
                'threat_level': row[2],
                'action': row[3],
                'details': row[4]
            })
            
        conn.close()
        return logs
        
    def clear_logs(self):
        """Clear all security logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM security_logs')
        
        conn.commit()
        conn.close()
        
    def export_logs(self, filename, format='csv'):
        """Export logs to file"""
        logs = self.get_logs(limit=10000)  # Export all logs
        
        if format.lower() == 'csv':
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['timestamp', 'url', 'threat_level', 'action', 'details']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for log in logs:
                    writer.writerow(log)
                    
        elif format.lower() == 'json':
            with open(filename, 'w', encoding='utf-8') as jsonfile:
                json.dump(logs, jsonfile, indent=2)
                
    def add_to_blacklist(self, url, reason="", added_by="user"):
        """Add URL to blacklist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO blacklist (url, date_added, reason, added_by)
                VALUES (?, ?, ?, ?)
            ''', (url, datetime.now().isoformat(), reason, added_by))
            
            conn.commit()
            success = True
        except sqlite3.IntegrityError:
            # URL already exists in blacklist
            success = False
        finally:
            conn.close()
            
        return success
        
    def remove_from_blacklist(self, url):
        """Remove URL from blacklist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM blacklist WHERE url = ?', (url,))
        
        conn.commit()
        conn.close()
        
    def get_blacklist(self):
        """Get all blacklisted URLs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT url, date_added, reason, added_by
            FROM blacklist
            ORDER BY date_added DESC
        ''')
        
        blacklist = []
        for row in cursor.fetchall():
            blacklist.append({
                'url': row[0],
                'date_added': row[1],
                'reason': row[2],
                'added_by': row[3]
            })
            
        conn.close()
        return blacklist
        
    def is_blacklisted(self, url):
        """Check if URL is blacklisted"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM blacklist WHERE url = ?', (url,))
        count = cursor.fetchone()[0]
        
        conn.close()
        return count > 0
        
    def add_to_whitelist(self, url, reason="", added_by="user"):
        """Add URL to whitelist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO whitelist (url, date_added, reason, added_by)
                VALUES (?, ?, ?, ?)
            ''', (url, datetime.now().isoformat(), reason, added_by))
            
            conn.commit()
            success = True
        except sqlite3.IntegrityError:
            # URL already exists in whitelist
            success = False
        finally:
            conn.close()
            
        return success
        
    def remove_from_whitelist(self, url):
        """Remove URL from whitelist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM whitelist WHERE url = ?', (url,))
        
        conn.commit()
        conn.close()
        
    def get_whitelist(self):
        """Get all whitelisted URLs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT url, date_added, reason, added_by
            FROM whitelist
            ORDER BY date_added DESC
        ''')
        
        whitelist = []
        for row in cursor.fetchall():
            whitelist.append({
                'url': row[0],
                'date_added': row[1],
                'reason': row[2],
                'added_by': row[3]
            })
            
        conn.close()
        return whitelist
        
    def is_whitelisted(self, url):
        """Check if URL is whitelisted"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM whitelist WHERE url = ?', (url,))
        count = cursor.fetchone()[0]
        
        conn.close()
        return count > 0
        
    def get_setting(self, key, default=None):
        """Get a setting value"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
        result = cursor.fetchone()
        
        conn.close()
        
        if result:
            return result[0]
        return default
        
    def set_setting(self, key, value):
        """Set a setting value"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO settings (key, value, updated_at)
            VALUES (?, ?, ?)
        ''', (key, str(value), datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
    def get_statistics(self):
        """Get security statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total logs
        cursor.execute('SELECT COUNT(*) FROM security_logs')
        total_logs = cursor.fetchone()[0]
        
        # Logs by threat level
        cursor.execute('''
            SELECT threat_level, COUNT(*) 
            FROM security_logs 
            GROUP BY threat_level
        ''')
        logs_by_level = dict(cursor.fetchall())
        
        # Actions taken
        cursor.execute('''
            SELECT action, COUNT(*) 
            FROM security_logs 
            GROUP BY action
        ''')
        actions_taken = dict(cursor.fetchall())
        
        # Blacklist and whitelist counts
        cursor.execute('SELECT COUNT(*) FROM blacklist')
        blacklist_count = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM whitelist')
        whitelist_count = cursor.fetchone()[0]
        
        # Recent activity (last 24 hours)
        yesterday = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
        cursor.execute('''
            SELECT COUNT(*) FROM security_logs 
            WHERE timestamp >= ?
        ''', (yesterday,))
        recent_activity = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_logs': total_logs,
            'logs_by_level': logs_by_level,
            'actions_taken': actions_taken,
            'blacklist_count': blacklist_count,
            'whitelist_count': whitelist_count,
            'recent_activity': recent_activity
        }
        
    def backup_database(self, backup_path):
        """Create a backup of the database"""
        import shutil
        shutil.copy2(self.db_path, backup_path)
        
    def restore_database(self, backup_path):
        """Restore database from backup"""
        import shutil
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, self.db_path)
            return True
        return False 