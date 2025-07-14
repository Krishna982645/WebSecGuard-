#!/usr/bin/env python3
"""
Advanced Password Leak Checker Utility for WebSecGuard
Comprehensive breach detection with multiple databases and analysis
"""

import hashlib
import re
import json
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import random

class PasswordLeakChecker:
    """Advanced password leak detection system"""
    
    def __init__(self, db_path="breach_data.db"):
        self.db_path = db_path
        self.init_breach_database()
        
        # Simulated breach databases
        self.breach_databases = {
            'haveibeenpwned': self._load_haveibeenpwned_data(),
            'dehashed': self._load_dehashed_data(),
            'leakcheck': self._load_leakcheck_data(),
            'intelx': self._load_intelx_data(),
            'snusbase': self._load_snusbase_data()
        }
        
        # Password strength patterns
        self.password_patterns = {
            'weak': [
                r'^[a-z]{1,6}$',  # Only lowercase, short
                r'^[0-9]{1,6}$',  # Only numbers, short
                r'^[a-z0-9]{1,6}$',  # Alphanumeric, short
                r'password',  # Common weak passwords
                r'123456',
                r'qwerty',
                r'admin',
                r'letmein',
                r'welcome',
                r'monkey',
                r'dragon',
                r'master',
                r'football',
                r'baseball',
                r'whatever',
                r'qazwsx',
                r'password123',
                r'admin123',
                r'root',
                r'toor'
            ],
            'medium': [
                r'^[a-zA-Z0-9]{8,12}$',  # Alphanumeric, medium length
                r'^[a-z]{8,12}$',  # Lowercase, medium length
                r'^[A-Z]{8,12}$',  # Uppercase, medium length
                r'^[0-9]{8,12}$',  # Numbers, medium length
            ],
            'strong': [
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{12,}$',  # Complex password
                r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{10,}$',  # Alphanumeric with case
            ]
        }
        
    def init_breach_database(self):
        """Initialize the breach database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create breach records table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS breach_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                password_hash TEXT,
                password TEXT,
                breach_source TEXT NOT NULL,
                breach_date TEXT,
                breach_name TEXT,
                breach_description TEXT,
                data_classes TEXT,
                is_verified BOOLEAN DEFAULT FALSE,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Create breach sources table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS breach_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT UNIQUE NOT NULL,
                source_url TEXT,
                last_updated TEXT,
                record_count INTEGER DEFAULT 0,
                is_active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        # Create password analysis table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_analysis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                password_strength TEXT,
                breach_count INTEGER DEFAULT 0,
                first_breach_date TEXT,
                last_breach_date TEXT,
                breach_sources TEXT,
                analysis_date TEXT NOT NULL
            )
        ''')
        
        # Insert default breach sources
        default_sources = [
            ('haveibeenpwned', 'https://haveibeenpwned.com', datetime.now().isoformat(), 0, True),
            ('dehashed', 'https://dehashed.com', datetime.now().isoformat(), 0, True),
            ('leakcheck', 'https://leakcheck.io', datetime.now().isoformat(), 0, True),
            ('intelx', 'https://intelx.io', datetime.now().isoformat(), 0, True),
            ('snusbase', 'https://snusbase.com', datetime.now().isoformat(), 0, True)
        ]
        
        cursor.executemany('''
            INSERT OR IGNORE INTO breach_sources (source_name, source_url, last_updated, record_count, is_active)
            VALUES (?, ?, ?, ?, ?)
        ''', default_sources)
        
        conn.commit()
        conn.close()
        
    def _load_haveibeenpwned_data(self) -> Dict:
        """Load simulated HaveIBeenPwned data"""
        return {
            'test@example.com': {
                'breaches': [
                    {'name': 'Adobe', 'date': '2013-10-04', 'count': 153000000},
                    {'name': 'LinkedIn', 'date': '2012-05-05', 'count': 164000000},
                    {'name': 'MySpace', 'date': '2008-06-11', 'count': 360000000}
                ],
                'pastes': [
                    {'source': 'Pastebin', 'id': 'abc123', 'date': '2017-08-28'},
                    {'source': 'Ghostbin', 'id': 'def456', 'date': '2018-01-15'}
                ]
            },
            'user@gmail.com': {
                'breaches': [
                    {'name': 'Dropbox', 'date': '2012-07-01', 'count': 68700000},
                    {'name': 'Tumblr', 'date': '2013-02-28', 'count': 65400000}
                ],
                'pastes': []
            },
            'admin@company.com': {
                'breaches': [
                    {'name': 'Yahoo', 'date': '2013-08-01', 'count': 3000000000},
                    {'name': 'Equifax', 'date': '2017-07-29', 'count': 147000000}
                ],
                'pastes': [
                    {'source': 'Pastebin', 'id': 'ghi789', 'date': '2019-03-10'}
                ]
            }
        }
        
    def _load_dehashed_data(self) -> Dict:
        """Load simulated Dehashed data"""
        return {
            'test@example.com': [
                {'email': 'test@example.com', 'password': 'password123', 'hash': 'hash1'},
                {'email': 'test@example.com', 'password': 'qwerty', 'hash': 'hash2'}
            ],
            'user@gmail.com': [
                {'email': 'user@gmail.com', 'password': 'letmein', 'hash': 'hash3'}
            ]
        }
        
    def _load_leakcheck_data(self) -> Dict:
        """Load simulated LeakCheck data"""
        return {
            'test@example.com': {
                'found': True,
                'sources': ['adobe', 'linkedin', 'myspace'],
                'last_check': '2023-01-15'
            },
            'user@gmail.com': {
                'found': True,
                'sources': ['dropbox'],
                'last_check': '2023-01-10'
            }
        }
        
    def _load_intelx_data(self) -> Dict:
        """Load simulated IntelX data"""
        return {
            'test@example.com': [
                {'title': 'Adobe Breach', 'date': '2013-10-04', 'url': 'https://example.com/adobe'},
                {'title': 'LinkedIn Breach', 'date': '2012-05-05', 'url': 'https://example.com/linkedin'}
            ]
        }
        
    def _load_snusbase_data(self) -> Dict:
        """Load simulated Snusbase data"""
        return {
            'test@example.com': {
                'email': 'test@example.com',
                'password': 'password123',
                'username': 'testuser',
                'domain': 'example.com'
            }
        }
        
    def check_email(self, email: str) -> Dict:
        """
        Comprehensive email breach check
        Returns: Dict with breach information
        """
        email = email.strip().lower()
        email_hash = hashlib.sha1(email.encode()).hexdigest()
        
        results = {
            'email': email,
            'found': False,
            'breach_count': 0,
            'breaches': [],
            'pastes': [],
            'sources': [],
            'first_breach': None,
            'last_breach': None,
            'total_records': 0,
            'password_exposure': False,
            'password_count': 0,
            'recommendations': []
        }
        
        # Check each breach database
        for source_name, database in self.breach_databases.items():
            source_results = self._check_source(email, source_name, database)
            if source_results['found']:
                results['found'] = True
                results['sources'].append(source_name)
                results['breach_count'] += source_results['breach_count']
                results['breaches'].extend(source_results['breaches'])
                results['pastes'].extend(source_results['pastes'])
                results['total_records'] += source_results['total_records']
                
                if source_results['password_exposure']:
                    results['password_exposure'] = True
                    results['password_count'] += source_results['password_count']
                    
        # Calculate breach dates
        if results['breaches']:
            dates = [breach['date'] for breach in results['breaches'] if breach.get('date')]
            if dates:
                results['first_breach'] = min(dates)
                results['last_breach'] = max(dates)
                
        # Generate recommendations
        results['recommendations'] = self._generate_recommendations(results)
        
        # Store analysis in database
        self._store_analysis(email, results)
        
        return results
        
    def _check_source(self, email: str, source_name: str, database: Dict) -> Dict:
        """Check a specific breach source"""
        results = {
            'found': False,
            'breach_count': 0,
            'breaches': [],
            'pastes': [],
            'total_records': 0,
            'password_exposure': False,
            'password_count': 0
        }
        
        if source_name == 'haveibeenpwned':
            if email in database:
                data = database[email]
                results['found'] = True
                results['breach_count'] = len(data['breaches'])
                results['breaches'] = data['breaches']
                results['pastes'] = data['pastes']
                results['total_records'] = sum(breach['count'] for breach in data['breaches'])
                
        elif source_name == 'dehashed':
            if email in database:
                results['found'] = True
                results['password_exposure'] = True
                results['password_count'] = len(database[email])
                results['total_records'] = len(database[email])
                
        elif source_name == 'leakcheck':
            if email in database and database[email]['found']:
                results['found'] = True
                results['breach_count'] = len(database[email]['sources'])
                
        elif source_name == 'intelx':
            if email in database:
                results['found'] = True
                results['breach_count'] = len(database[email])
                results['breaches'] = database[email]
                
        elif source_name == 'snusbase':
            if email in database:
                results['found'] = True
                results['password_exposure'] = True
                results['password_count'] = 1
                results['total_records'] = 1
                
        return results
        
    def _generate_recommendations(self, results: Dict) -> List[str]:
        """Generate security recommendations based on breach results"""
        recommendations = []
        
        if results['found']:
            recommendations.append("Change passwords for all accounts using this email")
            recommendations.append("Enable two-factor authentication where possible")
            recommendations.append("Use a password manager to generate unique passwords")
            
            if results['password_exposure']:
                recommendations.append("URGENT: Passwords were exposed in breaches")
                recommendations.append("Consider using a credit monitoring service")
                
            if results['breach_count'] > 5:
                recommendations.append("This email has been in many breaches - consider using a new email")
                
            if results['last_breach']:
                last_breach_date = datetime.fromisoformat(results['last_breach'])
                if (datetime.now() - last_breach_date).days < 365:
                    recommendations.append("Recent breach detected - immediate action required")
                    
        else:
            recommendations.append("No breaches found - keep using strong passwords")
            recommendations.append("Consider enabling two-factor authentication")
            
        return recommendations
        
    def _store_analysis(self, email: str, results: Dict):
        """Store analysis results in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO password_analysis 
            (email, password_hash, password_strength, breach_count, 
             first_breach_date, last_breach_date, breach_sources, analysis_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            email,
            hashlib.sha1(email.encode()).hexdigest(),
            'unknown',
            results['breach_count'],
            results['first_breach'],
            results['last_breach'],
            json.dumps(results['sources']),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
    def check_password_strength(self, password: str) -> Dict:
        """
        Analyze password strength
        Returns: Dict with strength analysis
        """
        analysis = {
            'password': password,
            'strength': 'weak',
            'score': 0,
            'issues': [],
            'suggestions': [],
            'entropy': 0,
            'crack_time': 'instant'
        }
        
        # Calculate base score
        score = 0
        
        # Length bonus
        if len(password) >= 12:
            score += 20
        elif len(password) >= 8:
            score += 10
        else:
            analysis['issues'].append("Password is too short")
            
        # Character variety bonus
        if re.search(r'[a-z]', password):
            score += 5
        else:
            analysis['issues'].append("Missing lowercase letters")
            
        if re.search(r'[A-Z]', password):
            score += 5
        else:
            analysis['issues'].append("Missing uppercase letters")
            
        if re.search(r'[0-9]', password):
            score += 5
        else:
            analysis['issues'].append("Missing numbers")
            
        if re.search(r'[^a-zA-Z0-9]', password):
            score += 10
        else:
            analysis['issues'].append("Missing special characters")
            
        # Penalty for common patterns
        for pattern in self.password_patterns['weak']:
            if re.search(pattern, password, re.IGNORECASE):
                score -= 20
                analysis['issues'].append("Contains common weak password pattern")
                break
                
        # Calculate entropy
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'[0-9]', password):
            charset_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            charset_size += 32
            
        if charset_size > 0:
            analysis['entropy'] = len(password) * (charset_size ** 0.5)
            
        # Determine strength level
        if score >= 30:
            analysis['strength'] = 'strong'
            analysis['crack_time'] = 'centuries'
        elif score >= 15:
            analysis['strength'] = 'medium'
            analysis['crack_time'] = 'days to months'
        else:
            analysis['strength'] = 'weak'
            analysis['crack_time'] = 'instant to hours'
            
        analysis['score'] = max(0, score)
        
        # Generate suggestions
        if analysis['strength'] == 'weak':
            analysis['suggestions'].extend([
                "Use at least 12 characters",
                "Include uppercase and lowercase letters",
                "Include numbers and special characters",
                "Avoid common words and patterns",
                "Consider using a passphrase"
            ])
        elif analysis['strength'] == 'medium':
            analysis['suggestions'].extend([
                "Increase length to 12+ characters",
                "Add more special characters",
                "Consider using a passphrase"
            ])
        else:
            analysis['suggestions'].append("Excellent password strength!")
            
        return analysis
        
    def check_password_reuse(self, email: str, password: str) -> Dict:
        """
        Check if password has been reused across breaches
        Returns: Dict with reuse analysis
        """
        password_hash = hashlib.sha1(password.encode()).hexdigest()
        
        # Simulate checking password reuse
        reused_emails = []
        if password in ['password123', 'qwerty', 'letmein']:
            reused_emails = ['user1@example.com', 'user2@example.com', 'user3@example.com']
            
        return {
            'password': password,
            'reused': len(reused_emails) > 0,
            'reuse_count': len(reused_emails),
            'reused_in_emails': reused_emails,
            'recommendation': 'Use unique passwords for each account' if reused_emails else 'Password appears unique'
        }
        
    def get_breach_statistics(self) -> Dict:
        """Get overall breach statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM password_analysis')
        total_checks = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM password_analysis WHERE breach_count > 0')
        breached_emails = cursor.fetchone()[0]
        
        cursor.execute('SELECT AVG(breach_count) FROM password_analysis WHERE breach_count > 0')
        avg_breaches = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'total_checks': total_checks,
            'breached_emails': breached_emails,
            'breach_rate': (breached_emails / total_checks * 100) if total_checks > 0 else 0,
            'average_breaches': round(avg_breaches, 2),
            'last_updated': datetime.now().isoformat()
        }
        
    def export_breach_data(self, filename: str, format: str = 'json'):
        """Export breach analysis data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT email, password_strength, breach_count, 
                   first_breach_date, last_breach_date, breach_sources, analysis_date
            FROM password_analysis
            ORDER BY analysis_date DESC
        ''')
        
        data = []
        for row in cursor.fetchall():
            data.append({
                'email': row[0],
                'password_strength': row[1],
                'breach_count': row[2],
                'first_breach_date': row[3],
                'last_breach_date': row[4],
                'breach_sources': json.loads(row[5]) if row[5] else [],
                'analysis_date': row[6]
            })
            
        conn.close()
        
        if format.lower() == 'json':
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
        elif format.lower() == 'csv':
            import csv
            with open(filename, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
                
        return len(data) 