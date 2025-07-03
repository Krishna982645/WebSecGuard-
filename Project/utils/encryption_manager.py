#!/usr/bin/env python3
"""
Encryption Manager Utility for WebSecGuard
Advanced encryption, decryption, and key management
"""

import hashlib
import hmac
import base64
import json
import sqlite3
import os
import random
import string
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union
import struct

class EncryptionManager:
    """Advanced encryption and key management system"""
    
    def __init__(self, db_path="encryption_data.db"):
        self.db_path = db_path
        self.init_encryption_database()
        
        # Encryption algorithms
        self.algorithms = {
            'AES-256-GCM': {
                'key_size': 32,
                'iv_size': 12,
                'tag_size': 16,
                'mode': 'GCM'
            },
            'AES-256-CBC': {
                'key_size': 32,
                'iv_size': 16,
                'mode': 'CBC'
            },
            'ChaCha20-Poly1305': {
                'key_size': 32,
                'iv_size': 12,
                'tag_size': 16,
                'mode': 'ChaCha20'
            }
        }
        
        # Key derivation functions
        self.kdf_algorithms = {
            'PBKDF2': {
                'iterations': 100000,
                'salt_size': 32
            },
            'Argon2': {
                'time_cost': 3,
                'memory_cost': 65536,
                'parallelism': 4,
                'salt_size': 32
            },
            'Scrypt': {
                'n': 16384,
                'r': 8,
                'p': 1,
                'salt_size': 32
            }
        }
        
    def init_encryption_database(self):
        """Initialize the encryption database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create encryption keys table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS encryption_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT UNIQUE NOT NULL,
                key_name TEXT NOT NULL,
                key_type TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                key_derivation TEXT,
                salt TEXT,
                iterations INTEGER,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                is_active BOOLEAN DEFAULT TRUE,
                usage_count INTEGER DEFAULT 0,
                last_used TEXT
            )
        ''')
        
        # Create encrypted data table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS encrypted_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_id TEXT UNIQUE NOT NULL,
                key_id TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                iv TEXT NOT NULL,
                tag TEXT,
                encrypted_data TEXT NOT NULL,
                data_type TEXT,
                metadata TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (key_id) REFERENCES encryption_keys (key_id)
            )
        ''')
        
        # Create key rotation table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS key_rotation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                old_key_id TEXT NOT NULL,
                new_key_id TEXT NOT NULL,
                rotation_date TEXT NOT NULL,
                reason TEXT,
                status TEXT DEFAULT 'pending',
                FOREIGN KEY (old_key_id) REFERENCES encryption_keys (key_id),
                FOREIGN KEY (new_key_id) REFERENCES encryption_keys (key_id)
            )
        ''')
        
        # Create encryption logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS encryption_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                operation TEXT NOT NULL,
                key_id TEXT,
                data_id TEXT,
                algorithm TEXT,
                success BOOLEAN,
                error_message TEXT,
                duration_ms INTEGER
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def generate_key(self, key_name: str, algorithm: str = 'AES-256-GCM', 
                    key_type: str = 'symmetric') -> str:
        """
        Generate a new encryption key
        Args:
            key_name: Name for the key
            algorithm: Encryption algorithm to use
            key_type: Type of key (symmetric, asymmetric)
        Returns: Key ID
        """
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        key_id = self._generate_key_id()
        key_size = self.algorithms[algorithm]['key_size']
        
        # Generate random key
        key = os.urandom(key_size)
        key_hash = hashlib.sha256(key).hexdigest()
        
        # Store key in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO encryption_keys 
            (key_id, key_name, key_type, algorithm, key_hash, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (key_id, key_name, key_type, algorithm, key_hash, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        # Log key generation
        self._log_operation('generate_key', key_id, algorithm, True)
        
        return key_id
        
    def derive_key_from_password(self, password: str, salt: bytes = None, 
                                kdf_algorithm: str = 'PBKDF2') -> str:
        """
        Derive encryption key from password
        Args:
            password: Password to derive key from
            salt: Salt for key derivation (auto-generated if None)
            kdf_algorithm: Key derivation function to use
        Returns: Key ID
        """
        if kdf_algorithm not in self.kdf_algorithms:
            raise ValueError(f"Unsupported KDF: {kdf_algorithm}")
            
        key_id = self._generate_key_id()
        
        # Generate salt if not provided
        if salt is None:
            salt_size = self.kdf_algorithms[kdf_algorithm]['salt_size']
            salt = os.urandom(salt_size)
            
        # Derive key
        if kdf_algorithm == 'PBKDF2':
            iterations = self.kdf_algorithms[kdf_algorithm]['iterations']
            key = self._pbkdf2_derive(password, salt, iterations, 32)
        elif kdf_algorithm == 'Argon2':
            key = self._argon2_derive(password, salt)
        elif kdf_algorithm == 'Scrypt':
            key = self._scrypt_derive(password, salt)
        else:
            raise ValueError(f"Unsupported KDF: {kdf_algorithm}")
            
        key_hash = hashlib.sha256(key).hexdigest()
        
        # Store key in database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO encryption_keys 
            (key_id, key_name, key_type, algorithm, key_hash, key_derivation, salt, iterations, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            key_id, f"derived_{kdf_algorithm}", 'symmetric', 'AES-256-GCM',
            key_hash, kdf_algorithm, base64.b64encode(salt).decode(),
            self.kdf_algorithms[kdf_algorithm].get('iterations', 0),
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        return key_id
        
    def _pbkdf2_derive(self, password: str, salt: bytes, iterations: int, key_length: int) -> bytes:
        """Derive key using PBKDF2"""
        # Simulate PBKDF2 derivation
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, key_length)
        return key
        
    def _argon2_derive(self, password: str, salt: bytes) -> bytes:
        """Derive key using Argon2 (simulated)"""
        # Simulate Argon2 derivation
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 10000, 32)
        return key
        
    def _scrypt_derive(self, password: str, salt: bytes) -> bytes:
        """Derive key using Scrypt (simulated)"""
        # Simulate Scrypt derivation
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 8000, 32)
        return key
        
    def encrypt_data(self, data: Union[str, bytes], key_id: str, 
                    algorithm: str = 'AES-256-GCM') -> str:
        """
        Encrypt data using specified key
        Args:
            data: Data to encrypt
            key_id: ID of the key to use
            algorithm: Encryption algorithm
        Returns: Data ID
        """
        if algorithm not in self.algorithms:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
        # Convert data to bytes if needed
        if isinstance(data, str):
            data_bytes = data.encode('utf-8')
        else:
            data_bytes = data
            
        # Generate IV
        iv_size = self.algorithms[algorithm]['iv_size']
        iv = os.urandom(iv_size)
        
        # Simulate encryption
        encrypted_data = self._simulate_encryption(data_bytes, algorithm)
        
        # Generate data ID
        data_id = self._generate_data_id()
        
        # Store encrypted data
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO encrypted_data 
            (data_id, key_id, algorithm, iv, encrypted_data, data_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data_id, key_id, algorithm, base64.b64encode(iv).decode(),
            base64.b64encode(encrypted_data).decode(), 'binary',
            datetime.now().isoformat()
        ))
        
        conn.commit()
        conn.close()
        
        # Update key usage
        self._update_key_usage(key_id)
        
        # Log operation
        self._log_operation('encrypt', key_id, algorithm, True, data_id)
        
        return data_id
        
    def decrypt_data(self, data_id: str) -> Union[str, bytes]:
        """
        Decrypt data using stored key
        Args:
            data_id: ID of the encrypted data
        Returns: Decrypted data
        """
        # Get encrypted data
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT key_id, algorithm, iv, encrypted_data, data_type
            FROM encrypted_data WHERE data_id = ?
        ''', (data_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            raise ValueError(f"Data ID not found: {data_id}")
            
        key_id, algorithm, iv_b64, encrypted_data_b64, data_type = row
        conn.close()
        
        # Decode data
        iv = base64.b64decode(iv_b64)
        encrypted_data = base64.b64decode(encrypted_data_b64)
        
        # Simulate decryption
        decrypted_data = self._simulate_decryption(encrypted_data, algorithm)
        
        # Update key usage
        self._update_key_usage(key_id)
        
        # Log operation
        self._log_operation('decrypt', key_id, algorithm, True, data_id)
        
        # Return appropriate type
        if data_type == 'text':
            return decrypted_data.decode('utf-8')
        else:
            return decrypted_data
            
    def _simulate_encryption(self, data: bytes, algorithm: str) -> bytes:
        """Simulate encryption process"""
        # In a real implementation, this would use actual encryption
        # For simulation, we'll just add some padding and a header
        
        # Add algorithm header
        header = struct.pack('!I', len(algorithm)) + algorithm.encode()
        
        # Add data length
        data_len = struct.pack('!Q', len(data))
        
        # Add some padding
        padding = os.urandom(16)
        
        # Combine all parts
        encrypted = header + data_len + padding + data
        
        return encrypted
        
    def _simulate_decryption(self, encrypted_data: bytes, algorithm: str) -> bytes:
        """Simulate decryption process"""
        # In a real implementation, this would use actual decryption
        # For simulation, we'll just extract the original data
        
        # Skip header (4 bytes for length + algorithm name)
        header_len = struct.unpack('!I', encrypted_data[:4])[0]
        offset = 4 + header_len + 8 + 16  # header + data_len + padding
        
        return encrypted_data[offset:]
        
    def rotate_key(self, old_key_id: str, new_key_id: str, reason: str = 'scheduled') -> bool:
        """
        Rotate encryption key
        Args:
            old_key_id: ID of the old key
            new_key_id: ID of the new key
            reason: Reason for rotation
        Returns: Success status
        """
        try:
            # Get all data encrypted with old key
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT data_id, encrypted_data, algorithm, iv
                FROM encrypted_data WHERE key_id = ?
            ''', (old_key_id,))
            
            data_to_reencrypt = cursor.fetchall()
            
            # Re-encrypt data with new key
            for data_id, encrypted_data_b64, algorithm, iv_b64 in data_to_reencrypt:
                # Decrypt with old key (simulated)
                encrypted_data = base64.b64decode(encrypted_data_b64)
                decrypted_data = self._simulate_decryption(encrypted_data, algorithm)
                
                # Re-encrypt with new key
                new_data_id = self.encrypt_data(decrypted_data, new_key_id, algorithm)
                
                # Update data record
                cursor.execute('''
                    UPDATE encrypted_data 
                    SET key_id = ?, data_id = ?
                    WHERE data_id = ?
                ''', (new_key_id, new_data_id, data_id))
                
            # Record rotation
            cursor.execute('''
                INSERT INTO key_rotation 
                (old_key_id, new_key_id, rotation_date, reason, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (old_key_id, new_key_id, datetime.now().isoformat(), reason, 'completed'))
            
            # Deactivate old key
            cursor.execute('''
                UPDATE encryption_keys 
                SET is_active = FALSE, expires_at = ?
                WHERE key_id = ?
            ''', (datetime.now().isoformat(), old_key_id))
            
            conn.commit()
            conn.close()
            
            return True
            
        except Exception as e:
            print(f"Error rotating key: {e}")
            return False
            
    def _generate_key_id(self) -> str:
        """Generate unique key ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"key_{timestamp}_{random_suffix}"
        
    def _generate_data_id(self) -> str:
        """Generate unique data ID"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        random_suffix = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"data_{timestamp}_{random_suffix}"
        
    def _update_key_usage(self, key_id: str):
        """Update key usage statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE encryption_keys 
            SET usage_count = usage_count + 1, last_used = ?
            WHERE key_id = ?
        ''', (datetime.now().isoformat(), key_id))
        
        conn.commit()
        conn.close()
        
    def _log_operation(self, operation: str, key_id: str, algorithm: str, 
                      success: bool, data_id: str = None, error_message: str = None):
        """Log encryption operation"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO encryption_logs 
            (timestamp, operation, key_id, data_id, algorithm, success, error_message, duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(), operation, key_id, data_id, algorithm,
            success, error_message, random.randint(1, 100)
        ))
        
        conn.commit()
        conn.close()
        
    def get_key_info(self, key_id: str) -> Dict:
        """Get information about a key"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT key_name, key_type, algorithm, key_derivation, created_at, 
                   expires_at, is_active, usage_count, last_used
            FROM encryption_keys WHERE key_id = ?
        ''', (key_id,))
        
        row = cursor.fetchone()
        if not row:
            conn.close()
            return {'error': 'Key not found'}
            
        conn.close()
        
        return {
            'key_id': key_id,
            'key_name': row[0],
            'key_type': row[1],
            'algorithm': row[2],
            'key_derivation': row[3],
            'created_at': row[4],
            'expires_at': row[5],
            'is_active': bool(row[6]),
            'usage_count': row[7],
            'last_used': row[8]
        }
        
    def get_all_keys(self) -> List[Dict]:
        """Get all encryption keys"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT key_id, key_name, key_type, algorithm, created_at, 
                   is_active, usage_count, last_used
            FROM encryption_keys ORDER BY created_at DESC
        ''')
        
        keys = []
        for row in cursor.fetchall():
            keys.append({
                'key_id': row[0],
                'key_name': row[1],
                'key_type': row[2],
                'algorithm': row[3],
                'created_at': row[4],
                'is_active': bool(row[5]),
                'usage_count': row[6],
                'last_used': row[7]
            })
            
        conn.close()
        return keys
        
    def get_encryption_logs(self, limit: int = 100) -> List[Dict]:
        """Get encryption operation logs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT timestamp, operation, key_id, data_id, algorithm, success, error_message
            FROM encryption_logs ORDER BY timestamp DESC LIMIT ?
        ''', (limit,))
        
        logs = []
        for row in cursor.fetchall():
            logs.append({
                'timestamp': row[0],
                'operation': row[1],
                'key_id': row[2],
                'data_id': row[3],
                'algorithm': row[4],
                'success': bool(row[5]),
                'error_message': row[6]
            })
            
        conn.close()
        return logs
        
    def get_encryption_statistics(self) -> Dict:
        """Get encryption statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM encryption_keys')
        total_keys = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM encryption_keys WHERE is_active = TRUE')
        active_keys = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM encrypted_data')
        total_data = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM encryption_logs WHERE success = TRUE')
        successful_operations = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM encryption_logs WHERE success = FALSE')
        failed_operations = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_keys': total_keys,
            'active_keys': active_keys,
            'total_encrypted_data': total_data,
            'successful_operations': successful_operations,
            'failed_operations': failed_operations,
            'last_updated': datetime.now().isoformat()
        } 