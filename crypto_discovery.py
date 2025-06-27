#!/usr/bin/env python3
"""
Enhanced Crypto Discovery System with Web API and Advanced Analytics
Extends the original system with REST API, database storage, and advanced features
"""

import os
import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from flask import Flask, jsonify, request, render_template_string
from flask import send_from_directory
from flask import send_file
from flask_cors import CORS
import schedule
import hashlib
from dataclasses import dataclass
from typing import List, Dict, Optional
import logging
from pathlib import Path
import subprocess
import re
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('crypto_discovery.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class CryptoAsset:
    """Data class for cryptographic assets"""
    id: str
    type: str
    source: str
    algorithm: str
    key_size: Optional[int]
    status: str
    quantum_vulnerable: bool
    last_updated: datetime
    metadata: Dict
    risk_score: float

@dataclass
class ScanResult:
    """Data class for scan results"""
    scan_id: str
    timestamp: datetime
    scan_type: str
    target: str
    findings_count: int
    vulnerable_count: int
    status: str
    duration: float

class CryptoDatabase:
    """Database manager for crypto assets and scan results"""
    
    def __init__(self, db_path="crypto_discovery.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Assets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                source TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_size INTEGER,
                status TEXT NOT NULL,
                quantum_vulnerable BOOLEAN NOT NULL,
                last_updated TIMESTAMP NOT NULL,
                metadata TEXT,
                risk_score REAL DEFAULT 0.0
            )
        ''')
        
        # Scans table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                timestamp TIMESTAMP NOT NULL,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                findings_count INTEGER NOT NULL,
                vulnerable_count INTEGER NOT NULL,
                status TEXT NOT NULL,
                duration REAL NOT NULL,
                results TEXT
            )
        ''')
        
        # Migration tasks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS migration_tasks (
                task_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                priority TEXT NOT NULL,
                status TEXT NOT NULL,
                created_date TIMESTAMP NOT NULL,
                target_date TIMESTAMP,
                completed_date TIMESTAMP,
                notes TEXT,
                FOREIGN KEY (asset_id) REFERENCES assets (id)
            )
        ''')
        
        # Compliance records table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_records (
                record_id TEXT PRIMARY KEY,
                standard TEXT NOT NULL,
                status TEXT NOT NULL,
                compliance_percentage REAL NOT NULL,
                issues_count INTEGER NOT NULL,
                last_assessment TIMESTAMP NOT NULL,
                next_review TIMESTAMP NOT NULL,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def save_asset(self, asset: CryptoAsset):
        """Save or update crypto asset"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO assets 
            (id, type, source, algorithm, key_size, status, quantum_vulnerable, 
             last_updated, metadata, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            asset.id, asset.type, asset.source, asset.algorithm, asset.key_size,
            asset.status, asset.quantum_vulnerable, asset.last_updated,
            json.dumps(asset.metadata), asset.risk_score
        ))
        
        conn.commit()
        conn.close()
    
    def get_assets(self, filter_type=None, status=None) -> List[CryptoAsset]:
        """Retrieve crypto assets with optional filtering"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM assets WHERE 1=1"
        params = []
        
        if filter_type:
            query += " AND type = ?"
            params.append(filter_type)
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        assets = []
        for row in rows:
            assets.append(CryptoAsset(
                id=row[0], type=row[1], source=row[2], algorithm=row[3],
                key_size=row[4], status=row[5], quantum_vulnerable=bool(row[6]),
                last_updated=datetime.fromisoformat(row[7]),
                metadata=json.loads(row[8] or '{}'), risk_score=row[9]
            ))
        
        return assets
    
    def save_scan_result(self, scan_result: ScanResult, results_data: Dict):
        """Save scan result to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO scans 
            (scan_id, timestamp, scan_type, target, findings_count, 
             vulnerable_count, status, duration, results)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            scan_result.scan_id, scan_result.timestamp, scan_result.scan_type,
            scan_result.target, scan_result.findings_count, scan_result.vulnerable_count,
            scan_result.status, scan_result.duration, json.dumps(results_data)
        ))
        
        conn.commit()
        conn.close()

class EnhancedCryptoDiscovery:
    """Enhanced crypto discovery system with advanced features"""
    
    def __init__(self):
        self.database = CryptoDatabase()
        self.scanning = False
        self.current_scan_id = None
        self.risk_weights = {
        # Post-Quantum Algorithms (Low Risk)
        'ML-KEM': {'default': 0.1},
        'ML-DSA': {'default': 0.1},
        'SLH-DSA': {'default': 0.15},  # Slightly higher due to performance
        'HQC': {'default': 0.1},
        
        # Traditional but still acceptable
        'Ed25519': {'default': 0.2},
        'X25519': {'default': 0.2},
        'AES': {'128': 0.3, '192': 0.2, '256': 0.1, 'default': 0.4},
        'ChaCha20': {'default': 0.1},
        
        # Quantum Vulnerable (High Risk)
        'RSA': {
            '1024': 1.0,  # Critical
            '2048': 0.9,  # High - phase out
            '3072': 0.7,  # Medium - acceptable until 2030
            '4096': 0.6,  # Lower but still quantum vulnerable
            'default': 0.95
        },
        'ECDSA': {
            '256': 0.8,
            '384': 0.7,
            '521': 0.6,
            'default': 0.85
        },
        'DSA': {'default': 0.9},
        
        # Deprecated (Critical Risk)
        'DES': {'default': 1.0},
        '3DES': {'default': 1.0},
        'MD5': {'default': 1.0},
        'SHA1': {'default': 1.0},
        'RC4': {'default': 1.0}
    }
    
    def calculate_risk_score(self, algorithm: str, key_size: Optional[int] = None) -> float:
        """Calculate risk score for cryptographic algorithm"""
        base_score = 0.5
        
        if algorithm in self.risk_weights:
            algo_weights = self.risk_weights[algorithm]
            if key_size and str(key_size) in algo_weights:
                base_score = algo_weights[str(key_size)]
            else:
                base_score = algo_weights.get('default', 0.5)
        
        # Add time-based urgency (quantum computers getting closer)
        current_year = datetime.now().year
        urgency_multiplier = min(2.0, 1.0 + (current_year - 2024) * 0.15)
        
        return min(1.0, base_score * urgency_multiplier)
    
    def is_quantum_vulnerable(self, algorithm: str, key_size: Optional[int] = None) -> bool:
        """Determine if algorithm is quantum vulnerable"""
        vulnerable_algorithms = {
            'RSA': True,
            'DSA': True,
            'ECDSA': True,
            'ECDH': True,
            'DH': True,
            'ElGamal': True
        }
        
        post_quantum_algorithms = {
            'ML-KEM': False,        # FIPS 203
            'ML-DSA': False,        # FIPS 204  
            'SLH-DSA': False,       # FIPS 205
            'HQC': False,           # Backup algorithm (2025)
            'CRYSTALS-Kyber': False,
            'CRYSTALS-Dilithium': False,
            'SPHINCS+': False,
            'Ed25519': False,       # Still good for now
            'X25519': False,
            'AES': False,           # 256-bit minimum recommended
            'ChaCha20': False
        }
        
        algorithm_clean = algorithm.replace('PublicKey', '').replace('PrivateKey', '')
        
        if algorithm_clean in post_quantum_algorithms:
            return post_quantum_algorithms[algorithm_clean]
        
        
        return vulnerable_algorithms.get(algorithm_clean, True)
    
    def enhanced_certificate_scan(self, cert_paths: List[str] = None) -> List[CryptoAsset]:
        """Enhanced certificate scanning with detailed analysis"""
        assets = []
        
        if cert_paths is None:
            cert_paths = [
                "/etc/ssl/certs/",
                "/usr/local/share/ca-certificates/",
                "/etc/pki/tls/certs/",
                os.path.expanduser("~/.ssl/"),
                "./certs/",
                "./test_certs/"
            ]
        
        for cert_path in cert_paths:
            if not os.path.exists(cert_path):
                continue
                
            if os.path.isdir(cert_path):
                for file in os.listdir(cert_path):
                    if file.endswith(('.crt', '.pem', '.cer', '.p12', '.pfx')):
                        full_path = os.path.join(cert_path, file)
                        asset = self._analyze_certificate_file(full_path)
                        if asset:
                            assets.append(asset)
            elif os.path.isfile(cert_path):
                asset = self._analyze_certificate_file(cert_path)
                if asset:
                    assets.append(asset)
        
        return assets
    
    def _analyze_certificate_file(self, file_path: str) -> Optional[CryptoAsset]:
        """Analyze individual certificate file"""
        try:
            with open(file_path, 'rb') as f:
                cert_data = f.read()
            
            # Try PEM format first
            try:
                cert = x509.load_pem_x509_certificate(cert_data)
            except:
                # Try DER format
                cert = x509.load_der_x509_certificate(cert_data)
            
            public_key = cert.public_key()
            key_type = type(public_key).__name__
            key_size = getattr(public_key, 'key_size', None)
            
            # Extract detailed certificate information
            metadata = {
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'not_before': cert.not_valid_before.isoformat(),
                'not_after': cert.not_valid_after.isoformat(),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'extensions': [],
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'file_modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
            }
            
            # Analyze certificate extensions
            for ext in cert.extensions:
                metadata['extensions'].append({
                    'oid': ext.oid.dotted_string,
                    'critical': ext.critical,
                    'value': str(ext.value)
                })
            
            # Determine status
            now = datetime.now()
            if cert.not_valid_after < now:
                status = 'expired'
            elif cert.not_valid_after < now + timedelta(days=30):
                status = 'expiring_soon'
            elif self.is_quantum_vulnerable(key_type, key_size):
                status = 'vulnerable'
            else:
                status = 'secure'
            
            asset_id = hashlib.sha256(f"{file_path}:{cert.serial_number}".encode()).hexdigest()[:16]
            risk_score = self.calculate_risk_score(key_type.replace('PublicKey', ''), key_size)
            
            asset = CryptoAsset(
                id=asset_id,
                type='certificate',
                source=file_path,
                algorithm=key_type.replace('PublicKey', ''),
                key_size=key_size,
                status=status,
                quantum_vulnerable=self.is_quantum_vulnerable(key_type, key_size),
                last_updated=datetime.now(),
                metadata=metadata,
                risk_score=risk_score
            )
            
            return asset
            
        except Exception as e:
            logger.warning(f"Failed to analyze certificate {file_path}: {e}")
            return None
    
    def scan_ssh_keys(self, ssh_dirs: List[str] = None) -> List[CryptoAsset]:
        """Scan for SSH keys and analyze their cryptographic properties"""
        assets = []
        
        if ssh_dirs is None:
            ssh_dirs = [
                os.path.expanduser("~/.ssh/"),
                "/etc/ssh/",
                "/root/.ssh/",
                "./ssh_keys/"
            ]
        
        for ssh_dir in ssh_dirs:
            if not os.path.exists(ssh_dir):
                continue
                
            for file in os.listdir(ssh_dir):
                if file.endswith(('.pub', '_rsa', '_dsa', '_ecdsa', '_ed25519')) or 'id_' in file:
                    full_path = os.path.join(ssh_dir, file)
                    asset = self._analyze_ssh_key(full_path)
                    if asset:
                        assets.append(asset)
        
        return assets
    
    def _analyze_ssh_key(self, file_path: str) -> Optional[CryptoAsset]:
        """Analyze individual SSH key file"""
        try:
            with open(file_path, 'rb') as f:
                key_data = f.read()
            
            # Try to determine if it's a public or private key
            if key_data.startswith(b'ssh-'):
                # Public key
                key_line = key_data.decode().strip().split('\n')[0]
                parts = key_line.split()
                if len(parts) >= 2:
                    key_type = parts[0]
                    key_material = parts[1]
                    
                    # Extract key size information
                    if 'rsa' in key_type.lower():
                        algorithm = 'RSA'
                        # For RSA, we need to decode the key to get size
                        try:
                            import base64
                            decoded = base64.b64decode(key_material)
                            # Simple heuristic based on key material length
                            if len(decoded) > 400:
                                key_size = 4096
                            elif len(decoded) > 300:
                                key_size = 3072
                            else:
                                key_size = 2048
                        except:
                            key_size = None
                    elif 'ecdsa' in key_type.lower():
                        algorithm = 'ECDSA'
                        if '256' in key_type:
                            key_size = 256
                        elif '384' in key_type:
                            key_size = 384
                        elif '521' in key_type:
                            key_size = 521
                        else:
                            key_size = 256
                    elif 'ed25519' in key_type.lower():
                        algorithm = 'Ed25519'
                        key_size = 256
                    else:
                        algorithm = key_type
                        key_size = None
                        
            else:
                # Private key - try to load with cryptography
                try:
                    private_key = serialization.load_pem_private_key(key_data, password=None)
                    key_type = type(private_key).__name__
                    algorithm = key_type.replace('PrivateKey', '')
                    key_size = getattr(private_key, 'key_size', None)
                except:
                    # Encrypted private key or unknown format
                    algorithm = 'Unknown'
                    key_size = None
            
            metadata = {
                'file_path': file_path,
                'file_size': os.path.getsize(file_path),
                'file_modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat(),
                'is_public_key': key_data.startswith(b'ssh-'),
                'permissions': oct(os.stat(file_path).st_mode)[-3:]
            }
            
            # Determine status based on algorithm and key size
            if self.is_quantum_vulnerable(algorithm, key_size):
                if algorithm == 'RSA' and key_size and key_size < 2048:
                    status = 'weak'
                else:
                    status = 'vulnerable'
            else:
                status = 'secure'
            
            asset_id = hashlib.sha256(f"ssh:{file_path}".encode()).hexdigest()[:16]
            risk_score = self.calculate_risk_score(algorithm, key_size)
            
            asset = CryptoAsset(
                id=asset_id,
                type='ssh_key',
                source=file_path,
                algorithm=algorithm,
                key_size=key_size,
                status=status,
                quantum_vulnerable=self.is_quantum_vulnerable(algorithm, key_size),
                last_updated=datetime.now(),
                metadata=metadata,
                risk_score=risk_score
            )
            
            return asset
            
        except Exception as e:
            logger.warning(f"Failed to analyze SSH key {file_path}: {e}")
            return None
    
    def scan_code_repositories(self, repo_paths: List[str] = None) -> List[CryptoAsset]:
        """Scan code repositories for hardcoded cryptographic usage"""
        assets = []
        
        if repo_paths is None:
            repo_paths = ['./src/']

        
        crypto_patterns = {
            'AES': r'(?i)(aes|rijndael)',
            'DES': r'(?i)(des|3des|tripledes)',
            'RSA': r'(?i)(rsa)',
            'ECDSA': r'(?i)(ecdsa|elliptic)',
            'MD5': r'(?i)(md5)',
            'SHA1': r'(?i)(sha1|sha-1)',
            'RC4': r'(?i)(rc4|arcfour)',
            'Blowfish': r'(?i)(blowfish)',
            'Private Key': r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            'Certificate': r'-----BEGIN\s+CERTIFICATE-----'
        }
        
        file_extensions = {'.py', '.js', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go', '.rs'}
        
        for repo_path in repo_paths:
            if not os.path.exists(repo_path):
                continue
                
            for root, dirs, files in os.walk(repo_path):
                # Skip common non-code directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'vendor']]
                
                for file in files:
                    if any(file.endswith(ext) for ext in file_extensions):
                        full_path = os.path.join(root, file)
                        matches = self._scan_file_for_crypto(full_path, crypto_patterns)
                        assets.extend(matches)
        
        return assets
    
    def _scan_file_for_crypto(self, file_path: str, patterns: Dict[str, str]) -> List[CryptoAsset]:
        """Scan individual file for cryptographic patterns"""
        assets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for crypto_type, pattern in patterns.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    context = content[max(0, match.start()-50):match.end()+50]
                    
                    metadata = {
                        'file_path': file_path,
                        'line_number': line_num,
                        'context': context.strip(),
                        'match_text': match.group(),
                        'file_size': os.path.getsize(file_path),
                        'file_modified': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
                    }
                    
                    # Determine vulnerability status
                    vulnerable_types = {'DES', 'MD5', 'SHA1', 'RC4'}
                    if crypto_type in vulnerable_types:
                        status = 'deprecated'
                        quantum_vulnerable = True
                        risk_score = 0.9
                    elif crypto_type in ['Private Key', 'Certificate']:
                        status = 'hardcoded_secret'
                        quantum_vulnerable = True
                        risk_score = 0.95
                    else:
                        status = 'found'
                        quantum_vulnerable = self.is_quantum_vulnerable(crypto_type)
                        risk_score = self.calculate_risk_score(crypto_type)
                    
                    asset_id = hashlib.sha256(f"code:{file_path}:{line_num}:{crypto_type}".encode()).hexdigest()[:16]
                    
                    asset = CryptoAsset(
                        id=asset_id,
                        type='code_reference',
                        source=file_path,
                        algorithm=crypto_type,
                        key_size=None,
                        status=status,
                        quantum_vulnerable=quantum_vulnerable,
                        last_updated=datetime.now(),
                        metadata=metadata,
                        risk_score=risk_score
                    )
                    
                    assets.append(asset)
                    
        except Exception as e:
            logger.warning(f"Failed to scan file {file_path}: {e}")
        
        return assets
    
    def perform_full_scan(self, targets: Dict[str, List[str]] = None) -> ScanResult:
        """Perform comprehensive cryptographic scan"""
        start_time = time.time()
        scan_id = hashlib.sha256(f"scan:{datetime.now().isoformat()}".encode()).hexdigest()[:16]
        self.current_scan_id = scan_id
        self.scanning = True
        
        logger.info(f"Starting full crypto scan: {scan_id}")
        
        all_assets = []
        
        try:
            # Scan certificates
            logger.info("Scanning certificates...")
            cert_paths = targets.get('certificates') if targets else None
            cert_assets = self.enhanced_certificate_scan(cert_paths)
            all_assets.extend(cert_assets)
            logger.info(f"Found {len(cert_assets)} certificate assets")
            
            # Scan SSH keys
            logger.info("Scanning SSH keys...")
            ssh_paths = targets.get('ssh_keys') if targets else None
            ssh_assets = self.scan_ssh_keys(ssh_paths)
            all_assets.extend(ssh_assets)
            logger.info(f"Found {len(ssh_assets)} SSH key assets")
            
            # Scan code repositories
            logger.info("Scanning code repositories...")
            repo_paths = targets.get('repositories') if targets else None
            code_assets = self.scan_code_repositories(repo_paths)
            all_assets.extend(code_assets)
            logger.info(f"Found {len(code_assets)} code reference assets")
            
            # Save all assets to database
            for asset in all_assets:
                self.database.save_asset(asset)
            
            # Calculate statistics
            vulnerable_count = sum(1 for asset in all_assets if asset.quantum_vulnerable)
            end_time = time.time()
            duration = end_time - start_time
            
            scan_result = ScanResult(
                scan_id=scan_id,
                timestamp=datetime.now(),
                scan_type='full_scan',
                target='system',
                findings_count=len(all_assets),
                vulnerable_count=vulnerable_count,
                status='completed',
                duration=duration
            )
            
            # Save scan result
            results_data = {
                'assets': [asset.__dict__ for asset in all_assets],
                'summary': {
                    'total_assets': len(all_assets),
                    'vulnerable_assets': vulnerable_count,
                    'asset_types': {
                        'certificates': len([a for a in all_assets if a.type == 'certificate']),
                        'ssh_keys': len([a for a in all_assets if a.type == 'ssh_key']),
                        'code_references': len([a for a in all_assets if a.type == 'code_reference'])
                    }
                }
            }
            results_data = self.serialize_for_json(results_data)
            self.database.save_scan_result(scan_result, results_data)

            logger.info(f"Scan completed: {len(all_assets)} assets found, {vulnerable_count} vulnerable")

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            scan_result = ScanResult(
                scan_id=scan_id,
                timestamp=datetime.now(),
                scan_type='full_scan',
                target='system',
                findings_count=0,
                vulnerable_count=0,
                status='failed',
                duration=time.time() - start_time
            )
        
        finally:
            self.scanning = False
            self.current_scan_id = None
        
        return scan_result
    
    def generate_migration_plan(self) -> Dict:
        """Generate quantum-safe migration plan"""
        assets = self.database.get_assets()
        vulnerable_assets = [a for a in assets if a.quantum_vulnerable]
        
        # Priority mapping
        priority_map = {
            'certificate': 'high',
            'ssh_key': 'medium',
            'code_reference': 'low'
        }
        
        migration_tasks = []
        
        for asset in vulnerable_assets:
            priority = priority_map.get(asset.type, 'medium')
            
            # Determine target algorithm
            if asset.algorithm == 'RSA':
                target_algorithm = 'Ed25519 or RSA-4096+'
            elif asset.algorithm == 'ECDSA':
                target_algorithm = 'Ed25519'
            elif asset.algorithm in ['DES', '3DES']:
                target_algorithm = 'AES-256'
            elif asset.algorithm in ['MD5', 'SHA1']:
                target_algorithm = 'SHA-256 or SHA-3'
            else:
                target_algorithm = 'Post-quantum alternative'
            
            task = {
                'asset_id': asset.id,
                'asset_type': asset.type,
                'current_algorithm': asset.algorithm,
                'target_algorithm': target_algorithm,
                'priority': priority,
                'estimated_effort': self._estimate_migration_effort(asset),
                'dependencies': self._identify_dependencies(asset),
                'recommended_timeline': self._calculate_timeline(asset, priority)
            }
            
            migration_tasks.append(task)
        
        # Sort by priority and risk score
        priority_order = {'high': 0, 'medium': 1, 'low': 2}
        migration_tasks.sort(key=lambda x: (priority_order[x['priority']], -assets[0].risk_score))
        
        return {
            'total_vulnerable_assets': len(vulnerable_assets),
            'migration_tasks': migration_tasks,
            'estimated_total_effort': sum(task['estimated_effort'] for task in migration_tasks),
            'priority_breakdown': {
                'high': len([t for t in migration_tasks if t['priority'] == 'high']),
                'medium': len([t for t in migration_tasks if t['priority'] == 'medium']),
                'low': len([t for t in migration_tasks if t['priority'] == 'low'])
            },
            'generated_at': datetime.now().isoformat()
        }
    
    
    
    def _estimate_migration_effort(self, asset: CryptoAsset) -> int:
        """Estimate migration effort in hours"""
        base_effort = {
            'certificate': 8,
            'ssh_key': 2,
            'code_reference': 4
        }
        
        effort = base_effort.get(asset.type, 4)
        
        # Adjust based on complexity indicators
        if asset.type == 'certificate':
            if 'extensions' in asset.metadata:
                effort += len(asset.metadata['extensions']) * 0.5
        
        return int(effort)
    
    def _identify_dependencies(self, asset: CryptoAsset) -> List[str]:
        """Identify dependencies for migration"""
        dependencies = []
        
        if asset.type == 'certificate':
            dependencies.extend(['Update certificate authority', 'Coordinate with dependent services'])
        elif asset.type == 'ssh_key':
            dependencies.extend(['Update authorized_keys files', 'Coordinate with team members'])
        elif asset.type == 'code_reference':
            dependencies.extend(['Update dependencies', 'Test cryptographic functions'])
        
        return dependencies
    
    def _calculate_timeline(self, asset: CryptoAsset, priority: str) -> str:
        """Calculate recommended timeline for migration"""
        if priority == 'high':
            return '1-3 months'
        elif priority == 'medium':
            return '3-6 months'
        else:
            return '6-12 months'

    def serialize_for_json(self, obj):
        if isinstance(obj, dict):
            return {k: self.serialize_for_json(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.serialize_for_json(i) for i in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        else:
            return obj

# Flask Web API
app = Flask(__name__)
CORS(app)

# Global discovery instance
discovery = EnhancedCryptoDiscovery()


@app.route('/style.css')
def style_css():
    return send_from_directory('.', 'style.css')

@app.route('/app.js')
def app_js():
    return send_from_directory('.', 'app.js')

@app.route('/')
def index():
    """Serve main dashboard"""
    return send_file('dashboard.html')

@app.route('/api/reset', methods=['POST'])
def reset_scans():
    """Delete all scans and assets from the database"""
    conn = sqlite3.connect(discovery.database.db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans")
    cursor.execute("DELETE FROM assets")
    conn.commit()
    conn.close()
    return jsonify({'message': 'All scans and assets have been reset.'})

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a new cryptographic scan"""
    if discovery.scanning:
        return jsonify({'error': 'Scan already in progress'}), 400
    
    targets = request.json.get('targets') if request.json else None
    
    # Start scan in background thread
    def run_scan():
        discovery.perform_full_scan(targets)
    
    thread = threading.Thread(target=run_scan)
    thread.start()
    
    return jsonify({
        'message': 'Scan started',
        'scan_id': discovery.current_scan_id
    })

@app.route('/api/scan/status')
def scan_status():
    """Get current scan status"""
    return jsonify({
        'scanning': discovery.scanning,
        'scan_id': discovery.current_scan_id
    })

@app.route('/api/assets')
def get_assets():
    """Get all crypto assets with optional filtering"""
    asset_type = request.args.get('type')
    status = request.args.get('status')
    
    assets = discovery.database.get_assets(asset_type, status)
    
    return jsonify({
        'assets': [
            {
                'id': asset.id,
                'type': asset.type,
                'source': asset.source,
                'algorithm': asset.algorithm,
                'key_size': asset.key_size,
                'status': asset.status,
                'quantum_vulnerable': asset.quantum_vulnerable,
                'last_updated': asset.last_updated.isoformat(),
                'risk_score': asset.risk_score,
                'metadata': asset.metadata
            }
            for asset in assets
        ],
        'total_count': len(assets)
    })

@app.route('/api/assets/summary')
def get_assets_summary():
    """Get summary statistics of crypto assets"""
    assets = discovery.database.get_assets()
    
    summary = {
        'total_assets': len(assets),
        'vulnerable_assets': len([a for a in assets if a.quantum_vulnerable]),
        'by_type': {},
        'by_status': {},
        'by_algorithm': {},
        'risk_distribution': {'low': 0, 'medium': 0, 'high': 0}
    }
    
    for asset in assets:
        # Count by type
        summary['by_type'][asset.type] = summary['by_type'].get(asset.type, 0) + 1
        
        # Count by status
        summary['by_status'][asset.status] = summary['by_status'].get(asset.status, 0) + 1
        
        # Count by algorithm
        summary['by_algorithm'][asset.algorithm] = summary['by_algorithm'].get(asset.algorithm, 0) + 1
        
        # Risk distribution
        if asset.risk_score <= 0.3:
            summary['risk_distribution']['low'] += 1
        elif asset.risk_score <= 0.7:
            summary['risk_distribution']['medium'] += 1
        else:
            summary['risk_distribution']['high'] += 1
    
    return jsonify(summary)

@app.route('/api/migration/plan')
def get_migration_plan():
    """Get quantum-safe migration plan"""
    plan = discovery.generate_migration_plan()
    return jsonify(plan)

@app.route('/api/compliance/report')
def get_compliance_report():
    """Generate compliance report"""
    assets = discovery.database.get_assets()
    
    # NIST Post-Quantum Cryptography Standards compliance
    nist_pqc_compliant = 0
    deprecated_algorithms = 0
    weak_key_sizes = 0
    
    for asset in assets:
        if asset.algorithm in ['Ed25519', 'AES', 'ChaCha20']:
            nist_pqc_compliant += 1
        
        if asset.algorithm in ['DES', '3DES', 'MD5', 'SHA1', 'RC4']:
            deprecated_algorithms += 1
        
        if asset.algorithm == 'RSA' and asset.key_size and asset.key_size < 2048:
            weak_key_sizes += 1
    
    compliance_percentage = (nist_pqc_compliant / len(assets) * 100) if assets else 0
    
    report = {
        'compliance_percentage': round(compliance_percentage, 2),
        'total_assets': len(assets),
        'compliant_assets': nist_pqc_compliant,
        'issues': {
            'deprecated_algorithms': deprecated_algorithms,
            'weak_key_sizes': weak_key_sizes,
            'quantum_vulnerable': len([a for a in assets if a.quantum_vulnerable])
        },
        'recommendations': [
            'Migrate RSA keys to 4096-bit minimum or Ed25519',
            'Replace deprecated algorithms (DES, MD5, SHA1)',
            'Implement post-quantum cryptography where possible',
            'Regular cryptographic inventory updates'
        ],
        'generated_at': datetime.now().isoformat()
    }
    
    return jsonify(report)

@app.route('/api/export/csv')
def export_csv():
    """Export assets to CSV format"""
    import csv
    from io import StringIO
    
    assets = discovery.database.get_assets()
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        'ID', 'Type', 'Source', 'Algorithm', 'Key Size', 'Status',
        'Quantum Vulnerable', 'Risk Score', 'Last Updated'
    ])
    
    # Write data
    for asset in assets:
        writer.writerow([
            asset.id, asset.type, asset.source, asset.algorithm,
            asset.key_size or '', asset.status, asset.quantum_vulnerable,
            asset.risk_score, asset.last_updated.isoformat()
        ])
    
    response = app.response_class(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=crypto_assets.csv'}
    )
    
    return response

# Scheduler for automated scans
def scheduled_scan():
    """Run scheduled cryptographic scan"""
    if not discovery.scanning:
        logger.info("Running scheduled crypto scan")
        discovery.perform_full_scan()

# Schedule daily scans at 2 AM
schedule.every().day.at("02:00").do(scheduled_scan)

def run_scheduler():
    """Run the scheduler in background thread"""
    while True:
        schedule.run_pending()
        time.sleep(60)

# CLI Interface   
def main():
    """Main CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Enhanced Crypto Discovery System')
    parser.add_argument('--scan', action='store_true', help='Run full cryptographic scan')
    parser.add_argument('--web', action='store_true', help='Start web dashboard')
    parser.add_argument('--port', type=int, default=5000, help='Web server port')
    parser.add_argument('--host', default='localhost', help='Web server host')
    parser.add_argument('--export', choices=['csv', 'json'], help='Export assets to file')
    parser.add_argument('--migration-plan', action='store_true', help='Generate migration plan')
    parser.add_argument('--compliance-report', action='store_true', help='Generate compliance report')
    
    args = parser.parse_args()
    
    if args.scan:
        print("Starting cryptographic asset discovery scan...")
        result = discovery.perform_full_scan({'repositories':['./src/']})
        print(f"Scan completed: {result.findings_count} assets found, {result.vulnerable_count} vulnerable")
        
    elif args.migration_plan:
        print("Generating quantum-safe migration plan...")
        plan = discovery.generate_migration_plan()
        print(f"Migration Plan Summary:")
        print(f"- Total vulnerable assets: {plan['total_vulnerable_assets']}")
        print(f"- Estimated effort: {plan['estimated_total_effort']} hours")
        print(f"- High priority tasks: {plan['priority_breakdown']['high']}")
        
    elif args.compliance_report:
        # Generate compliance report via API endpoint logic
        assets = discovery.database.get_assets()
        compliant = len([a for a in assets if not a.quantum_vulnerable])
        compliance_pct = (compliant / len(assets) * 100) if assets else 0
        print(f"Compliance Report:")
        print(f"- Total assets: {len(assets)}")
        print(f"- Compliant assets: {compliant}")
        print(f"- Compliance percentage: {compliance_pct:.1f}%")
        
    elif args.export:
        assets = discovery.database.get_assets()
        if args.export == 'csv':
            import csv
            with open('crypto_assets.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['ID', 'Type', 'Algorithm', 'Status', 'Quantum Vulnerable', 'Risk Score'])
                for asset in assets:
                    writer.writerow([asset.id, asset.type, asset.algorithm, asset.status, 
                                   asset.quantum_vulnerable, asset.risk_score])
            print(f"Exported {len(assets)} assets to crypto_assets.csv")
            
        elif args.export == 'json':
            with open('crypto_assets.json', 'w') as f:
                json.dump([{
                    'id': asset.id,
                    'type': asset.type,
                    'algorithm': asset.algorithm,
                    'status': asset.status,
                    'quantum_vulnerable': asset.quantum_vulnerable,
                    'risk_score': asset.risk_score,
                    'metadata': asset.metadata
                } for asset in assets], f, indent=2, default=str)
            print(f"Exported {len(assets)} assets to crypto_assets.json")
            
    elif args.web:
        print(f"Starting web dashboard on http://{args.host}:{args.port}")
        
        # Start scheduler in background
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()
        
        app.run(host=args.host, port=args.port, debug=False)
        
    else:
        # Interactive mode
        print("Enhanced Crypto Discovery System")
        print("Available commands:")
        print("1. Run full scan")
        print("2. View assets")
        print("3. Generate migration plan")
        print("4. Start web dashboard")
        print("5. Exit")
        
        while True:
            choice = input("\nEnter choice (1-5): ").strip()
            
            if choice == '1':
                result = discovery.perform_full_scan()
                print(f"Scan completed: {result.findings_count} assets found")
                
            elif choice == '2':
                assets = discovery.database.get_assets()
                print(f"\nFound {len(assets)} crypto assets:")
                for asset in assets[:10]:  # Show first 10
                    print(f"- {asset.type}: {asset.algorithm} ({asset.status})")
                if len(assets) > 10:
                    print(f"... and {len(assets) - 10} more")
                    
            elif choice == '3':
                plan = discovery.generate_migration_plan()
                print(f"\nMigration Plan: {plan['total_vulnerable_assets']} assets need migration")
                
            elif choice == '4':
                print("Starting web dashboard on http://localhost:5000")
                app.run(host='localhost', port=5000, debug=False)
                
            elif choice == '5':
                print("Goodbye!")
                break
                
            else:
                print("Invalid choice. Please enter 1-5.")

if __name__ == '__main__':
    main()