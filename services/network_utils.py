#!/usr/bin/env python3
"""
internxt_cli/services/network_utils.py
Network utilities for SSL certificate management (matches TypeScript NetworkUtils)
"""

import os
import hashlib
from pathlib import Path
from typing import Dict, Any
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from config.config import config_service


class NetworkUtils:
    """Network utilities for WebDAV SSL certificates and authentication"""
    
    WEBDAV_SSL_CERTS_DIR = config_service.internxt_cli_data_dir / "webdav-ssl"
    WEBDAV_SSL_CERT_FILE = WEBDAV_SSL_CERTS_DIR / "cert.crt"
    WEBDAV_SSL_KEY_FILE = WEBDAV_SSL_CERTS_DIR / "priv.key"
    WEBDAV_LOCAL_URL = "localhost"
    
    @classmethod
    def get_auth_from_credentials(cls, creds: Dict[str, str]) -> Dict[str, str]:
        """Get authentication credentials for network operations"""
        username = creds.get('user', '')
        password = creds.get('pass', '')
        
        # Hash password with SHA256 (matches TypeScript implementation)
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        return {
            'username': username,
            'password': password_hash
        }
    
    @classmethod
    def get_webdav_ssl_certs(cls) -> Dict[str, bytes]:
        """Get WebDAV SSL certificates, generating new ones if needed"""
        # Ensure SSL directory exists
        cls.WEBDAV_SSL_CERTS_DIR.mkdir(parents=True, exist_ok=True)
        
        # Check if certificates exist and are valid
        if cls.WEBDAV_SSL_CERT_FILE.exists() and cls.WEBDAV_SSL_KEY_FILE.exists():
            try:
                # Read existing certificates
                cert_pem = cls.WEBDAV_SSL_CERT_FILE.read_bytes()
                key_pem = cls.WEBDAV_SSL_KEY_FILE.read_bytes()
                
                # Check if certificate is still valid
                cert = x509.load_pem_x509_certificate(cert_pem)
                now = datetime.utcnow()
                
                if now < cert.not_valid_after:
                    # Certificate is still valid
                    return {
                        'cert': cert_pem,
                        'key': key_pem
                    }
                else:
                    print("🔄 SSL certificate expired, generating new one...")
                    
            except Exception as e:
                print(f"🔄 SSL certificate invalid ({e}), generating new one...")
        
        # Generate new certificates
        return cls.generate_new_selfsigned_certs()
    
    @classmethod
    def generate_new_selfsigned_certs(cls) -> Dict[str, bytes]:
        """Generate new self-signed SSL certificates"""
        print("🔐 Generating new SSL certificate for WebDAV server...")
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cls.WEBDAV_LOCAL_URL),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Internxt WebDAV"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "WebDAV Server"),
        ])
        
        # Certificate valid for 1 year
        valid_from = datetime.utcnow()
        valid_to = valid_from + timedelta(days=365)
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            valid_from
        ).not_valid_after(
            valid_to
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(cls.WEBDAV_LOCAL_URL),
                x509.DNSName("127.0.0.1"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256())
        
        # Serialize to PEM format
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Save certificates
        cls.save_webdav_ssl_certs(cert_pem, key_pem)
        
        print("✅ SSL certificate generated successfully")
        
        return {
            'cert': cert_pem,
            'key': key_pem
        }
    
    @classmethod
    def save_webdav_ssl_certs(cls, cert_pem: bytes, key_pem: bytes) -> None:
        """Save SSL certificates to disk"""
        try:
            # Ensure directory exists
            cls.WEBDAV_SSL_CERTS_DIR.mkdir(parents=True, exist_ok=True)
            
            # Write certificate
            cls.WEBDAV_SSL_CERT_FILE.write_bytes(cert_pem)
            cls.WEBDAV_SSL_KEY_FILE.write_bytes(key_pem)
            
            # Set secure permissions (owner read/write only)
            if os.name != 'nt':  # Unix-like systems
                os.chmod(cls.WEBDAV_SSL_CERT_FILE, 0o600)
                os.chmod(cls.WEBDAV_SSL_KEY_FILE, 0o600)
                
        except Exception as e:
            raise RuntimeError(f"Failed to save SSL certificates: {e}")
    
    @classmethod
    def parse_range_header(cls, range_header: str, file_size: int) -> Dict[str, Any]:
        """
        Parse HTTP Range header for partial content requests
        Returns range information or None if invalid/not supported
        """
        if not range_header or not range_header.startswith('bytes='):
            return None
        
        try:
            # Remove 'bytes=' prefix
            range_spec = range_header[6:]
            
            # Parse range (support single range only for now)
            if ',' in range_spec:
                raise ValueError("Multi-range requests not supported")
            
            if '-' not in range_spec:
                raise ValueError("Invalid range format")
            
            start_str, end_str = range_spec.split('-', 1)
            
            # Parse start and end
            if start_str == '':
                # Suffix range (last N bytes)
                if end_str == '':
                    raise ValueError("Invalid suffix range")
                suffix_length = int(end_str)
                start = max(0, file_size - suffix_length)
                end = file_size - 1
            elif end_str == '':
                # From start to end of file
                start = int(start_str)
                end = file_size - 1
            else:
                # Both start and end specified
                start = int(start_str)
                end = int(end_str)
            
            # Validate range
            if start < 0 or end >= file_size or start > end:
                raise ValueError("Range not satisfiable")
            
            return {
                'start': start,
                'end': end,
                'length': end - start + 1,
                'total_size': file_size
            }
            
        except ValueError as e:
            print(f"Invalid range header '{range_header}': {e}")
            return None


# Additional imports needed for IP address handling
try:
    import ipaddress
except ImportError:
    print("❌ Missing ipaddress module (should be in Python standard library)")
    raise