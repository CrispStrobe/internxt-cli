#!/usr/bin/env python3
"""
internxt_cli/services/crypto.py
Cryptographic operations for Internxt CLI
"""

import os
import sys
import hashlib
from typing import Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from mnemonic import Mnemonic
import base64


class CryptoService:
    """Handles all cryptographic operations"""

    def __init__(self):
        self.backend = default_backend()
        self.mnemonic_gen = Mnemonic("english")

    def pass_to_hash(self, password: str, salt: str = None) -> Tuple[str, str]:
        """Generate hash for password with optional salt"""
        if salt is None:
            salt_bytes = os.urandom(16)
            salt = salt_bytes.hex()
        else:
            salt_bytes = bytes.fromhex(salt)

        # PBKDF2 with SHA1 (matching TypeScript implementation)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=32,  # 256 bits
            salt=salt_bytes,
            iterations=10000,
            backend=self.backend
        )
        hash_bytes = kdf.derive(password.encode('utf-8'))
        hash_hex = hash_bytes.hex()

        return salt, hash_hex

    def encrypt_text(self, text: str) -> str:
        """Encrypt text using app crypto secret (CryptoJS compatible)"""
        # Import here to avoid circular imports
        try:
            from ..config.config import config_service
        except ImportError:
            try:
                from internxt_cli.config.config import config_service
            except ImportError:
                current_dir = os.path.dirname(os.path.abspath(__file__))
                parent_dir = os.path.dirname(current_dir)
                if parent_dir not in sys.path:
                    sys.path.insert(0, parent_dir)
                from config.config import config_service
        
        secret = config_service.get('APP_CRYPTO_SECRET')
        return self.encrypt_text_with_key(text, secret)

    def decrypt_text(self, encrypted_text: str) -> str:
        """Decrypt text using app crypto secret (CryptoJS compatible)"""
        # Import here to avoid circular imports
        try:
            from ..config.config import config_service
        except ImportError:
            try:
                from internxt_cli.config.config import config_service
            except ImportError:
                current_dir = os.path.dirname(os.path.abspath(__file__))
                parent_dir = os.path.dirname(current_dir)
                if parent_dir not in sys.path:
                    sys.path.insert(0, parent_dir)
                from config.config import config_service
        
        secret = config_service.get('APP_CRYPTO_SECRET')
        return self.decrypt_text_with_key(encrypted_text, secret)

    def encrypt_text_with_key(self, text: str, secret: str) -> str:
        """Encrypt text with key (CryptoJS Salted__ format compatible)"""
        salt = os.urandom(8)
        key, iv = self._get_key_and_iv_from(secret, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        # PKCS7 padding
        text_bytes = text.encode('utf-8')
        padding_length = 16 - (len(text_bytes) % 16)
        padded_text = text_bytes + bytes([padding_length] * padding_length)

        encrypted = encryptor.update(padded_text) + encryptor.finalize()

        # CryptoJS format: 'Salted__' + salt + encrypted
        openssl_start = b'Salted__'
        result = openssl_start + salt + encrypted

        return result.hex()

    def decrypt_text_with_key(self, encrypted_hex: str, secret: str) -> str:
        """Decrypt text with key (CryptoJS Salted__ format compatible)"""
        cipher_bytes = bytes.fromhex(encrypted_hex)

        # Extract salt (skip 'Salted__' prefix)
        salt = cipher_bytes[8:16]
        key, iv = self._get_key_and_iv_from(secret, salt)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()

        contents_to_decrypt = cipher_bytes[16:]
        decrypted_padded = decryptor.update(contents_to_decrypt) + decryptor.finalize()

        # Remove PKCS7 padding
        padding_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-padding_length]

        return decrypted.decode('utf-8')

    def _get_key_and_iv_from(self, secret: str, salt: bytes) -> Tuple[bytes, bytes]:
        """Generate key and IV from secret and salt (CryptoJS compatible)"""
        password = secret.encode('latin-1') + salt
        md5_hashes = []
        digest = password

        # 3 rounds of MD5 (CryptoJS compatibility)
        for i in range(3):
            md5_hashes.append(hashlib.md5(digest).digest())
            digest = md5_hashes[i] + password

        key = md5_hashes[0] + md5_hashes[1]  # 32 bytes
        iv = md5_hashes[2][:16]  # 16 bytes

        return key, iv

    def generate_file_key(self, mnemonic: str, bucket_id: str, index: bytes) -> bytes:
        """Generate file encryption key from mnemonic, bucket and index"""
        # This is a simplified version - in practice this involves more complex key derivation
        # that matches the Internxt SDK implementation
        seed = self.mnemonic_gen.to_seed(mnemonic)

        # Combine seed, bucket_id, and index
        key_material = seed + bucket_id.encode() + index

        # Use SHA256 to derive 32-byte key
        return hashlib.sha256(key_material).digest()

    def validate_mnemonic(self, mnemonic: str) -> bool:
        """Validate BIP39 mnemonic"""
        return self.mnemonic_gen.check(mnemonic)

    def decrypt_file_stream(self, encrypted_stream, key: bytes, iv: bytes,
                          start_offset: int = 0) -> bytes:
        """Decrypt file stream using AES-256-CTR"""
        # For CTR mode, we need to calculate the correct counter for the offset
        if start_offset > 0:
            # Calculate block offset for CTR mode
            aes_block_size = 16
            start_block_offset = start_offset % aes_block_size
            start_block_number = (start_offset - start_block_offset) // aes_block_size

            # Increment IV by block number for CTR mode
            iv_int = int.from_bytes(iv, 'big')
            new_iv_int = (iv_int + start_block_number) % (2 ** 128)
            new_iv = new_iv_int.to_bytes(16, 'big')

            cipher = Cipher(algorithms.AES(key), modes.CTR(new_iv), backend=self.backend)
            decryptor = cipher.decryptor()

            # Skip bytes within the block
            if start_block_offset > 0:
                skip_buffer = b'\x00' * start_block_offset
                decryptor.update(skip_buffer)
        else:
            cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=self.backend)
            decryptor = cipher.decryptor()

        # Decrypt the stream
        decrypted = decryptor.update(encrypted_stream) + decryptor.finalize()
        return decrypted

    def encrypt_file_stream(self, plaintext_stream: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypt file stream using AES-256-CTR"""
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=self.backend)
        encryptor = cipher.encryptor()

        encrypted = encryptor.update(plaintext_stream) + encryptor.finalize()
        return encrypted


# Global instance
crypto_service = CryptoService()