# ==> services/crypto.py <==
#!/usr/bin/env python3
"""
internxt_cli/services/crypto.py
Cryptographic operations for Internxt CLI - EXACT match to TypeScript blueprint
"""
import os
import hashlib
import base64
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from mnemonic import Mnemonic

from config.config import config_service

class CryptoService:
    """Handles all cryptographic operations"""

    def __init__(self):
        self.backend = default_backend()
        self.mnemonic_gen = Mnemonic("english")

    def _generate_file_key(self, mnemonic: str, bucket_id: str, index: bytes) -> bytes:
        """
        Generates a file-specific encryption key from the user's mnemonic.
        This is a direct port of `Environment.utils.generateFileKey` from the TS blueprint.
        """
        seed = self.mnemonic_gen.to_seed(mnemonic)
        key_material = seed + bucket_id.encode('utf-8') + index
        return hashlib.sha256(key_material).digest()

    def encrypt_stream(self, data: bytes, mnemonic: str, bucket_id: str) -> Tuple[bytes, bytes]:
        """
        Encrypts file data using AES-256-CTR as defined in the blueprint.
        Returns a tuple of (encrypted_data, index_nonce).
        """
        index_nonce = os.urandom(32) # 32-byte nonce as per TS `crypto.randomBytes(crypto.algorithm.ivSize)`
        iv = index_nonce[:16] # IV is the first 16 bytes of the index
        key = self._generate_file_key(mnemonic, bucket_id, index_nonce)

        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()
        return encrypted_data, index_nonce

    def decrypt_stream(self, data: bytes, mnemonic: str, bucket_id: str, index_hex: str) -> bytes:
        """
        Decrypts file data using AES-256-CTR as defined in the blueprint.
        """
        index_nonce = bytes.fromhex(index_hex)
        iv = index_nonce[:16]
        key = self._generate_file_key(mnemonic, bucket_id, index_nonce)
        
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        return decrypted_data

    # --- Methods from baseline ---
    
    def pass_to_hash(self, password: str, salt: str = None) -> dict:
        if salt is None:
            salt_bytes = os.urandom(16)
            salt = salt_bytes.hex()
        else:
            salt_bytes = bytes.fromhex(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA1(),
            length=32,
            salt=salt_bytes,
            iterations=10000,
            backend=self.backend
        )
        hash_bytes = kdf.derive(password.encode('utf-8'))
        return {'salt': salt, 'hash': hash_bytes.hex()}

    def encrypt_text(self, text: str) -> str:
        app_crypto_secret = config_service.get('APP_CRYPTO_SECRET')
        return self.encrypt_text_with_key(text, app_crypto_secret)

    def decrypt_text(self, encrypted_text: str) -> str:
        app_crypto_secret = config_service.get('APP_CRYPTO_SECRET')
        return self.decrypt_text_with_key(encrypted_text, app_crypto_secret)

    def encrypt_text_with_key(self, text_to_encrypt: str, secret: str) -> str:
        salt = os.urandom(8)
        key, iv = self._get_key_and_iv_from(secret, salt)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        text_bytes = text_to_encrypt.encode('utf-8')
        padding_length = 16 - (len(text_bytes) % 16)
        padded_text = text_bytes + bytes([padding_length] * padding_length)
        
        encrypted = encryptor.update(padded_text) + encryptor.finalize()
        result = b'Salted__' + salt + encrypted
        return result.hex()

    def decrypt_text_with_key(self, encrypted_text: str, secret: str) -> str:
        cipher_bytes = bytes.fromhex(encrypted_text)
        salt = cipher_bytes[8:16]
        key, iv = self._get_key_and_iv_from(secret, salt)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        contents_to_decrypt = cipher_bytes[16:]
        decrypted_padded = decryptor.update(contents_to_decrypt) + decryptor.finalize()
        
        padding_length = decrypted_padded[-1]
        decrypted = decrypted_padded[:-padding_length] if padding_length <= 16 else decrypted_padded
        return decrypted.decode('utf-8')

    def _get_key_and_iv_from(self, secret: str, salt: bytes) -> Tuple[bytes, bytes]:
        password = secret.encode('latin-1') + salt
        md5_hashes = []
        digest = password
        for _ in range(3):
            md5_hashes.append(hashlib.md5(digest).digest())
            digest = md5_hashes[-1] + password
        key = md5_hashes[0] + md5_hashes[1]
        iv = md5_hashes[2]
        return key, iv

    def validate_mnemonic(self, mnemonic_phrase: str) -> bool:
        return self.mnemonic_gen.check(mnemonic_phrase)

    def encrypt_password_hash(self, password: str, encrypted_salt: str) -> str:
        salt = self.decrypt_text(encrypted_salt)
        hash_obj = self.pass_to_hash(password, salt)
        return self.encrypt_text(hash_obj['hash'])

    def generate_keys(self, password: str) -> Dict[str, Any]:
        print("   ⚠️  Generating placeholder PGP keys for login payload.")
        encrypted_pk = self.encrypt_text_with_key("placeholder-private-key-for-login", password)
        return {
            "privateKeyEncrypted": encrypted_pk,
            "publicKey": "placeholder-public-key-for-login",
            "revocationCertificate": "placeholder-revocation-cert-for-login",
            "ecc": { "publicKey": "placeholder-ecc-public-key", "privateKeyEncrypted": encrypted_pk },
            "kyber": { "publicKey": None, "privateKeyEncrypted": None }
        }

# Global instance
crypto_service = CryptoService()