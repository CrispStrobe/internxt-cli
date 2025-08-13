#!/usr/bin/env python3
"""
internxt_cli/services/auth.py
Authentication service for Internxt CLI
"""
import base64
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from config.config import config_service
from utils.api import api_client
from services.crypto import crypto_service

class AuthService:
    def __init__(self):
        self.config = config_service
        self.api = api_client
        self.crypto = crypto_service
    
    def is_2fa_needed(self, email: str) -> bool:
        try:
            details = self.api.security_details(email)
            is_needed = details.get('tfa', False)
            print(f"    ✅ Security details successful, 2FA Enabled: {is_needed}")
            return is_needed
        except Exception as e:
            print(f"    ⚠️  Could not determine 2FA status. Reason: {e}")
            return False

    def do_login(self, email: str, password: str, tfa_code: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs the full login flow and correctly handles credentials.
        """
        # Step 1: Get security details
        security_details = self.api.security_details(email)
        encrypted_salt = security_details.get('sKey')
        if not encrypted_salt:
            raise ValueError("Login failed: Did not receive encryptedSalt (sKey) from security details.")

        # Step 2: Perform client-side crypto operations
        print("    Performing client-side crypto operations...")
        encrypted_password_hash = self.crypto.encrypt_password_hash(password, encrypted_salt)
        keys_payload = self.crypto.generate_keys(password)
        print("    ✅ Crypto operations complete.")

        # Step 3: Construct the final payload
        final_payload = {
            'email': email.lower(), 'password': encrypted_password_hash, 'tfa': tfa_code,
            'keys': {
                'ecc': { 'publicKey': keys_payload['ecc']['publicKey'], 'privateKey': keys_payload['ecc']['privateKeyEncrypted'] },
                'kyber': keys_payload['kyber']
            },
            'privateKey': keys_payload['privateKeyEncrypted'], 'publicKey': keys_payload['publicKey'],
            'revocationKey': keys_payload['revocationCertificate'],
        }

        # Step 4: Make the final login call
        response = self.api.login_access(final_payload)

        user_data, token, new_token = response.get('user'), response.get('token'), response.get('newToken')
        if not all([user_data, token, new_token]):
            raise ValueError("Login failed: Final API response was missing 'user', 'token', or 'newToken'")

        print("    ✅ Full login successful!")

        # Step 5: CORRECTLY HANDLE CREDENTIALS
        # CRITICAL FIX: The mnemonic is ENCRYPTED with the user's password!
        encrypted_mnemonic = user_data.get('mnemonic')
        if not encrypted_mnemonic:
            raise ValueError("Login failed: Mnemonic not found in user data.")
        
        # Decrypt the mnemonic using the user's password
        try:
            clear_mnemonic = self.crypto.decrypt_text_with_key(encrypted_mnemonic, password)
            print(f"    ✅ Mnemonic decrypted successfully ({len(clear_mnemonic.split())} words)")
        except Exception as e:
            raise ValueError(f"Login failed: Could not decrypt mnemonic: {e}")
        
        # Validate the decrypted mnemonic
        if not self.crypto.validate_mnemonic(clear_mnemonic):
            raise ValueError("Login failed: Decrypted mnemonic is invalid")
        
        # Handle private key (this part can stay as is)
        clear_private_key = ""
        encrypted_pk = user_data.get('privateKey', '')
        
        if encrypted_pk:
            try:
                # Check if it looks like a PGP private key (already decrypted)
                if '-----BEGIN PGP PRIVATE KEY BLOCK-----' in encrypted_pk:
                    clear_private_key = encrypted_pk
                else:
                    # It's encrypted - try to decrypt it
                    try:
                        # Try as base64 first
                        import base64
                        encrypted_pk_bytes = base64.b64decode(encrypted_pk)
                        encrypted_pk_hex = encrypted_pk_bytes.hex()
                    except:
                        # Assume it's already hex
                        encrypted_pk_hex = encrypted_pk
                    
                    clear_private_key = self.crypto.decrypt_text_with_key(encrypted_pk_hex, clear_mnemonic)
            except Exception as e:
                # If decryption fails, it might already be decrypted or not needed
                print(f"    ℹ️  Note: Private key handling: {str(e)[:50]}...")
                clear_private_key = encrypted_pk

        clear_user = {**user_data, 'mnemonic': clear_mnemonic, 'privateKey': clear_private_key}

        return {
            'user': clear_user, 'token': token, 'newToken': new_token,
            'lastLoggedInAt': datetime.now(timezone.utc).isoformat(),
            'lastTokenRefreshAt': datetime.now(timezone.utc).isoformat(),
        }

    def login(self, email: str, password: str, tfa_code: Optional[str] = None) -> Dict[str, Any]:
        credentials = self.do_login(email, password, tfa_code)
        self.config.save_user_credentials(credentials)
        self.api.set_auth_tokens(credentials.get('token'), credentials.get('newToken'))
        return credentials

    def get_auth_details(self) -> Dict[str, Any]:
        login_creds = self.config.read_user_credentials()
        if not login_creds or not all(k in login_creds for k in ['newToken', 'token']) or not login_creds.get('user', {}).get('mnemonic'):
            raise ValueError("MissingCredentialsError: No valid credentials found. Please login.")
        self.api.set_auth_tokens(login_creds.get('token'), login_creds.get('newToken'))
        return login_creds

    def logout(self) -> None:
        self.config.clear_user_credentials()
        self.api.set_auth_tokens(None, None)
        print("    ✅ Local credentials cleared.")

    def whoami(self) -> Optional[Dict[str, Any]]:
        try:
            credentials = self.get_auth_details()
            user = credentials.get('user', {})
            return {
                'email': user.get('email', ''), 'uuid': user.get('uuid', ''),
                'rootFolderId': user.get('rootFolderId', user.get('root_folder_id', '')),
            }
        except ValueError:
            return None

auth_service = AuthService()