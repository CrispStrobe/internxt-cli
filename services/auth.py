# ==> services/auth.py <==
#!/usr/bin/env python3
"""
internxt_cli/services/auth.py
Authentication service for Internxt CLI - A direct translation of the official SDK blueprint.
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
        """
        Checks 2FA status using the security_details method, as per the SDK.
        """
        try:
            details = self.api.security_details(email)
            is_needed = details.get('tfa', False)
            print(f"   ✅ Security details successful, 2FA Enabled: {is_needed}")
            return is_needed
        except Exception as e:
            print(f"   ⚠️  Could not determine 2FA status. Reason: {e}")
            return False

    def do_login(self, email: str, password: str, tfa_code: Optional[str] = None) -> Dict[str, Any]:
        """
        Performs the full login flow and decrypts credentials,
        matching the logic step-by-step from the TypeScript `auth.service.ts` blueprint.
        """
        # Step 1: Get security details
        security_details = self.api.security_details(email)
        encrypted_salt = security_details.get('sKey')
        if not encrypted_salt:
            raise ValueError("Login failed: Did not receive encryptedSalt (sKey) from security details.")
        
        # Step 2: Perform client-side crypto operations
        print("   Performing client-side crypto operations...")
        encrypted_password_hash = self.crypto.encrypt_password_hash(password, encrypted_salt)
        keys_payload = self.crypto.generate_keys(password)
        print("   ✅ Crypto operations complete.")

        # Step 3: Construct the final payload for the /auth/login/access endpoint.
        final_payload = {
            'email': email.lower(),
            'password': encrypted_password_hash,
            'tfa': tfa_code,
            'keys': {
                'ecc': {
                    'publicKey': keys_payload['ecc']['publicKey'],
                    'privateKey': keys_payload['ecc']['privateKeyEncrypted']
                },
                'kyber': keys_payload['kyber']
            },
            'privateKey': keys_payload['privateKeyEncrypted'],
            'publicKey': keys_payload['publicKey'],
            'revocationKey': keys_payload['revocationCertificate'],
        }

        # Step 4: Make the final login call
        response = self.api.login_access(final_payload)
        
        user_data, token, new_token = response.get('user'), response.get('token'), response.get('newToken')
        if not all([user_data, token, new_token]):
            raise ValueError("Login failed: Final API response was missing 'user', 'token', or 'newToken'")
        
        print("   ✅ Full login successful!")
        
        # Step 5: Decrypt credentials for local use
        clear_mnemonic = self.crypto.decrypt_text_with_key(user_data['mnemonic'], password)
        
        # FIXED: The privateKey from the server is Base64 encoded, not hex. We must decode it first.
        clear_private_key = ""
        encrypted_pk_b64 = user_data.get('privateKey')
        if encrypted_pk_b64:
            try:
                # The server sends the private key in Base64, but the decryptor expects hex.
                # We decode from Base64 to bytes, then re-encode to a hex string.
                encrypted_pk_hex = base64.b64decode(encrypted_pk_b64).hex()
                decrypted_pk_string = self.crypto.decrypt_text_with_key(encrypted_pk_hex, password)
                # The final object stores the plaintext key as Base64, as per the TS blueprint.
                clear_private_key = base64.b64encode(decrypted_pk_string.encode()).decode()
            except Exception as e:
                print(f"   ⚠️  Warning: Failed to decrypt private key due to format issue: {e}")

        clear_user = {**user_data, 'mnemonic': clear_mnemonic, 'privateKey': clear_private_key}
        
        return {
            'user': clear_user, 'token': token, 'newToken': new_token,
            'lastLoggedInAt': datetime.now(timezone.utc).isoformat(),
            'lastTokenRefreshAt': datetime.now(timezone.utc).isoformat(),
        }

    def login(self, email: str, password: str, tfa_code: Optional[str] = None) -> Dict[str, Any]:
        """Login wrapper that saves credentials."""
        credentials = self.do_login(email, password, tfa_code)
        self.config.save_user_credentials(credentials)
        self.api.set_auth_tokens(credentials.get('newToken'))
        return credentials
    
    def refresh_user_tokens(self, old_creds: Dict[str, Any]) -> Dict[str, Any]:
        """Placeholder for refreshing user tokens to match TS blueprint structure."""
        print("   ⚠️  Token refresh functionality is not implemented in this version.")
        return old_creds

    def get_auth_details(self) -> Dict[str, Any]:
        """Get current auth details."""
        login_creds = self.config.read_user_credentials()
        if not login_creds or not all(k in login_creds for k in ['newToken', 'token']) or not login_creds.get('user', {}).get('mnemonic'):
            raise ValueError("MissingCredentialsError: No valid credentials found. Please login.")
        self.api.set_auth_tokens(login_creds.get('newToken'))
        return login_creds
    
    def logout(self) -> None:
        """Logout user and clear local credentials."""
        self.config.clear_user_credentials()
        self.api.set_auth_tokens(None)
        print("   ✅ Local credentials cleared.")
    
    def whoami(self) -> Optional[Dict[str, Any]]:
        """Get current user info if logged in."""
        try:
            credentials = self.get_auth_details()
            user = credentials.get('user', {})
            return {
                'email': user.get('email', ''),
                'uuid': user.get('uuid', ''),
                'rootFolderId': user.get('rootFolderId', user.get('root_folder_id', '')),
            }
        except ValueError:
            return None

# Global instance
auth_service = AuthService()