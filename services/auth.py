#!/usr/bin/env python3
"""
internxt_cli/services/auth.py
Authentication service for Internxt CLI
"""

import base64
import json
import sys
import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple

# Fix imports to work both as module and direct script
try:
    from ..config.config import config_service
    from ..utils.api import api_client
    from .crypto import crypto_service
except ImportError:
    # Fallback for direct script execution
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from config.config import config_service
    from utils.api import api_client
    from services.crypto import crypto_service


class AuthService:
    """Handles authentication and token management"""

    def __init__(self):
        self.config = config_service
        self.api = api_client
        self.crypto = crypto_service

    def is_2fa_needed(self, email: str) -> bool:
        """Check if 2FA is required for user"""
        return self.api.check_2fa_needed(email)

    def login(self, email: str, password: str, tfa_code: str = None) -> Dict[str, Any]:
        """Login user and return credentials"""
        try:
            # Attempt login
            response = self.api.login(email, password, tfa_code)

            # Extract user data and tokens
            user_data = response.get('user', {})
            token = response.get('token', '')
            new_token = response.get('newToken', '')

            if not all([user_data, token, new_token]):
                raise ValueError("Invalid login response: missing required fields")

            # Decrypt user's mnemonic
            encrypted_mnemonic = user_data.get('mnemonic', '')
            if not encrypted_mnemonic:
                raise ValueError("No mnemonic found in user data")

            try:
                mnemonic = self.crypto.decrypt_text_with_key(encrypted_mnemonic, password)
                if not self.crypto.validate_mnemonic(mnemonic):
                    raise ValueError("Invalid mnemonic")
            except Exception as e:
                raise ValueError(f"Failed to decrypt mnemonic: {e}")

            # Decrypt private key if present
            private_key = ""
            if user_data.get('privateKey'):
                try:
                    # Simplified private key decryption - in practice this would use PGP
                    private_key_encrypted = user_data['privateKey']
                    private_key = self.crypto.decrypt_text_with_key(private_key_encrypted, password)
                except Exception:
                    # Private key decryption failed, but continue without it
                    pass

            # Prepare login credentials
            login_credentials = {
                'user': {
                    **user_data,
                    'mnemonic': mnemonic,
                    'privateKey': private_key,
                    'email': email.lower()
                },
                'token': token,
                'newToken': new_token,
                'lastLoggedInAt': datetime.now(timezone.utc).isoformat(),
                'lastTokenRefreshAt': datetime.now(timezone.utc).isoformat()
            }

            # Save credentials and set API tokens
            self.config.save_user_credentials(login_credentials)
            self.api.set_auth_tokens(token, new_token)

            return login_credentials

        except Exception as e:
            raise ValueError(f"Login failed: {e}")

    def logout(self) -> None:
        """Logout user and clear credentials"""
        self.config.clear_user_credentials()
        self.api.set_auth_tokens(None, None)

    def get_auth_details(self) -> Dict[str, Any]:
        """Get current auth details, refreshing tokens if needed"""
        credentials = self.config.read_user_credentials()

        if not credentials:
            raise ValueError("No credentials found. Please login first.")

        # Validate tokens
        token = credentials.get('token', '')
        new_token = credentials.get('newToken', '')

        if not all([token, new_token]):
            raise ValueError("Invalid credentials: missing tokens")

        # Check if tokens need refresh
        token_valid, token_needs_refresh = self._validate_token(token)
        new_token_valid, new_token_needs_refresh = self._validate_token(new_token)

        if not token_valid or not new_token_valid:
            raise ValueError("Tokens are expired. Please login again.")

        if token_needs_refresh or new_token_needs_refresh:
            credentials = self._refresh_tokens(credentials)

        # Set API tokens
        self.api.set_auth_tokens(credentials['token'], credentials['newToken'])

        return credentials

    def _validate_token(self, token: str) -> Tuple[bool, bool]:
        """Validate JWT token and check if refresh is needed"""
        if not token:
            return False, False

        try:
            # Decode JWT payload (basic validation)
            parts = token.split('.')
            if len(parts) != 3:
                return False, False

            # Decode payload
            payload_b64 = parts[1]
            # Add padding if needed
            payload_b64 += '=' * (4 - len(payload_b64) % 4)
            payload_json = base64.b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)

            exp = payload.get('exp')
            if not exp:
                return False, False

            # Check expiration
            current_time = datetime.now(timezone.utc).timestamp()
            two_days_seconds = 2 * 24 * 60 * 60
            remaining_seconds = exp - current_time

            expired = remaining_seconds <= 0
            needs_refresh = remaining_seconds > 0 and remaining_seconds <= two_days_seconds

            return not expired, needs_refresh

        except Exception:
            return False, False

    def _refresh_tokens(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Refresh authentication tokens"""
        try:
            new_token = credentials['newToken']
            response = self.api.refresh_tokens(new_token)

            # Update credentials with new tokens
            credentials['token'] = response.get('oldToken', credentials['token'])
            credentials['newToken'] = response.get('newToken', credentials['newToken'])
            credentials['lastTokenRefreshAt'] = datetime.now(timezone.utc).isoformat()

            # Save updated credentials
            self.config.save_user_credentials(credentials)

            return credentials

        except Exception as e:
            raise ValueError(f"Token refresh failed: {e}")

    def whoami(self) -> Optional[Dict[str, Any]]:
        """Get current user info"""
        try:
            credentials = self.get_auth_details()
            return {
                'email': credentials['user']['email'],
                'uuid': credentials['user']['uuid'],
                'rootFolderId': credentials['user'].get('root_folder_id', ''),
            }
        except Exception:
            return None


# Global instance
auth_service = AuthService()