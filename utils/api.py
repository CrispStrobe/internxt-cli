# ==> utils/api.py <==
#!/usr/bin/env python3
"""
API Client - A direct translation of the network calls in the TypeScript SDK.
"""
import requests
import json
from typing import Dict, Any, Optional

from config.config import config_service

class ApiClient:
    """
    This client's methods are a direct port of the HTTP calls found in the
    official Internxt TypeScript SDK source code (`src/auth/index.ts`).
    """
    def __init__(self):
        self.session = requests.Session()
        self.drive_api_url = config_service.get('DRIVE_NEW_API_URL')
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': "internxt-cli-python/3.0.0", # Blueprint Version
            'Accept': 'application/json',
        })

    def _make_request(self, method: str, url: str, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Makes an HTTP request and returns the JSON response."""
        try:
            response = self.session.request(method, url, json=data, timeout=30)
            response.raise_for_status()
            return response.json() if response.content else {}
        except requests.exceptions.HTTPError as e:
            error_message = f"HTTP {e.response.status_code} Error"
            try: error_message = e.response.json().get("message", "Unknown Error")
            except json.JSONDecodeError: pass
            raise ValueError(f"API Error: {error_message}") from e
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Network request failed: {e}") from e
    
    def set_auth_tokens(self, new_token: Optional[str]):
        """Sets the auth token for subsequent requests."""
        if new_token:
            self.session.headers['Authorization'] = f"Bearer {new_token}"
        else:
            self.session.headers.pop('Authorization', None)

    def security_details(self, email: str) -> Dict[str, Any]:
        """
        Gets security details (sKey and 2FA status) by POSTing email to /auth/login.
        This matches the SDK's `securityDetails` function.
        """
        url = f"{self.drive_api_url}/auth/login"
        print(f"   Calling (Step 1 - Security Details): {url}")
        return self._make_request("POST", url, data={'email': email})

    def login_access(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Performs the final login with the encrypted password hash and keys.
        This matches the SDK's final call to `/auth/login/access`.
        """
        url = f"{self.drive_api_url}/auth/login/access"
        print(f"   Calling (Step 2 - Final Login): {url}")
        return self._make_request("POST", url, data=payload)

# Global instance
api_client = ApiClient()