#!/usr/bin/env python3
"""
internxt_cli/utils/api.py
API client for Internxt services - CORRECTED TO MATCH THE COMPLETE SDK BLUEPRINT
"""

import requests
import json
import sys
import os
from typing import Dict, Any, Optional

# Corrected relative import
from config.config import config_service


class ApiClient:
    """
    HTTP client for Internxt API. All endpoints are corrected to match the official SDK blueprint.
    """

    def __init__(self):
        self.session = requests.Session()
        self.drive_api_url = config_service.get('DRIVE_NEW_API_URL')
        self.network_url = config_service.get('NETWORK_URL')
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'internxt-python-cli/4.0.0' # Final Blueprint Version
        })

    def set_auth_tokens(self, token: Optional[str], new_token: Optional[str]):
        """Sets the auth token for subsequent requests."""
        if new_token:
            self.session.headers['Authorization'] = f'Bearer {new_token}'
        else:
            self.session.headers.pop('Authorization', None)

    def _make_request(self, method: str, url: str, data: Optional[Dict[str, Any]] = None, 
                      headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None) -> requests.Response:
        """Central request handler, returns the full response object."""
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            response = requests.request(method, url, json=data, headers=request_headers, params=params, timeout=30)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            error_message = f"HTTP {e.response.status_code} Error"
            try: error_message = e.response.json().get("message", "Unknown Error")
            except json.JSONDecodeError: pass
            raise ValueError(f"API Error: {error_message}") from e
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Network request failed for {url}: {e}") from e

    def get(self, url: str, params: Dict[str, Any] = None, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Make GET request and return JSON"""
        response = self._make_request("GET", url, params=params, headers=headers)
        return response.json() if response.content else {}
    
    def post(self, url: str, data: Dict[str, Any] = None, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Make POST request and return JSON"""
        response = self._make_request("POST", url, data=data, headers=headers)
        return response.json() if response.content else {}

    # --- AUTH API ENDPOINTS (Corrected to match src/auth/index.ts) ---

    def security_details(self, email: str) -> Dict[str, Any]:
        """Gets security details (sKey and 2FA status)."""
        url = f"{self.drive_api_url}/auth/login"
        return self.post(url, data={'email': email})

    def login_access(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Performs the final login with the encrypted password hash and keys."""
        url = f"{self.drive_api_url}/auth/login/access"
        return self.post(url, data=payload)

    # --- STORAGE API ENDPOINTS (Corrected to match src/drive/storage/index.ts) ---
    
    def get_folder_folders(self, folder_uuid: str, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Get subfolders in folder"""
        # Corrected Endpoint: /folders/content/{uuid}/folders
        url = f"{self.drive_api_url}/folders/content/{folder_uuid}/folders"
        params = {'offset': offset, 'limit': limit, 'sort': 'plainName', 'direction': 'ASC'}
        return self.get(url, params)

    def get_folder_files(self, folder_uuid: str, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Get files in folder"""
        # Corrected Endpoint: /folders/content/{uuid}/files
        url = f"{self.drive_api_url}/folders/content/{folder_uuid}/files"
        params = {'offset': offset, 'limit': limit, 'sort': 'plainName', 'direction': 'ASC'}
        return self.get(url, params)

    def create_folder(self, plain_name: str, parent_folder_uuid: str) -> Dict[str, Any]:
        """Create new folder"""
        # Corrected Endpoint: /folders
        url = f"{self.drive_api_url}/folders"
        data = {'plainName': plain_name, 'parentFolderUuid': parent_folder_uuid}
        return self.post(url, data)
        
    def create_file_entry(self, file_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create file entry in drive"""
        # Corrected Endpoint: /files
        url = f"{self.drive_api_url}/files"
        # The SDK blueprint sends a different payload structure than the old baseline
        payload = {
            'name': file_data.get('name'),
            'bucket': file_data.get('bucket'),
            'fileId': file_data.get('fileId'),
            'encryptVersion': file_data.get('encryptVersion'),
            'folderUuid': file_data.get('folderId'), # The old baseline used 'folderId' for a UUID
            'size': file_data.get('size'),
            'plainName': file_data.get('plainName'),
            'type': file_data.get('type'),
        }
        return self.post(url, payload)

    def get_file_metadata(self, file_uuid: str) -> Dict[str, Any]:
        """Get file metadata"""
        # Corrected Endpoint: /files/{uuid}/meta
        url = f"{self.drive_api_url}/files/{file_uuid}/meta"
        return self.get(url)

    def get_folder_metadata(self, folder_uuid: str) -> Dict[str, Any]:
        """Get folder metadata"""
        # Corrected Endpoint: /folders/{uuid}/meta
        url = f"{self.drive_api_url}/folders/{folder_uuid}/meta"
        return self.get(url)

    def delete_file(self, file_uuid: str) -> Dict[str, Any]:
        """Delete a file"""
        # Corrected Endpoint: /files/{uuid}
        url = f"{self.drive_api_url}/files/{file_uuid}"
        return self.delete(url)

    def delete_folder(self, folder_uuid: str) -> Dict[str, Any]:
        """Delete a folder"""
        # Corrected Endpoint: /folders/{uuid}
        url = f"{self.drive_api_url}/folders/{folder_uuid}"
        return self.delete(url)

    # --- OTHER BASELINE METHODS (preserved) ---

    def get_storage_usage(self) -> Dict[str, Any]:
        """Get storage usage information"""
        # Corrected Endpoint: /users/usage (v2 endpoint)
        url = f"{self.drive_api_url}/users/usage"
        return self.get(url)

    # Note: The network API methods below interact with a different service ('gateway.internxt.com')
    # and their endpoints might be correct as they are. They are preserved from the baseline.
    def get_upload_urls(self, bucket_id: str, file_size: int) -> Dict[str, Any]:
        """Get upload URLs for file"""
        # This endpoint uses NETWORK_URL, not DRIVE_API_URL
        url = f"{self.network_url}/v2/buckets/{bucket_id}/files/start"
        data = {'uploads': [{'index': 0, 'size': file_size}]}
        return self.post(url, data)

    def get_download_urls(self, bucket_id: str, file_id: str) -> Dict[str, Any]:
        """Get download URLs for file"""
        # This endpoint uses NETWORK_URL and a different header version
        url = f"{self.network_url}/buckets/{bucket_id}/files/{file_id}/info"
        return self.get(url, headers={'x-api-version': '2'})

# Global instance
api_client = ApiClient()