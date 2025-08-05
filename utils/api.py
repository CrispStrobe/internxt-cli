#!/usr/bin/env python3
"""
internxt_cli/utils/api.py
API client for Internxt services
"""

import requests
import json
import sys
import os
from typing import Dict, Any, Optional, Tuple, List

# Fix imports to work both as module and direct script
try:
    from ..config.config import config_service
except ImportError:
    # Fallback for direct script execution
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from config.config import config_service


class ApiClient:
    """HTTP client for Internxt API"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'internxt-python-cli/1.0.0'
        })

        self.drive_api_url = config_service.get('DRIVE_NEW_API_URL')
        self.network_url = config_service.get('NETWORK_URL')

        # Auth tokens
        self.token = None
        self.new_token = None

    def set_auth_tokens(self, token: str, new_token: str):
        """Set authentication tokens"""
        self.token = token
        self.new_token = new_token
        if new_token:
            self.session.headers.update({
                'Authorization': f'Bearer {new_token}'
            })
        elif 'Authorization' in self.session.headers:
            del self.session.headers['Authorization']

    def _handle_request_error(self, response: requests.Response, action: str):
        """Handle HTTP request errors with detailed information"""
        try:
            error_data = response.json()
            error_message = error_data.get('message', f'HTTP {response.status_code}')
        except:
            error_message = f'HTTP {response.status_code}: {response.text[:200] if response.text else "No response body"}'
        
        raise requests.HTTPError(f"{action} failed: {error_message}")

    def post(self, url: str, data: Dict[str, Any] = None,
             headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Make POST request"""
        request_headers = {}
        if headers:
            request_headers.update(headers)

        try:
            response = self.session.post(url, json=data, headers=request_headers, timeout=30)
            if not response.ok:
                self._handle_request_error(response, "POST")
            return response.json()
        except requests.exceptions.Timeout:
            raise requests.HTTPError("Request timeout")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError("Connection error")

    def get(self, url: str, params: Dict[str, Any] = None,
            headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Make GET request"""
        request_headers = {}
        if headers:
            request_headers.update(headers)

        try:
            response = self.session.get(url, params=params, headers=request_headers, timeout=30)
            if not response.ok:
                self._handle_request_error(response, "GET")
            return response.json()
        except requests.exceptions.Timeout:
            raise requests.HTTPError("Request timeout")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError("Connection error")

    def put(self, url: str, data: Dict[str, Any] = None,
            headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Make PUT request"""
        request_headers = {}
        if headers:
            request_headers.update(headers)

        try:
            response = self.session.put(url, json=data, headers=request_headers, timeout=60)
            if not response.ok:
                self._handle_request_error(response, "PUT")
            return response.json()
        except requests.exceptions.Timeout:
            raise requests.HTTPError("Request timeout")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError("Connection error")

    def delete(self, url: str, headers: Dict[str, str] = None) -> Dict[str, Any]:
        """Make DELETE request"""
        request_headers = {}
        if headers:
            request_headers.update(headers)

        try:
            response = self.session.delete(url, headers=request_headers, timeout=30)
            if not response.ok:
                self._handle_request_error(response, "DELETE")
            
            try:
                return response.json()
            except json.JSONDecodeError:
                return {"success": True}
        except requests.exceptions.Timeout:
            raise requests.HTTPError("Request timeout")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError("Connection error")

    # Auth API endpoints
    def login(self, email: str, password: str, tfa_code: str = None) -> Dict[str, Any]:
        """Login to Internxt"""
        url = f"{self.drive_api_url}/auth/signin"
        data = {
            'email': email.lower(),
            'password': password
        }

        if tfa_code:
            data['tfa'] = tfa_code

        return self.post(url, data)

    def check_2fa_needed(self, email: str) -> bool:
        """Check if 2FA is required for user"""
        url = f"{self.drive_api_url}/auth/security"
        data = {'email': email.lower()}

        try:
            response = self.post(url, data)
            return response.get('tfaEnabled', False)
        except Exception as e:
            print(f"Warning: Could not check 2FA status: {e}")
            return False

    def refresh_tokens(self, refresh_token: str) -> Dict[str, Any]:
        """Refresh authentication tokens"""
        url = f"{self.drive_api_url}/auth/refresh"
        headers = {'Authorization': f'Bearer {refresh_token}'}

        return self.post(url, headers=headers)

    # Storage API endpoints
    def get_folder_content(self, folder_uuid: str, offset: int = 0,
                          limit: int = 50) -> Dict[str, Any]:
        """Get folder contents"""
        url = f"{self.drive_api_url}/storage/folder/{folder_uuid}/meta"
        params = {
            'offset': offset,
            'limit': limit,
            'sort': 'plainName',
            'order': 'ASC'
        }

        return self.get(url, params)

    def get_folder_files(self, folder_uuid: str, offset: int = 0,
                        limit: int = 50) -> Dict[str, Any]:
        """Get files in folder"""
        url = f"{self.drive_api_url}/storage/folder/{folder_uuid}/files"
        params = {
            'offset': offset,
            'limit': limit,
            'sort': 'plainName',
            'order': 'ASC'
        }

        return self.get(url, params)

    def get_folder_folders(self, folder_uuid: str, offset: int = 0,
                          limit: int = 50) -> Dict[str, Any]:
        """Get subfolders in folder"""
        url = f"{self.drive_api_url}/storage/folder/{folder_uuid}/folders"
        params = {
            'offset': offset,
            'limit': limit,
            'sort': 'plainName',
            'order': 'ASC'
        }

        return self.get(url, params)

    def create_folder(self, plain_name: str, parent_folder_uuid: str) -> Dict[str, Any]:
        """Create new folder"""
        url = f"{self.drive_api_url}/storage/folder"
        data = {
            'plainName': plain_name,
            'parentFolderUuid': parent_folder_uuid
        }

        return self.post(url, data)

    def create_file_entry(self, file_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create file entry in drive"""
        url = f"{self.drive_api_url}/storage/file"

        return self.post(url, file_data)

    def get_file_metadata(self, file_uuid: str) -> Dict[str, Any]:
        """Get file metadata"""
        url = f"{self.drive_api_url}/storage/file/{file_uuid}/meta"

        return self.get(url)

    def get_folder_metadata(self, folder_uuid: str) -> Dict[str, Any]:
        """Get folder metadata"""
        url = f"{self.drive_api_url}/storage/folder/{folder_uuid}/meta"

        return self.get(url)

    def delete_file(self, file_uuid: str) -> Dict[str, Any]:
        """Delete a file"""
        url = f"{self.drive_api_url}/storage/file/{file_uuid}"

        return self.delete(url)

    def delete_folder(self, folder_uuid: str) -> Dict[str, Any]:
        """Delete a folder"""
        url = f"{self.drive_api_url}/storage/folder/{folder_uuid}"

        return self.delete(url)

    def move_file(self, file_uuid: str, destination_folder_uuid: str) -> Dict[str, Any]:
        """Move a file to a different folder"""
        url = f"{self.drive_api_url}/storage/file/{file_uuid}/move"
        data = {
            'destinationFolderUuid': destination_folder_uuid
        }

        return self.post(url, data)

    def move_folder(self, folder_uuid: str, destination_folder_uuid: str) -> Dict[str, Any]:
        """Move a folder to a different location"""
        url = f"{self.drive_api_url}/storage/folder/{folder_uuid}/move"
        data = {
            'destinationFolderUuid': destination_folder_uuid
        }

        return self.post(url, data)

    def search_files(self, query: str, folder_uuid: str = None) -> List[Dict[str, Any]]:
        """Search for files by name"""
        url = f"{self.drive_api_url}/storage/search"
        params = {
            'query': query,
            'type': 'file'
        }
        
        if folder_uuid:
            params['folderUuid'] = folder_uuid

        response = self.get(url, params)
        return response.get('results', [])

    def get_storage_usage(self) -> Dict[str, Any]:
        """Get storage usage information"""
        url = f"{self.drive_api_url}/storage/usage"

        return self.get(url)

    # Network API endpoints (for file upload/download)
    def get_upload_urls(self, bucket_id: str, file_size: int) -> Dict[str, Any]:
        """Get upload URLs for file"""
        url = f"{self.network_url}/api/storage/bucket/{bucket_id}/file"
        data = {
            'fileSize': file_size
        }

        return self.post(url, data)

    def upload_file_chunk(self, upload_url: str, chunk_data: bytes,
                         content_type: str = 'application/octet-stream') -> requests.Response:
        """Upload file chunk to network"""
        headers = {
            'Content-Type': content_type
        }

        try:
            response = requests.put(upload_url, data=chunk_data, headers=headers, timeout=300)
            if not response.ok:
                self._handle_request_error(response, "Upload chunk")
            return response
        except requests.exceptions.Timeout:
            raise requests.HTTPError("Upload timeout")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError("Upload connection error")

    def get_download_urls(self, bucket_id: str, file_id: str) -> Dict[str, Any]:
        """Get download URLs for file"""
        url = f"{self.network_url}/api/storage/bucket/{bucket_id}/file/{file_id}"

        return self.get(url)

    def download_file_chunk(self, download_url: str, range_header: str = None) -> bytes:
        """Download file chunk from network"""
        headers = {}
        if range_header:
            headers['Range'] = range_header

        try:
            response = requests.get(download_url, headers=headers, stream=True, timeout=300)
            if not response.ok:
                self._handle_request_error(response, "Download chunk")
            return response.content
        except requests.exceptions.Timeout:
            raise requests.HTTPError("Download timeout")
        except requests.exceptions.ConnectionError:
            raise requests.HTTPError("Download connection error")

    # User info endpoints
    def get_user_info(self) -> Dict[str, Any]:
        """Get current user information"""
        url = f"{self.drive_api_url}/user"

        return self.get(url)

    def get_user_usage(self) -> Dict[str, Any]:
        """Get user storage usage"""
        url = f"{self.drive_api_url}/user/usage"

        return self.get(url)

    # Health check
    def health_check(self) -> bool:
        """Check if the API is accessible"""
        try:
            url = f"{self.drive_api_url}/health"
            response = requests.get(url, timeout=10)
            return response.ok
        except:
            return False

    def network_health_check(self) -> bool:
        """Check if the network API is accessible"""
        try:
            url = f"{self.network_url}/api/health"
            response = requests.get(url, timeout=10)
            return response.ok
        except:
            return False


# Global instance
api_client = ApiClient()