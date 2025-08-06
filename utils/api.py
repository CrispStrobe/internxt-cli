#!/usr/bin/env python3
"""
internxt_cli/utils/api.py
API client for Internxt services - Enhanced with trash/delete operations
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
    HTTP client for Internxt API - Enhanced with trash/delete operations
    """

    def __init__(self):
        self.session = requests.Session()
        self.drive_api_url = config_service.get('DRIVE_NEW_API_URL')
        self.network_url = config_service.get('NETWORK_URL')
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'internxt-python-cli/4.0.0',
            'Accept': 'application/json',
        })

    def set_auth_tokens(self, token: Optional[str], new_token: Optional[str]):
        """Sets the auth token for subsequent requests."""
        if new_token:
            self.session.headers['Authorization'] = f'Bearer {new_token}'
        else:
            self.session.headers.pop('Authorization', None)

    def _make_request(self, method: str, url: str, data: Optional[Any] = None, 
                      headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None, 
                      auth: Optional[tuple] = None, is_json=True) -> requests.Response:
        """Central request handler, returns the full response object."""
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            # If basic auth is provided, it overrides the session's Bearer token
            if auth:
                request_headers.pop('Authorization', None)

            json_payload = data if is_json else None
            data_payload = data if not is_json else None

            response = requests.request(method, url, json=json_payload, data=data_payload, 
                                        headers=request_headers, params=params, auth=auth, timeout=300)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as e:
            error_message = f"HTTP {e.response.status_code} Error"
            try: 
                error_message = e.response.json().get("message", "Unknown Error")
            except json.JSONDecodeError: 
                pass
            raise ValueError(f"API Error: {error_message}") from e
        except requests.exceptions.RequestException as e:
            raise ConnectionError(f"Network request failed for {url}: {e}") from e

    def get(self, url: str, params: Dict[str, Any] = None, headers: Dict[str, str] = None, auth: Optional[tuple] = None) -> Dict[str, Any]:
        """Make GET request and return JSON"""
        response = self._make_request("GET", url, params=params, headers=headers, auth=auth)
        return response.json() if response.content else {}
    
    def post(self, url: str, data: Dict[str, Any] = None, headers: Dict[str, str] = None, auth: Optional[tuple] = None) -> Dict[str, Any]:
        """Make POST request and return JSON"""
        response = self._make_request("POST", url, data=data, headers=headers, auth=auth)
        return response.json() if response.content else {}

    def delete(self, url: str, headers: Dict[str, str] = None, auth: Optional[tuple] = None) -> Dict[str, Any]:
        """Make DELETE request and return JSON"""
        response = self._make_request("DELETE", url, headers=headers, auth=auth)
        return response.json() if response.content else {}
    
    def put(self, url: str, data: Dict[str, Any] = None, headers: Dict[str, str] = None, auth: Optional[tuple] = None) -> Dict[str, Any]:
        """Make PUT request and return JSON"""
        response = self._make_request("PUT", url, data=data, headers=headers, auth=auth)
        return response.json() if response.content else {}

    def patch(self, url: str, data: Dict[str, Any] = None, headers: Dict[str, str] = None, auth: Optional[tuple] = None) -> Dict[str, Any]:
        """Make PATCH request and return JSON"""
        response = self._make_request("PATCH", url, data=data, headers=headers, auth=auth)
        return response.json() if response.content else {}

    # --- AUTH API ENDPOINTS ---

    def security_details(self, email: str) -> Dict[str, Any]:
        """Gets security details (sKey and 2FA status)."""
        url = f"{self.drive_api_url}/auth/login"
        return self.post(url, data={'email': email})

    def login_access(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Performs the final login with the encrypted password hash and keys."""
        url = f"{self.drive_api_url}/auth/login/access"
        return self.post(url, data=payload)

    # --- STORAGE API ENDPOINTS ---
    
    def get_folder_folders(self, folder_uuid: str, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Get subfolders in folder"""
        url = f"{self.drive_api_url}/folders/content/{folder_uuid}/folders"
        params = {'offset': offset, 'limit': limit, 'sort': 'plainName', 'direction': 'ASC'}
        return self.get(url, params)

    def get_folder_files(self, folder_uuid: str, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        """Get files in folder"""
        url = f"{self.drive_api_url}/folders/content/{folder_uuid}/files"
        params = {'offset': offset, 'limit': limit, 'sort': 'plainName', 'direction': 'ASC'}
        return self.get(url, params)

    def create_folder(self, plain_name: str, parent_folder_uuid: str) -> Dict[str, Any]:
        """Create new folder"""
        url = f"{self.drive_api_url}/folders"
        data = {'plainName': plain_name, 'parentFolderUuid': parent_folder_uuid}
        return self.post(url, data)
    
    # --- NETWORK API ENDPOINTS ---
    
    def start_upload(self, bucket_id: str, file_size: int, auth: tuple) -> Dict[str, Any]:
        """Gets upload URLs for a file, using Basic Auth."""
        url = f"{self.network_url}/v2/buckets/{bucket_id}/files/start"
        data = {'uploads': [{'index': 0, 'size': file_size}]}
        return self.post(url, data, auth=auth)

    def upload_chunk(self, upload_url: str, chunk_data: bytes):
        """Uploads a raw chunk of data using PUT. No auth needed for pre-signed URL."""
        response = requests.put(upload_url, data=chunk_data, headers={'Content-Type': 'application/octet-stream'}, timeout=300)
        response.raise_for_status()

    def finish_upload(self, bucket_id: str, payload: Dict[str, Any], auth: tuple) -> Dict[str, Any]:
        """Finalizes an upload, using Basic Auth."""
        url = f"{self.network_url}/v2/buckets/{bucket_id}/files/finish"
        return self.post(url, data=payload, auth=auth)
    
    # --- FILE/FOLDER OPERATIONS ---
    
    def create_file_entry(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Creates the file metadata entry in the Drive, matching the SDK blueprint."""
        url = f"{self.drive_api_url}/files"
        return self.post(url, data=payload)

    def get_file_metadata(self, file_uuid: str) -> Dict[str, Any]:
        """Get file metadata"""
        url = f"{self.drive_api_url}/files/{file_uuid}/meta"
        return self.get(url)

    def get_folder_metadata(self, folder_uuid: str) -> Dict[str, Any]:
        """Get folder metadata"""
        url = f"{self.drive_api_url}/folders/{folder_uuid}/meta"
        return self.get(url)

    # --- DELETE/TRASH OPERATIONS ---
    
    def delete_file(self, file_uuid: str) -> Dict[str, Any]:
        """Delete a file (moves to trash or deletes permanently depending on API)"""
        url = f"{self.drive_api_url}/files/{file_uuid}"
        return self.delete(url)

    def delete_folder(self, folder_uuid: str) -> Dict[str, Any]:
        """Delete a folder (moves to trash or deletes permanently depending on API)"""
        url = f"{self.drive_api_url}/folders/{folder_uuid}"
        return self.delete(url)

    def trash_items(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Add items to trash - matches TrashService.trashItems()"""
        url = f"{self.drive_api_url}/trash"
        return self.post(url, data=payload)

    def get_trash_content(self, offset: int = 0, limit: int = 50, item_type: str = 'both') -> Dict[str, Any]:
        """Get trash content"""
        url = f"{self.drive_api_url}/trash"
        params = {'offset': offset, 'limit': limit, 'type': item_type}
        return self.get(url, params)

    def clear_trash(self) -> Dict[str, Any]:
        """Clear all items from trash permanently"""
        url = f"{self.drive_api_url}/trash/clear"
        return self.delete(url)

    def restore_item(self, item_uuid: str, item_type: str, destination_folder_uuid: str = None) -> Dict[str, Any]:
        """Restore item from trash"""
        url = f"{self.drive_api_url}/trash/restore"
        data = {
            'uuid': item_uuid,
            'type': item_type,
            'destinationFolderUuid': destination_folder_uuid
        }
        return self.post(url, data)

    def delete_permanently(self, item_uuid: str, item_type: str) -> Dict[str, Any]:
        """Permanently delete item from trash"""
        url = f"{self.drive_api_url}/trash/{item_uuid}"
        params = {'type': item_type}
        return self.delete(url, headers={'Content-Type': 'application/json'})

    # --- MOVE/RENAME OPERATIONS ---
    
    def move_file(self, file_uuid: str, destination_folder_uuid: str) -> Dict[str, Any]:
        """Move file to different folder"""
        url = f"{self.drive_api_url}/files/{file_uuid}/move"
        data = {'destinationFolderUuid': destination_folder_uuid}
        return self.patch(url, data)

    def move_folder(self, folder_uuid: str, destination_folder_uuid: str) -> Dict[str, Any]:
        """Move folder to different folder"""
        url = f"{self.drive_api_url}/folders/{folder_uuid}/move"
        data = {'destinationFolderUuid': destination_folder_uuid}
        return self.patch(url, data)

    def rename_file(self, file_uuid: str, new_name: str) -> Dict[str, Any]:
        """Rename file"""
        url = f"{self.drive_api_url}/files/{file_uuid}"
        data = {'plainName': new_name}
        return self.patch(url, data)

    def rename_folder(self, folder_uuid: str, new_name: str) -> Dict[str, Any]:
        """Rename folder"""
        url = f"{self.drive_api_url}/folders/{folder_uuid}"
        data = {'plainName': new_name}
        return self.patch(url, data)

    # --- DOWNLOAD OPERATIONS ---
    
    def get_download_links(self, bucket_id: str, file_id: str, auth: tuple) -> Dict[str, Any]:
        """Gets download URLs for a file, using Basic Auth."""
        url = f"{self.network_url}/buckets/{bucket_id}/files/{file_id}/info"
        return self.get(url, headers={'x-api-version': '2'}, auth=auth)

    def download_chunk(self, download_url: str) -> bytes:
        """Downloads a raw chunk of data. No auth needed for pre-signed URL."""
        response = requests.get(download_url, timeout=300)
        response.raise_for_status()
        return response.content

    # --- UTILITY OPERATIONS ---
    
    def get_storage_usage(self) -> Dict[str, Any]:
        """Get storage usage information"""
        url = f"{self.drive_api_url}/users/usage"
        return self.get(url)

    def get_user_info(self) -> Dict[str, Any]:
        """Get current user information"""
        url = f"{self.drive_api_url}/users/me"
        return self.get(url)

    # --- LEGACY/COMPATIBILITY METHODS ---
    
    def create_file_entry_v1(self, file_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create file entry in drive (legacy method)"""
        url = f"{self.drive_api_url}/files"
        payload = {
            'name': file_data.get('name'),
            'bucket': file_data.get('bucket'),
            'fileId': file_data.get('fileId'),
            'encryptVersion': file_data.get('encryptVersion'),
            'folderUuid': file_data.get('folderId'), 
            'size': file_data.get('size'),
            'plainName': file_data.get('plainName'),
            'type': file_data.get('type'),
        }
        return self.post(url, payload)

    def get_upload_urls(self, bucket_id: str, file_size: int) -> Dict[str, Any]:
        """Get upload URLs for file (legacy method)"""
        url = f"{self.network_url}/v2/buckets/{bucket_id}/files/start"
        data = {'uploads': [{'index': 0, 'size': file_size}]}
        return self.post(url, data)

    def get_download_urls(self, bucket_id: str, file_id: str) -> Dict[str, Any]:
        """Get download URLs for file (legacy method)"""
        url = f"{self.network_url}/buckets/{bucket_id}/files/{file_id}/info"
        return self.get(url, headers={'x-api-version': '2'})


# Global instance
api_client = ApiClient()