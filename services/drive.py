#!/usr/bin/env python3
"""
internxt_cli/services/drive.py
Drive operations for Internxt CLI - EXACT match to TypeScript NetworkFacade and upload process
FIXED: Now implements the EXACT upload/download protocol from TypeScript SDK
"""

import os
import sys
import hashlib
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, BinaryIO
from tqdm import tqdm
import io

# Fix imports to work both as module and direct script
try:
    from ..config.config import config_service
    from ..utils.api import api_client
    from .crypto import crypto_service
    from .auth import auth_service
except ImportError:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from config.config import config_service
    from utils.api import api_client
    from services.crypto import crypto_service
    from services.auth import auth_service


class DriveService:
    """
    Handles drive operations - EXACT match to TypeScript SDK upload/download process
    """

    def __init__(self):
        self.config = config_service
        self.api = api_client
        self.crypto = crypto_service
        self.auth = auth_service

        self.TWENTY_GIGABYTES = 20 * 1024 * 1024 * 1024   # 20GB limit
        self.MULTIPART_THRESHOLD = 100 * 1024 * 1024      # 100MB multipart threshold
        self.CHUNK_SIZE = 64 * 1024 * 1024                # 64MB chunks

    def _get_network_auth(self, user_creds: Dict[str, Any]) -> tuple:
        """
        Creates the Basic Auth credentials for the Network API.
        EXACT match to NetworkFacade authentication in TypeScript
        """
        bridge_user = user_creds.get('bridgeUser')
        user_id = user_creds.get('userId')
        if not bridge_user or not user_id:
            raise ValueError("Missing network credentials (bridgeUser, userId)")
        
        # EXACT match to TypeScript: SHA256 hash of userId for password
        hashed_password = hashlib.sha256(str(user_id).encode()).hexdigest()
        return (bridge_user, hashed_password)

    def get_folder_content(self, folder_uuid: str) -> Dict[str, List[Dict[str, Any]]]:
        """Get folder contents - matches TypeScript DriveFolderService"""
        try:
            credentials = self.auth.get_auth_details()
            
            # Get folders and files separately (matches TypeScript implementation)
            folders = self._get_all_folders(folder_uuid)
            files = self._get_all_files(folder_uuid)

            return {
                'folders': folders,
                'files': files
            }
            
        except Exception as e:
            print(f"Error getting folder content: {e}")
            return {'folders': [], 'files': []}

    def list_folder(self, folder_uuid: str = None) -> Dict[str, List[Dict[str, Any]]]:
        """List contents of a folder - wrapper for backward compatibility"""
        credentials = self.auth.get_auth_details()

        if not folder_uuid:
            folder_uuid = credentials['user'].get('rootFolderId', '')
            if not folder_uuid:
                raise ValueError("No root folder ID found")

        return self.get_folder_content(folder_uuid)

    def _get_all_folders(self, folder_uuid: str, offset: int = 0) -> List[Dict[str, Any]]:
        """Recursively get all folders - EXACT match to TypeScript pagination"""
        try:
            response = self.api.get_folder_folders(folder_uuid, offset, 50)
            folders = response.get('result', response.get('folders', []))

            # EXACT match to TypeScript: if len == 50, get more
            if len(folders) == 50:
                folders.extend(self._get_all_folders(folder_uuid, offset + 50))

            return folders
            
        except Exception as e:
            print(f"Warning: Failed to get folders: {e}")
            return []

    def _get_all_files(self, folder_uuid: str, offset: int = 0) -> List[Dict[str, Any]]:
        """Recursively get all files - EXACT match to TypeScript pagination"""
        try:
            response = self.api.get_folder_files(folder_uuid, offset, 50)
            files = response.get('result', response.get('files', []))

            # EXACT match to TypeScript: if len == 50, get more
            if len(files) == 50:
                files.extend(self._get_all_files(folder_uuid, offset + 50))

            return files
            
        except Exception as e:
            print(f"Warning: Failed to get files: {e}")
            return []

    def create_folder(self, name: str, parent_folder_uuid: str = None) -> Dict[str, Any]:
        """Create a new folder - matches TypeScript create folder"""
        credentials = self.auth.get_auth_details()

        if not parent_folder_uuid:
            parent_folder_uuid = credentials['user'].get('rootFolderId', '')
            if not parent_folder_uuid:
                raise ValueError("No root folder ID found")

        return self.api.create_folder(name, parent_folder_uuid)

    def upload_file(self, file_path_str: str, destination_folder_uuid: str = None):
        """
        EXACT implementation of file upload matching TypeScript NetworkFacade + DriveFileService
        This matches the upload process from upload-file.ts and NetworkFacade
        """
        credentials = self.auth.get_auth_details()
        user = credentials['user']
        bucket_id = user['bucket']
        mnemonic = user['mnemonic']
        network_auth = self._get_network_auth(user)

        if not destination_folder_uuid:
            destination_folder_uuid = user['rootFolderId']

        file_path = Path(file_path_str)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found at: {file_path}")

        file_size = file_path.stat().st_size
        if file_size > self.TWENTY_GIGABYTES:
            raise ValueError("File is too large (must be less than 20 GB)")
        
        print(f"📤 Uploading '{file_path.name}' using EXACT TypeScript protocol...")
        
        # Read file data
        with open(file_path, 'rb') as f:
            plaintext = f.read()
        
        with tqdm(total=5, desc="Uploading", unit="step", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]') as pbar:
            # Step 1: Encrypt using EXACT Internxt protocol
            pbar.set_description("🔐 Encrypting with exact protocol")
            encrypted_data, file_index_hex = self.crypto.encrypt_stream_internxt_protocol(plaintext, mnemonic, bucket_id)
            pbar.update(1)

            # Step 2: Start upload (get signed URLs)
            pbar.set_description("🚀 Initializing network upload")
            start_response = self.api.start_upload(bucket_id, len(encrypted_data), auth=network_auth)
            upload_details = start_response['uploads'][0]
            upload_url = upload_details['url']
            file_network_uuid = upload_details['uuid']
            pbar.update(1)

            # Step 3: Upload encrypted data to signed URL
            pbar.set_description("☁️  Uploading encrypted data")
            self.api.upload_chunk(upload_url, encrypted_data)
            pbar.update(1)

            # Step 4: Finalize upload (EXACT match to TypeScript finish payload)
            pbar.set_description("✅ Finalizing network upload")
            # Calculate hash of encrypted data (EXACT match to TypeScript)
            encrypted_hash = hashlib.sha256(encrypted_data).hexdigest()
            
            finish_payload = {
                'index': file_index_hex,  # EXACT: hex string, not bytes
                'shards': [{
                    'hash': encrypted_hash,
                    'uuid': file_network_uuid
                }]
            }
            finish_response = self.api.finish_upload(bucket_id, finish_payload, auth=network_auth)
            network_file_id = finish_response['id']
            pbar.update(1)

            # Step 5: Create Drive file entry (EXACT match to TypeScript DriveFileService)
            pbar.set_description("📋 Creating file metadata")
            file_entry_payload = {
                'folderUuid': destination_folder_uuid,
                'plainName': file_path.stem,  # Name without extension
                'type': file_path.suffix.lstrip('.') if file_path.suffix else '',  # Extension without dot
                'size': file_size,  # Original file size, not encrypted size
                'bucket': bucket_id,
                'fileId': network_file_id,  # Network file ID from finish response
                'encryptVersion': 'Aes03',  # EXACT match to TypeScript EncryptionVersion.Aes03
                'name': ''  # EXACT: Empty string for deprecated field
            }
            created_file = self.api.create_file_entry(file_entry_payload)
            pbar.update(1)
        
        print(f"✅ Success! File '{created_file.get('plainName')}' uploaded with UUID: {created_file.get('uuid')}")
        print(f"🔐 Encryption index: {file_index_hex[:16]}...")
        return created_file

    def download_file(self, file_uuid: str, destination_path_str: str):
        """
        EXACT implementation of file download matching TypeScript NetworkFacade
        This matches the download process from download-file.ts and NetworkFacade
        """
        credentials = self.auth.get_auth_details()
        user = credentials['user']
        mnemonic = user['mnemonic']
        network_auth = self._get_network_auth(user)
        
        print(f"📥 Downloading file UUID: {file_uuid} using EXACT TypeScript protocol...")

        with tqdm(total=5, desc="Downloading", unit="step", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]') as pbar:
            # Step 1: Get file metadata from Drive
            pbar.set_description("📋 Fetching file metadata")
            metadata = self.api.get_file_metadata(file_uuid)
            bucket_id = metadata['bucket']
            network_file_id = metadata['fileId']
            file_size = int(metadata['size'])
            
            # Construct filename (EXACT match to TypeScript)
            file_name = metadata.get('plainName', 'downloaded_file')
            file_type = metadata.get('type')
            if file_type:
                file_name = f"{file_name}.{file_type}"
            pbar.update(1)

            # Step 2: Get download links from Network
            pbar.set_description("🔗 Fetching download links")
            links_response = self.api.get_download_links(bucket_id, network_file_id, auth=network_auth)
            download_url = links_response['shards'][0]['url']
            file_index_hex = links_response['index']  # Encryption index
            pbar.update(1)

            # Step 3: Download encrypted data
            pbar.set_description("☁️  Downloading encrypted data")
            encrypted_data = self.api.download_chunk(download_url)
            pbar.update(1)

            # Step 4: Decrypt using EXACT Internxt protocol
            pbar.set_description("🔓 Decrypting with exact protocol")
            decrypted_data = self.crypto.decrypt_stream_internxt_protocol(
                encrypted_data, mnemonic, bucket_id, file_index_hex
            )
            
            # CRITICAL: Trim to exact file size (handles padding from AES-CTR)
            if len(decrypted_data) > file_size:
                decrypted_data = decrypted_data[:file_size]
            pbar.update(1)

            # Step 5: Save decrypted file
            destination_path = Path(destination_path_str)
            if destination_path.is_dir():
                destination_path = destination_path / file_name

            pbar.set_description(f"💾 Saving to disk")
            with open(destination_path, 'wb') as f:
                f.write(decrypted_data)
            pbar.update(1)
        
        print(f"✅ Success! File downloaded and saved to '{destination_path}'")
        print(f"🔓 Decryption index: {file_index_hex[:16]}...")
        return str(destination_path)

    def _format_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        if not size_bytes:
            return "0 B"

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0

        return f"{size_bytes:.1f} PB"

    def delete_file(self, file_uuid: str) -> Dict[str, Any]:
        """Delete a file"""
        credentials = self.auth.get_auth_details()
        return self.api.delete_file(file_uuid)

    def delete_folder(self, folder_uuid: str) -> Dict[str, Any]:
        """Delete a folder"""  
        credentials = self.auth.get_auth_details()
        return self.api.delete_folder(folder_uuid)

    def get_file_metadata(self, file_uuid: str) -> Dict[str, Any]:
        """Get file metadata"""
        credentials = self.auth.get_auth_details()
        return self.api.get_file_metadata(file_uuid)

    def get_folder_metadata(self, folder_uuid: str) -> Dict[str, Any]:
        """Get folder metadata"""
        credentials = self.auth.get_auth_details()
        return self.api.get_folder_metadata(folder_uuid)


# Global instance
drive_service = DriveService()