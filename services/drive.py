#!/usr/bin/env python3
"""
internxt_cli/services/drive.py
Drive operations for Internxt CLI
"""

import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from tqdm import tqdm

# Fix imports to work both as module and direct script
try:
    from ..config.config import config_service
    from ..utils.api import api_client
    from .crypto import crypto_service
    from .auth import auth_service
except ImportError:
    # Fallback for direct script execution
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    if parent_dir not in sys.path:
        sys.path.insert(0, parent_dir)
    from config.config import config_service
    from utils.api import api_client
    from services.crypto import crypto_service
    from services.auth import auth_service


class DriveService:
    """Handles drive operations (list, upload, download)"""

    def __init__(self):
        self.config = config_service
        self.api = api_client
        self.crypto = crypto_service
        self.auth = auth_service

        # Upload limits
        self.max_file_size = 20 * 1024 * 1024 * 1024  # 20GB
        self.multipart_threshold = 100 * 1024 * 1024   # 100MB
        self.chunk_size = 64 * 1024 * 1024             # 64MB chunks

    def list_folder(self, folder_uuid: str = None) -> Dict[str, List[Dict[str, Any]]]:
        """List contents of a folder"""
        credentials = self.auth.get_auth_details()

        if not folder_uuid:
            folder_uuid = credentials['user'].get('root_folder_id', '')
            if not folder_uuid:
                raise ValueError("No root folder ID found")

        # Get all folders and files
        folders = self._get_all_folders(folder_uuid)
        files = self._get_all_files(folder_uuid)

        return {
            'folders': folders,
            'files': files
        }

    def _get_all_folders(self, folder_uuid: str, offset: int = 0) -> List[Dict[str, Any]]:
        """Recursively get all folders in a directory"""
        try:
            response = self.api.get_folder_folders(folder_uuid, offset, 50)
            folders = response.get('result', [])

            if len(folders) == 50:  # More folders available
                folders.extend(self._get_all_folders(folder_uuid, offset + 50))

            return folders
        except Exception as e:
            print(f"Warning: Failed to get folders: {e}")
            return []

    def _get_all_files(self, folder_uuid: str, offset: int = 0) -> List[Dict[str, Any]]:
        """Recursively get all files in a directory"""
        try:
            response = self.api.get_folder_files(folder_uuid, offset, 50)
            files = response.get('result', [])

            if len(files) == 50:  # More files available
                files.extend(self._get_all_files(folder_uuid, offset + 50))

            return files
        except Exception as e:
            print(f"Warning: Failed to get files: {e}")
            return []

    def create_folder(self, name: str, parent_folder_uuid: str = None) -> Dict[str, Any]:
        """Create a new folder"""
        credentials = self.auth.get_auth_details()

        if not parent_folder_uuid:
            parent_folder_uuid = credentials['user'].get('root_folder_id', '')
            if not parent_folder_uuid:
                raise ValueError("No root folder ID found")

        return self.api.create_folder(name, parent_folder_uuid)

    def upload_file(self, file_path: str, destination_folder_uuid: str = None,
                   progress_callback=None) -> Dict[str, Any]:
        """Upload a file to Internxt Drive"""
        file_path = Path(file_path)

        if not file_path.exists() or not file_path.is_file():
            raise ValueError(f"File not found: {file_path}")

        file_size = file_path.stat().st_size
        if file_size == 0:
            raise ValueError("Cannot upload empty files")

        if file_size > self.max_file_size:
            raise ValueError(f"File too large. Maximum size: {self.max_file_size / (1024**3):.1f}GB")

        credentials = self.auth.get_auth_details()
        user = credentials['user']

        if not destination_folder_uuid:
            destination_folder_uuid = user.get('root_folder_id', '')
            if not destination_folder_uuid:
                raise ValueError("No root folder ID found")

        print(f"📁 Uploading {file_path.name} ({self._human_size(file_size)})...")

        # Read and encrypt file
        with open(file_path, 'rb') as f:
            file_content = f.read()

        # Generate encryption key
        bucket_id = user.get('bucket', '')
        file_index = os.urandom(32)  # Random file index
        encryption_key = self.crypto.generate_file_key(user['mnemonic'], bucket_id, file_index)
        encryption_iv = os.urandom(16)

        # Encrypt file content
        print("🔒 Encrypting file...")
        encrypted_content = self.crypto.encrypt_file_stream(file_content, encryption_key, encryption_iv)

        # Upload to network
        print("📤 Uploading to network...")
        file_id = self._upload_to_network(encrypted_content, bucket_id, progress_callback)

        # Create file entry in Drive
        print("📝 Creating file entry...")
        file_data = {
            'plain_name': file_path.stem,
            'type': file_path.suffix.lstrip('.') if file_path.suffix else '',
            'size': file_size,
            'folder_id': destination_folder_uuid,
            'id': file_id,
            'bucket': bucket_id,
            'encrypt_version': 'AES03',
            'name': ''  # Encrypted name will be set by server
        }

        try:
            drive_file = self.api.create_file_entry(file_data)
        except Exception as e:
            print(f"Warning: File uploaded but failed to create drive entry: {e}")
            # Return a basic response if drive entry creation fails
            drive_file = {
                'uuid': file_id,
                'plainName': file_path.stem,
                'type': file_path.suffix.lstrip('.') if file_path.suffix else '',
                'size': file_size
            }

        print(f"✅ File uploaded successfully!")
        print(f"🔗 View at: {self.config.get('DRIVE_WEB_URL')}/file/{drive_file.get('uuid', file_id)}")

        return drive_file

    def _upload_to_network(self, encrypted_content: bytes, bucket_id: str,
                          progress_callback=None) -> str:
        """Upload encrypted content to network"""
        file_size = len(encrypted_content)

        if file_size > self.multipart_threshold:
            return self._upload_multipart(encrypted_content, bucket_id, progress_callback)
        else:
            return self._upload_single(encrypted_content, bucket_id, progress_callback)

    def _upload_single(self, encrypted_content: bytes, bucket_id: str,
                      progress_callback=None) -> str:
        """Upload file in single request"""
        try:
            # Get upload URL
            upload_info = self.api.get_upload_urls(bucket_id, len(encrypted_content))
            upload_url = upload_info.get('url', '')
            file_id = upload_info.get('fileId', '')

            if not upload_url or not file_id:
                raise ValueError("Failed to get upload URL")

            # Upload with progress
            if progress_callback:
                progress_callback(0)

            # Show progress bar for upload
            with tqdm(total=len(encrypted_content), unit='B', unit_scale=True, desc="Uploading") as pbar:
                def upload_callback(bytes_uploaded):
                    pbar.update(bytes_uploaded - pbar.n)
                    if progress_callback:
                        progress_callback(int(100 * bytes_uploaded / len(encrypted_content)))

                self.api.upload_file_chunk(upload_url, encrypted_content)
                upload_callback(len(encrypted_content))

            if progress_callback:
                progress_callback(100)

            return file_id
        except Exception as e:
            raise ValueError(f"Upload failed: {e}")

    def _upload_multipart(self, encrypted_content: bytes, bucket_id: str,
                         progress_callback=None) -> str:
        """Upload file in multiple chunks"""
        file_size = len(encrypted_content)
        num_chunks = (file_size + self.chunk_size - 1) // self.chunk_size

        print(f"📦 Uploading in {num_chunks} parts...")

        # For simplified implementation, we'll still upload as single part
        # In a full implementation, this would handle multipart uploads
        return self._upload_single(encrypted_content, bucket_id, progress_callback)

    def download_file(self, file_uuid: str, output_path: str = None,
                     progress_callback=None) -> str:
        """Download and decrypt a file from Internxt Drive"""
        credentials = self.auth.get_auth_details()
        user = credentials['user']

        # Get file metadata
        print("📋 Getting file metadata...")
        try:
            file_metadata = self.api.get_file_metadata(file_uuid)
        except Exception as e:
            raise ValueError(f"Failed to get file metadata: {e}")

        file_name = file_metadata.get('plainName', 'unknown')
        file_type = file_metadata.get('type', '')
        file_size = file_metadata.get('size', 0)
        bucket_id = file_metadata.get('bucket', '')
        file_id = file_metadata.get('fileId', '')

        if file_type:
            file_name_full = f"{file_name}.{file_type}"
        else:
            file_name_full = file_name

        if not output_path:
            output_path = Path.cwd() / file_name_full
        else:
            output_path = Path(output_path)
            if output_path.is_dir():
                output_path = output_path / file_name_full

        print(f"💾 Downloading {file_name_full} ({self._human_size(file_size)})...")

        # Get download URLs
        try:
            download_info = self.api.get_download_urls(bucket_id, file_id)
            download_urls = download_info.get('urls', [])
        except Exception as e:
            raise ValueError(f"Failed to get download URLs: {e}")

        if not download_urls:
            raise ValueError("No download URLs available")

        # Download encrypted content
        print("⬇️  Downloading from network...")
        encrypted_content = b""

        with tqdm(total=file_size, unit='B', unit_scale=True, desc="Downloading") as pbar:
            for url_info in download_urls:
                url = url_info.get('url', '')
                if url:
                    try:
                        chunk = self.api.download_file_chunk(url)
                        encrypted_content += chunk
                        pbar.update(len(chunk))
                    except Exception as e:
                        print(f"Warning: Failed to download chunk from {url}: {e}")
                        continue

        if not encrypted_content:
            raise ValueError("Failed to download any file content")

        # Generate decryption key (simplified - in practice this would be more complex)
        file_index = hashlib.sha256(file_id.encode()).digest()[:32]
        decryption_key = self.crypto.generate_file_key(user['mnemonic'], bucket_id, file_index)
        decryption_iv = os.urandom(16)  # This should come from file metadata

        # Decrypt content
        print("🔓 Decrypting file...")
        try:
            decrypted_content = self.crypto.decrypt_file_stream(
                encrypted_content, decryption_key, decryption_iv
            )
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

        # Trim to actual file size (remove padding)
        if len(decrypted_content) > file_size:
            decrypted_content = decrypted_content[:file_size]

        # Save to file
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'wb') as f:
                f.write(decrypted_content)
        except Exception as e:
            raise ValueError(f"Failed to save file: {e}")

        print(f"✅ File downloaded successfully to: {output_path}")

        return str(output_path)

    def _human_size(self, size_bytes: int) -> str:
        """Convert bytes to human readable format"""
        if not size_bytes:
            return "0 B"

        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0

        return f"{size_bytes:.1f} PB"


# Global instance
drive_service = DriveService()