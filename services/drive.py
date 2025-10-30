#!/usr/bin/env python3
"""
internxt_cli/services/drive.py
with path resolution
"""

import os
import sys
import hashlib
import fnmatch
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from tqdm import tqdm
import time

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
    Extended Drive operations with path resolution and trash operations
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
        """Creates Basic Auth for Network API"""
        bridge_user = user_creds.get('bridgeUser')
        user_id = user_creds.get('userId')
        if not bridge_user or not user_id:
            raise ValueError("Missing network credentials")
        
        hashed_password = hashlib.sha256(str(user_id).encode()).hexdigest()
        return (bridge_user, hashed_password)

    # ========== PATH RESOLUTION ==========

    def resolve_path(self, path: str) -> Dict[str, Any]:
        """
        Resolve a path to UUID and metadata
        Returns: {'type': 'file'/'folder', 'uuid': str, 'metadata': dict, 'path': str}
        """
        credentials = self.auth.get_auth_details()
        root_folder_uuid = credentials['user'].get('rootFolderId', '')
        
        path = path.strip()
        if path.startswith('/'):
            path = path[1:]
        
        if not path:
            return {
                'type': 'folder', 'uuid': root_folder_uuid,
                'metadata': {'uuid': root_folder_uuid, 'plainName': 'Root'},
                'path': '/'
            }
        
        path_parts = [part for part in path.split('/') if part]
        current_folder_uuid = root_folder_uuid
        resolved_path_parts = []
        
        for i, part in enumerate(path_parts):
            is_last_part = (i == len(path_parts) - 1)
            folder_content = self.get_folder_content(current_folder_uuid)
            
            # Look for folder
            found_folder = None
            for folder in folder_content['folders']:
                if folder.get('plainName') == part or folder.get('name') == part:
                    found_folder = folder
                    break
            
            # Look for file (only if last part)
            found_file = None
            if is_last_part:
                for file in folder_content['files']:
                    file_name = file.get('plainName', '')
                    file_type = file.get('type', '')
                    full_name = f"{file_name}.{file_type}" if file_type else file_name
                    
                    if (file_name == part or full_name == part or file.get('name') == part):
                        found_file = file
                        break
            
            if found_folder and (not is_last_part or not found_file):
                resolved_path_parts.append(found_folder.get('plainName', part))
                current_folder_uuid = found_folder['uuid']
                
                if is_last_part:
                    return {
                        'type': 'folder', 'uuid': found_folder['uuid'],
                        'metadata': found_folder, 'path': '/' + '/'.join(resolved_path_parts)
                    }
                    
            elif found_file and is_last_part:
                file_name = found_file.get('plainName', '')
                file_type = found_file.get('type', '')
                full_name = f"{file_name}.{file_type}" if file_type else file_name
                resolved_path_parts.append(full_name)
                
                return {
                    'type': 'file', 'uuid': found_file['uuid'],
                    'metadata': found_file, 'path': '/' + '/'.join(resolved_path_parts)
                }
            else:
                current_path = '/' + '/'.join(resolved_path_parts + [part])
                raise FileNotFoundError(f"Path not found: {current_path}")
        
        return {
            'type': 'folder', 'uuid': current_folder_uuid,
            'metadata': {'uuid': current_folder_uuid, 'plainName': path_parts[-1] if path_parts else 'Root'},
            'path': '/' + '/'.join(resolved_path_parts)
        }

    def download_file_by_path(self, file_path: str, destination_path_str: str = None):
        """Download file by path instead of UUID"""
        print(f"🔍 Resolving path: {file_path}")
        
        resolved = self.resolve_path(file_path)
        if resolved['type'] != 'file':
            raise ValueError(f"Path '{file_path}' is a folder, not a file")
        
        file_uuid = resolved['uuid']
        print(f"📋 Resolved to file UUID: {file_uuid}")
        
        if not destination_path_str:
            filename = Path(resolved['path']).name
            destination_path_str = f"./{filename}"
        
        return self.download_file(file_uuid, destination_path_str)

    def list_folder_with_paths(self, folder_path: str = "/") -> Dict[str, List[Dict[str, Any]]]:
        """List folder contents with full paths"""
        print(f"📁 Listing folder: {folder_path}")
        
        if folder_path == "" or folder_path == "/":
            resolved = self.resolve_path("/")
        else:
            resolved = self.resolve_path(folder_path)
        
        if resolved['type'] != 'folder':
            raise ValueError(f"Path '{folder_path}' is a file, not a folder")
        
        folder_uuid = resolved['uuid']
        base_path = resolved['path']
        content = self.get_folder_content(folder_uuid)
        
        # Enhance with path info
        enhanced_folders = []
        for folder in content['folders']:
            folder_name = folder.get('plainName', folder.get('name', 'Unknown'))
            full_path = f"{base_path.rstrip('/')}/{folder_name}"
            
            enhanced_folders.append({
                **folder,
                'path': full_path,
                'display_name': folder_name,
                'size_display': '<DIR>',
                'modified': folder.get('modificationTime') or folder.get('updatedAt', ''),
            })
        
        enhanced_files = []
        for file in content['files']:
            file_name = file.get('plainName', '')
            file_type = file.get('type', '')
            display_name = f"{file_name}.{file_type}" if file_type else file_name
            full_path = f"{base_path.rstrip('/')}/{display_name}"
            
            # FIXED: Convert size string from API to integer before formatting
            try:
                size_bytes = int(file.get('size', 0))
            except (ValueError, TypeError):
                size_bytes = 0
            size_display = self._format_size(size_bytes)
            
            enhanced_files.append({
                **file,
                'path': full_path,
                'display_name': display_name,
                'size_display': size_display,
                'modified': file.get('modificationTime') or file.get('updatedAt', ''),
            })
        
        return {
            'folders': enhanced_folders,
            'files': enhanced_files,
            'current_path': base_path
        }

    def find_files(self, search_term: str, folder_path: str = "/") -> List[Dict[str, Any]]:
        """Search for files by name with wildcards"""
        print(f"🔍 Searching for '{search_term}' in {folder_path}")
        
        results = []
        
        def search_recursive(current_path: str):
            try:
                content = self.list_folder_with_paths(current_path)
                
                # Check files in current folder
                for file in content['files']:
                    if fnmatch.fnmatch(file['display_name'].lower(), search_term.lower()):
                        results.append({**file, 'found_in': current_path})
                
                # Search subfolders recursively
                for folder in content['folders']:
                    search_recursive(folder['path'])
                    
            except Exception as e:
                print(f"   ⚠️  Could not search in {current_path}: {e}")
        
        search_recursive(folder_path)
        print(f"📍 Found {len(results)} matching files")
        return results

    # ========== TRASH OPERATIONS ==========

    def trash_file(self, file_uuid: str) -> Dict[str, Any]:
        """Move file to trash"""
        try:
            response = self.api.trash_file(file_uuid)  # Uses corrected bulk API
            return {'success': True, 'message': 'File moved to trash successfully', 'file': {'uuid': file_uuid}, 'result': response}
        except Exception as e:
            raise Exception(f"Failed to trash file: {e}")

    def trash_folder(self, folder_uuid: str) -> Dict[str, Any]:
        """Move folder to trash"""
        try:
            response = self.api.trash_folder(folder_uuid)  # Uses corrected bulk API
            return {'success': True, 'message': 'Folder moved to trash successfully', 'folder': {'uuid': folder_uuid}, 'result': response}
        except Exception as e:
            raise Exception(f"Failed to trash folder: {e}")

    def trash_by_path(self, path: str) -> Dict[str, Any]:
        """Move file or folder to trash by path"""
        print(f"🗑️  Moving to trash: {path}")
        
        resolved = self.resolve_path(path)
        
        if resolved['type'] == 'file':
            return self.trash_file(resolved['uuid'])
        else:
            return self.trash_folder(resolved['uuid'])

    def delete_permanently_file(self, file_uuid: str) -> Dict[str, Any]:
        """Permanently delete file - matches DeletePermanentlyFile command"""
        try:
            response = self.api.delete_file(file_uuid)
            return {'success': True, 'message': 'File permanently deleted successfully'}
        except Exception as e:
            raise Exception(f"Failed to permanently delete file: {e}")

    def delete_permanently_folder(self, folder_uuid: str) -> Dict[str, Any]:
        """Permanently delete folder - matches DeletePermanentlyFolder command"""
        try:
            response = self.api.delete_folder(folder_uuid)
            return {'success': True, 'message': 'Folder permanently deleted successfully'}
        except Exception as e:
            raise Exception(f"Failed to permanently delete folder: {e}")

    def delete_permanently_by_path(self, path: str) -> Dict[str, Any]:
        """Permanently delete file or folder by path"""
        print(f"🗑️  Permanently deleting: {path}")
        
        resolved = self.resolve_path(path)
        
        if resolved['type'] == 'file':
            return self.delete_permanently_file(resolved['uuid'])
        else:
            return self.delete_permanently_folder(resolved['uuid'])

    # ========== MOVE AND RENAME OPERATIONS ==========

    def move_file(self, file_uuid: str, destination_folder_uuid: str) -> Dict[str, Any]:
        """Move file to different folder"""
        try:
            response = self.api.move_file(file_uuid, destination_folder_uuid)
            return {'success': True, 'message': f'File moved successfully to: {destination_folder_uuid}', 'result': response}
        except Exception as e:
            raise Exception(f"Failed to move file: {e}")

    def move_folder(self, folder_uuid: str, destination_folder_uuid: str) -> Dict[str, Any]:
        """Move folder to different folder"""
        try:
            response = self.api.move_folder(folder_uuid, destination_folder_uuid)
            return {'success': True, 'message': f'Folder moved successfully to: {destination_folder_uuid}', 'result': response}
        except Exception as e:
            raise Exception(f"Failed to move folder: {e}")

    def rename_file(self, file_uuid: str, new_name: str) -> Dict[str, Any]:
        """Rename file"""
        try:
            # Parse name and extension
            if '.' in new_name:
                name_parts = new_name.rsplit('.', 1)
                plain_name = name_parts[0]
                file_type = name_parts[1]
            else:
                plain_name = new_name
                file_type = None
                
            response = self.api.rename_file(file_uuid, plain_name, file_type)
            return {'success': True, 'message': f'File renamed successfully to: {new_name}', 'result': response}
        except Exception as e:
            raise Exception(f"Failed to rename file: {e}")

    def rename_folder(self, folder_uuid: str, new_name: str) -> Dict[str, Any]:
        """Rename folder"""
        try:
            response = self.api.rename_folder(folder_uuid, new_name)
            return {'success': True, 'message': f'Folder renamed successfully to: {new_name}', 'result': response}
        except Exception as e:
            raise Exception(f"Failed to rename folder: {e}")
        
    def move_item(self, item_uuid: str, destination_folder_uuid: str) -> Dict[str, Any]:
        """Move file or folder to different folder (WebDAV required)"""
        try:
            # Try as file first
            try:
                return self.move_file(item_uuid, destination_folder_uuid)
            except:
                # If file move fails, try as folder
                return self.move_folder(item_uuid, destination_folder_uuid)
        except Exception as e:
            raise Exception(f"Failed to move item {item_uuid}: {e}")

    def rename_item(self, item_uuid: str, new_name: str) -> Dict[str, Any]:
        """Rename file or folder (WebDAV required)"""
        try:
            # Try as file first
            try:
                return self.rename_file(item_uuid, new_name)
            except:
                # If file rename fails, try as folder
                return self.rename_folder(item_uuid, new_name)
        except Exception as e:
            raise Exception(f"Failed to rename item {item_uuid}: {e}")

    def trash_item(self, item_uuid: str) -> Dict[str, Any]:
        """Move file or folder to trash (WebDAV required)"""
        try:
            # Use the corrected API trash methods
            try:
                return self.api.trash_file(item_uuid)
            except:
                return self.api.trash_folder(item_uuid)
        except Exception as e:
            raise Exception(f"Failed to trash item {item_uuid}: {e}")

    def update_file(self, file_uuid: str, local_path: str) -> Dict[str, Any]:
        """Update existing file with new content (WebDAV required for PUT operations)"""
        try:
            # Get current file metadata
            current_metadata = self.api.get_file_metadata(file_uuid)
            folder_uuid = current_metadata.get('folderUuid', '')
            plain_name = current_metadata.get('plainName', '')
            file_type = current_metadata.get('type', '')
            
            # Upload new content and get new file ID
            file_path = Path(local_path)
            file_size = file_path.stat().st_size
            
            # Get credentials and upload new version
            credentials = self.auth.get_auth_details()
            user = credentials['user']
            bucket_id = user['bucket']
            mnemonic = user['mnemonic']
            network_auth = self._get_network_auth(user)
            
            with open(file_path, 'rb') as f:
                plaintext = f.read()
            
            # Encrypt and upload
            encrypted_data, file_index_hex = self.crypto.encrypt_stream_internxt_protocol(plaintext, mnemonic, bucket_id)
            start_response = self.api.start_upload(bucket_id, len(encrypted_data), auth=network_auth)
            upload_details = start_response['uploads'][0]
            upload_url = upload_details['url']
            file_network_uuid = upload_details['uuid']
            
            self.api.upload_chunk(upload_url, encrypted_data)
            
            encrypted_hash = hashlib.sha256(encrypted_data).hexdigest()
            finish_payload = {
                'index': file_index_hex,
                'shards': [{'hash': encrypted_hash, 'uuid': file_network_uuid}]
            }
            finish_response = self.api.finish_upload(bucket_id, finish_payload, auth=network_auth)
            network_file_id = finish_response['id']
            
            # Replace file content using corrected API
            replace_payload = {
                'fileId': network_file_id,
                'size': file_size
            }
            result = self.api.replace_file(file_uuid, replace_payload)
            
            return {
                'success': True,
                'message': f'File {plain_name} updated successfully',
                'result': result
            }
            
        except Exception as e:
            raise Exception(f"Failed to update file {file_uuid}: {e}")
        
    def check_file_exists(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Check if a file exists at the given path without throwing an exception.
        Returns file info if exists, None otherwise.
        """
        try:
            resolved = self.resolve_path(path)
            return resolved if resolved['type'] == 'file' else None
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def check_folder_exists(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Check if a folder exists at the given path without throwing an exception.
        Returns folder info if exists, None otherwise.
        """
        try:
            resolved = self.resolve_path(path)
            return resolved if resolved['type'] == 'folder' else None
        except FileNotFoundError:
            return None
        except Exception:
            return None

    def copy_item(self, item_uuid: str, destination_folder_uuid: str) -> Dict[str, Any]:
        """Copy file to different folder preserving timestamps"""
        try:
            # Get file metadata
            metadata = self.api.get_file_metadata(item_uuid)
            
            # Extract timestamps - try both field name variations
            creation_time = metadata.get('creationTime') or metadata.get('createdAt')
            modification_time = metadata.get('modificationTime') or metadata.get('updatedAt')
            
            # Download file to temporary location
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_path = temp_file.name
            
            try:
                self.download_file(item_uuid, temp_path)
                
                # Upload to new location WITH timestamps
                plain_name = metadata.get('plainName', '')
                file_type = metadata.get('type', '')
                
                print(f"     📋 Copying with timestamp preservation:")
                if creation_time:
                    print(f"        Original creation: {creation_time}")
                if modification_time:
                    print(f"        Original modification: {modification_time}")
                
                # Create new file with upload_file_to_folder, passing timestamps
                result = self.upload_file_to_folder(
                    temp_path, 
                    destination_folder_uuid, 
                    plain_name, 
                    file_type,
                    creation_time=creation_time,
                    modification_time=modification_time
                )
                
                return {
                    'success': True,
                    'message': f'File {plain_name} copied successfully',
                    'result': result,
                    'timestamps_preserved': bool(creation_time or modification_time)
                }
                
            finally:
                # Clean up temp file
                try:
                    os.unlink(temp_path)
                except:
                    pass
                    
        except Exception as e:
            raise Exception(f"Copy failed: {e}")
        
    def create_upload_checkpoint(self, file_path: Path, target_uuid: str) -> str:
        """
        Create a checkpoint file for resumable uploads.
        Returns checkpoint file path.
        """
        checkpoint_dir = self.config.internxt_cli_data_dir / 'upload_checkpoints'
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        import hashlib
        # Create unique checkpoint ID based on file path and target
        checkpoint_id = hashlib.md5(f"{file_path}{target_uuid}".encode()).hexdigest()
        checkpoint_file = checkpoint_dir / f"{checkpoint_id}.json"
        
        checkpoint_data = {
            'file_path': str(file_path),
            'target_uuid': target_uuid,
            'file_size': file_path.stat().st_size,
            'timestamp': time.time(),
            'status': 'started'
        }
        
        import json
        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint_data, f)
        
        return str(checkpoint_file)

    def remove_upload_checkpoint(self, checkpoint_file: str):
        """Remove upload checkpoint after successful upload."""
        try:
            Path(checkpoint_file).unlink()
        except Exception:
            pass
        
    def sanitize_filename(self, filename: str) -> str:
        """
        Sanitize filename for upload, removing or replacing problematic characters.
        """
        # Remove or replace characters that might cause issues
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Remove leading/trailing spaces and dots
        filename = filename.strip(' .')
        
        # Ensure filename is not empty
        if not filename:
            filename = 'unnamed_file'
        
        return filename

    def upload_file_to_folder(self, file_path_str: str, destination_folder_uuid: str, 
                            custom_name: str = None, custom_extension: str = None,
                            creation_time: str = None, modification_time: str = None):
        """Upload file with custom name/extension and optional timestamps to specific folder"""
        credentials = self.auth.get_auth_details()
        user = credentials['user']
        bucket_id = user['bucket']
        mnemonic = user['mnemonic']
        network_auth = self._get_network_auth(user)

        file_path = Path(file_path_str)
        if not file_path.is_file():
            raise FileNotFoundError(f"File not found at: {file_path}")

        file_size = file_path.stat().st_size
        if file_size > self.TWENTY_GIGABYTES:
            raise ValueError(f"File is too large (must be less than {self._format_size(self.TWENTY_GIGABYTES)})")
        
        # Use custom name/extension if provided
        file_name = custom_name or file_path.stem
        file_extension = custom_extension if custom_extension is not None else file_path.suffix.lstrip('.')
        
        display_name = f"{file_name}.{file_extension}" if file_extension else file_name
        print(f"     📤 Uploading '{display_name}' ({self._format_size(file_size)})...")
        
        # Log timestamp preservation attempt
        if creation_time or modification_time:
            print(f"     🕐 Attempting to preserve timestamps:")
            if creation_time:
                print(f"        Creation: {creation_time}")
            if modification_time:
                print(f"        Modification: {modification_time}")
        
        try:
            with open(file_path, 'rb') as f:
                plaintext = f.read()
        except Exception as e:
            raise IOError(f"Failed to read file {file_path}: {e}")
        
        with tqdm(total=5, desc="     Uploading", unit="step", 
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]', 
                leave=False) as pbar:
            
            try:
                pbar.set_description("     🔐 Encrypting")
                encrypted_data, file_index_hex = self.crypto.encrypt_stream_internxt_protocol(
                    plaintext, mnemonic, bucket_id
                )
                pbar.update(1)

                pbar.set_description("     🚀 Initializing")
                start_response = self.api.start_upload(bucket_id, len(encrypted_data), auth=network_auth)
                upload_details = start_response['uploads'][0]
                upload_url = upload_details['url']
                file_network_uuid = upload_details['uuid']
                pbar.update(1)

                pbar.set_description("     ☁️  Uploading")
                self.api.upload_chunk(upload_url, encrypted_data)
                pbar.update(1)

                pbar.set_description("     ✅ Finalizing")
                encrypted_hash = hashlib.sha256(encrypted_data).hexdigest()
                
                finish_payload = {
                    'index': file_index_hex,
                    'shards': [{'hash': encrypted_hash, 'uuid': file_network_uuid}]
                }
                finish_response = self.api.finish_upload(bucket_id, finish_payload, auth=network_auth)
                network_file_id = finish_response['id']
                pbar.update(1)

                pbar.set_description("     📋 Creating entry")
                file_entry_payload = {
                    'folderUuid': destination_folder_uuid,
                    'plainName': file_name,
                    'type': file_extension if file_extension else '',
                    'size': file_size,
                    'bucket': bucket_id,
                    'fileId': network_file_id,
                    'encryptVersion': 'Aes03',
                    'name': ''
                }
                
                # Add timestamps using SDK-compatible field names
                if creation_time:
                    file_entry_payload['creationTime'] = creation_time
                    print(f"     🕐 Added creationTime to payload")
                if modification_time:
                    file_entry_payload['modificationTime'] = modification_time
                    print(f"     🕐 Added modificationTime to payload")
                
                created_file = self.api.create_file_entry(file_entry_payload)
                pbar.update(1)
                
                # Verify if timestamps were actually set
                if creation_time or modification_time:
                    returned_creation = created_file.get('creationTime') or created_file.get('createdAt')
                    returned_modification = created_file.get('modificationTime') or created_file.get('updatedAt')
                    
                    if creation_time and returned_creation:
                        print(f"     ✅ Creation timestamp preserved: {returned_creation}")
                    elif creation_time:
                        print(f"     ⚠️  Creation timestamp NOT set (API returned: {returned_creation})")
                    
                    if modification_time and returned_modification:
                        print(f"     ✅ Modification timestamp preserved: {returned_modification}")
                    elif modification_time:
                        print(f"     ⚠️  Modification timestamp NOT set (API returned: {returned_modification})")
            
            except Exception as e:
                pbar.close()
                raise Exception(f"Upload failed: {e}")
        
        return created_file

    # ========== CORE OPERATIONS ==========

    def get_folder_content(self, folder_uuid: str) -> Dict[str, List[Dict[str, Any]]]:
        """Get folder contents"""
        try:
            credentials = self.auth.get_auth_details()
            folders = self._get_all_folders(folder_uuid)
            files = self._get_all_files(folder_uuid)
            return {'folders': folders, 'files': files}
        except Exception as e:
            print(f"Error getting folder content: {e}")
            return {'folders': [], 'files': []}

    def list_folder(self, folder_uuid: str = None) -> Dict[str, List[Dict[str, Any]]]:
        """List folder contents - backward compatibility"""
        credentials = self.auth.get_auth_details()

        if not folder_uuid:
            folder_uuid = credentials['user'].get('rootFolderId', '')
            if not folder_uuid:
                raise ValueError("No root folder ID found")

        return self.get_folder_content(folder_uuid)

    def _get_all_folders(self, folder_uuid: str, offset: int = 0) -> List[Dict[str, Any]]:
        """Recursively get all folders with pagination"""
        try:
            response = self.api.get_folder_folders(folder_uuid, offset, 50)
            folders = response.get('result', response.get('folders', []))

            if len(folders) == 50:
                folders.extend(self._get_all_folders(folder_uuid, offset + 50))

            return folders
        except Exception as e:
            print(f"Warning: Failed to get folders: {e}")
            return []

    def _get_all_files(self, folder_uuid: str, offset: int = 0) -> List[Dict[str, Any]]:
        """Recursively get all files with pagination"""
        try:
            response = self.api.get_folder_files(folder_uuid, offset, 50)
            files = response.get('result', response.get('files', []))

            if len(files) == 50:
                files.extend(self._get_all_files(folder_uuid, offset + 50))

            return files
        except Exception as e:
            print(f"Warning: Failed to get files: {e}")
            return []

    def create_folder(self, name: str, parent_folder_uuid: str = None,
                      creation_time: str = None, modification_time: str = None) -> Dict[str, Any]:
        """Create new folder with optional timestamps"""
        credentials = self.auth.get_auth_details()

        if not parent_folder_uuid:
            parent_folder_uuid = credentials['user'].get('rootFolderId', '')
            if not parent_folder_uuid:
                raise ValueError("No root folder ID found")
        
        # Build payload for the new api.create_folder
        payload = {
            'plainName': name,
            'parentFolderUuid': parent_folder_uuid
        }

        if creation_time:
            payload['creationTime'] = creation_time
            print(f"     🕐 Adding folder creationTime: {creation_time}")
        if modification_time:
            payload['modificationTime'] = modification_time
            print(f"     🕐 Adding folder modificationTime: {modification_time}")

        # This now calls the modified api.create_folder(payload)
        return self.api.create_folder(payload)

    def create_folder_recursive(self, path: str,
                              creation_time: str = None, modification_time: str = None) -> Dict[str, Any]:
        """
        Ensures a folder path exists, creating intermediate folders if necessary.
        Sets timestamps *only* if the folder is being created new.
        Returns the metadata of the final folder.
        """
        credentials = self.auth.get_auth_details()
        root_folder_uuid = credentials['user'].get('rootFolderId', '')

        path = path.strip().strip('/')
        if not path:
             return {'uuid': root_folder_uuid, 'plainName': 'Root'}

        parts = [part for part in path.split('/') if part] # Clean empty parts
        current_parent_uuid = root_folder_uuid
        current_path_so_far = "/"
        final_folder_info = None

        for i, part in enumerate(parts):
            is_last_part = (i == len(parts) - 1)
            found_folder = None
            
            try:
                # 1. Check if the folder already exists
                content = self.get_folder_content(current_parent_uuid)
                for folder in content['folders']:
                    if folder.get('plainName') == part or folder.get('name') == part:
                        found_folder = folder
                        break

                if found_folder:
                    # 2. FOLDER EXISTS: We cannot update its timestamp.
                    # Just use its info and move to the next part.
                    current_parent_uuid = found_folder['uuid']
                    final_folder_info = found_folder
                    
                    if is_last_part and (creation_time or modification_time):
                        print(f"  -> ℹ️  Note: Folder '{part}' already exists. Cannot update timestamps (API limitation).")
                
                else:
                    # 3. FOLDER DOES NOT EXIST: Create it new.
                    try:
                        print(f"  -> Creating new folder: {part} in {current_path_so_far}")
                        
                        # We only pass timestamps if this is the *final* folder
                        if is_last_part:
                            print(f"  -> 🕐 Applying timestamps to new folder: {part}")
                            new_folder = self.create_folder(
                                part, 
                                current_parent_uuid,
                                creation_time=creation_time,
                                modification_time=modification_time
                            )
                        else:
                            # Create intermediate folders *without* timestamps
                            new_folder = self.api.create_folder({
                                'plainName': part, 
                                'parentFolderUuid': current_parent_uuid
                            })
                        
                        current_parent_uuid = new_folder['uuid']
                        final_folder_info = new_folder
                    
                    except Exception as e:
                        # Handle the race condition we saw before
                        if "already exists" in str(e):
                            print(f"  -> ℹ️  Folder '{part}' already exists (consistency). Resolving...")
                            try:
                                existing_folder_path = f"{current_path_so_far.rstrip('/')}/{part}"
                                resolved = self.resolve_path(existing_folder_path)
                                current_parent_uuid = resolved['uuid']
                                final_folder_info = resolved['metadata']
                            except Exception as e2:
                                raise Exception(f"Failed to create folder '{part}' and could not resolve it after: {e2}")
                        else:
                            raise e # Re-raise other errors

                current_path_so_far = f"{current_path_so_far.rstrip('/')}/{part}"
                
                # If this is the last part, return the info we found or created
                if is_last_part:
                    return final_folder_info

            except Exception as e:
                 raise Exception(f"Failed to resolve or create folder part '{part}' in '{current_path_so_far}': {e}")

        return {'uuid': root_folder_uuid, 'plainName': 'Root'}

    def create_folder_recursive(self, path: str,
                              creation_time: str = None, modification_time: str = None) -> Dict[str, Any]:
        """
        Ensures a folder path exists, creating intermediate folders if necessary.
        Sets timestamps *only* if the folder is being created new.
        Returns the metadata of the final folder.
        """
        credentials = self.auth.get_auth_details()
        root_folder_uuid = credentials['user'].get('rootFolderId', '')

        path = path.strip().strip('/')
        if not path:
             return {'uuid': root_folder_uuid, 'plainName': 'Root'}

        parts = [part for part in path.split('/') if part] # Clean empty parts
        current_parent_uuid = root_folder_uuid
        current_path_so_far = "/"
        final_folder_info = None

        for i, part in enumerate(parts):
            is_last_part = (i == len(parts) - 1)
            found_folder = None
            
            try:
                # 1. Check if the folder already exists
                content = self.get_folder_content(current_parent_uuid)
                for folder in content['folders']:
                    if folder.get('plainName') == part or folder.get('name') == part:
                        found_folder = folder
                        break

                if found_folder:
                    # 2. FOLDER EXISTS: We cannot update its timestamp.
                    # Just use its info and move to the next part.
                    current_parent_uuid = found_folder['uuid']
                    final_folder_info = found_folder
                    
                    if is_last_part and (creation_time or modification_time):
                        print(f"  -> ℹ️  Note: Folder '{part}' already exists. Cannot update timestamps (API limitation).")
                
                else:
                    # 3. FOLDER DOES NOT EXIST: Create it new.
                    try:
                        print(f"  -> Creating new folder: {part} in {current_path_so_far}")
                        
                        # We only pass timestamps if this is the *final* folder
                        if is_last_part:
                            print(f"  -> 🕐 Applying timestamps to new folder: {part}")
                            new_folder = self.create_folder(
                                part, 
                                current_parent_uuid,
                                creation_time=creation_time,
                                modification_time=modification_time
                            )
                        else:
                            # Create intermediate folders *without* timestamps
                            new_folder = self.api.create_folder({
                                'plainName': part, 
                                'parentFolderUuid': current_parent_uuid
                            })
                        
                        current_parent_uuid = new_folder['uuid']
                        final_folder_info = new_folder
                    
                    except Exception as e:
                        # Handle the race condition we saw before
                        if "already exists" in str(e):
                            print(f"  -> ℹ️  Folder '{part}' already exists (consistency). Resolving...")
                            try:
                                existing_folder_path = f"{current_path_so_far.rstrip('/')}/{part}"
                                resolved = self.resolve_path(existing_folder_path)
                                current_parent_uuid = resolved['uuid']
                                final_folder_info = resolved['metadata']
                            except Exception as e2:
                                raise Exception(f"Failed to create folder '{part}' and could not resolve it after: {e2}")
                        else:
                            raise e # Re-raise other errors

                current_path_so_far = f"{current_path_so_far.rstrip('/')}/{part}"
                
                # If this is the last part, return the info we found or created
                if is_last_part:
                    return final_folder_info

            except Exception as e:
                 raise Exception(f"Failed to resolve or create folder part '{part}' in '{current_path_so_far}': {e}")

        return {'uuid': root_folder_uuid, 'plainName': 'Root'}
    
    def validate_upload_sources(self, sources: List[str], recursive: bool = False) -> Tuple[List[Path], List[str]]:
        """
        Validate upload sources and return valid files and error messages.
        
        Returns: (valid_paths, error_messages)
        """
        valid_paths = []
        errors = []
        
        for source in sources:
            source_path = Path(source)
            
            # Check if source exists
            if not source_path.exists():
                errors.append(f"Source not found: {source}")
                continue
            
            # Check if readable
            if not os.access(source_path, os.R_OK):
                errors.append(f"Source not readable: {source}")
                continue
            
            # Check file size if it's a file
            if source_path.is_file():
                try:
                    size = source_path.stat().st_size
                    if size > self.TWENTY_GIGABYTES:
                        errors.append(f"File too large (>{self._format_size(self.TWENTY_GIGABYTES)}): {source}")
                        continue
                except Exception as e:
                    errors.append(f"Cannot read file {source}: {e}")
                    continue
            
            # Check if directory but recursive not enabled
            if source_path.is_dir() and not recursive:
                errors.append(f"Directory requires --recursive flag: {source}")
                continue
            
            valid_paths.append(source_path)
        
        return valid_paths, errors
    
    def get_upload_statistics(self, local_path: Path, recursive: bool = False) -> Dict[str, Any]:
        """
        Calculate statistics for an upload operation before starting.
        Useful for showing progress and estimating time.
        
        Returns: {
            'total_files': int,
            'total_size': int,
            'total_dirs': int,
            'file_list': List[Path]
        }
        """
        stats = {
            'total_files': 0,
            'total_size': 0,
            'total_dirs': 0,
            'file_list': []
        }
        
        if local_path.is_file():
            stats['total_files'] = 1
            stats['total_size'] = local_path.stat().st_size
            stats['file_list'] = [local_path]
        elif local_path.is_dir():
            if recursive:
                for item in local_path.rglob('*'):
                    if item.is_file():
                        try:
                            stats['total_files'] += 1
                            stats['total_size'] += item.stat().st_size
                            stats['file_list'].append(item)
                        except Exception:
                            pass  # Skip files we can't read
                    elif item.is_dir():
                        stats['total_dirs'] += 1
            else:
                # Just count direct children
                for item in local_path.iterdir():
                    if item.is_file():
                        try:
                            stats['total_files'] += 1
                            stats['total_size'] += item.stat().st_size
                            stats['file_list'].append(item)
                        except Exception:
                            pass
                    elif item.is_dir():
                        stats['total_dirs'] += 1
        
        return stats
    
    def should_include_file(self, file_path: Path, include_patterns: List[str], 
                            exclude_patterns: List[str]) -> bool:
        """Check if a file should be included based on include/exclude patterns"""
        import fnmatch
        file_name = file_path.name
        
        # If include patterns specified, file must match at least one
        if include_patterns:
            matches_include = any(fnmatch.fnmatch(file_name, pattern) for pattern in include_patterns)
            if not matches_include:
                return False
        
        # If exclude patterns specified, file must not match any
        if exclude_patterns:
            matches_exclude = any(fnmatch.fnmatch(file_name, pattern) for pattern in exclude_patterns)
            if matches_exclude:
                return False
        
        return True

    def upload_single_item_with_conflict_handling(
            self,
            local_path: Path,
            target_remote_parent_path_str: str,
            target_folder_uuid: str,
            on_conflict: str,
            remote_filename: Optional[str] = None,
            creation_time: Optional[str] = None,
            modification_time: Optional[str] = None
        ) -> str:
        """
        Uploads a single local file, handling conflicts based on the specified strategy.
        
        Args:
            local_path: Path object for the local file.
            target_remote_parent_path_str: The full intended remote path of the PARENT folder.
            target_folder_uuid: The UUID of the *immediate parent* remote folder to upload into.
            on_conflict: 'skip' or 'overwrite'.
            remote_filename: If specified, use this filename instead of local_path.name.
            creation_time: ISO format timestamp for file creation (optional).
            modification_time: ISO format timestamp for file modification (optional).

        Returns:
            "uploaded", "skipped", or "error"
        """
        if not local_path.is_file():
            print(f"  -> ⚠️  Not a file, skipping: {local_path}")
            return "skipped"

        # Validate file size before proceeding
        try:
            file_size = local_path.stat().st_size
            if file_size > self.TWENTY_GIGABYTES:
                print(f"  -> ❌ File too large (>{self._format_size(self.TWENTY_GIGABYTES)}): {local_path.name}")
                return "error"
            if file_size == 0:
                print(f"  -> ⚠️  File is empty, skipping: {local_path.name}")
                return "skipped"
        except Exception as e:
            print(f"  -> ❌ Cannot read file: {e}")
            return "error"

        effective_remote_filename = remote_filename or local_path.name
        
        # Construct the full path of the potential target FILE for existence check
        full_target_remote_path = f"{target_remote_parent_path_str.rstrip('/')}/{effective_remote_filename}"
        if full_target_remote_path.startswith('//'):
            full_target_remote_path = full_target_remote_path[1:]
        if not full_target_remote_path.startswith('/'):
            full_target_remote_path = '/' + full_target_remote_path

        print(f"  -> Preparing upload: '{local_path.name}' ({self._format_size(file_size)}) to '{full_target_remote_path}'")
        
        if creation_time or modification_time:
            print(f"  -> 🕐 With timestamp preservation")

        existing_item_info = None
        try:
            existing_item_info = self.resolve_path(full_target_remote_path)
            print(f"  -> Target exists: {full_target_remote_path} (Type: {existing_item_info['type']})")
        except FileNotFoundError:
            print(f"  -> Target does not exist, proceeding with upload")
            pass
        except Exception as e:
            print(f"  -> ⚠️  Error checking target existence: {e}")

        if existing_item_info:
            if on_conflict == 'skip':
                print(f"  -> ⏭️  Skipping due to conflict policy (file exists)")
                return "skipped"
            elif on_conflict == 'overwrite':
                if existing_item_info['type'] == 'folder':
                    print(f"  -> ❌ Cannot overwrite folder with a file: {full_target_remote_path}")
                    return "error"
                else:
                    print(f"  -> 🔄 Overwriting existing file...")
                    try:
                        self.delete_permanently_by_path(full_target_remote_path)
                        print(f"  -> 🗑️  Deleted existing file for overwrite")
                    except Exception as del_err:
                        print(f"  -> ❌ Error deleting existing file for overwrite: {del_err}")
                        return "error"
            else:
                print(f"  -> ❌ Invalid conflict mode '{on_conflict}'")
                return "error"

        # --- Proceed with upload ---
        try:
            file_stem = Path(effective_remote_filename).stem
            file_suffix = Path(effective_remote_filename).suffix.lstrip('.')
            
            if not file_suffix and '.' not in effective_remote_filename:
                file_suffix = ''
            elif not file_suffix and '.' in effective_remote_filename:
                file_stem = effective_remote_filename
                file_suffix = ''

            # Upload with timestamps
            self.upload_file_to_folder(
                str(local_path),
                target_folder_uuid,
                custom_name=file_stem,
                custom_extension=file_suffix if file_suffix else None,
                creation_time=creation_time,
                modification_time=modification_time
            )
            print(f"  -> ✅ Successfully uploaded: {effective_remote_filename}")
            return "uploaded"
        except Exception as up_err:
            print(f"  -> ❌ Error during upload: {up_err}")
            import traceback
            traceback.print_exc()
            return "error"

    def download_file(self, file_uuid: str, destination_path_str: str, 
                    preserve_timestamps: bool = False):
        """Download and decrypt file with optional timestamp preservation"""
        credentials = self.auth.get_auth_details()
        user = credentials['user']
        mnemonic = user['mnemonic']
        network_auth = self._get_network_auth(user)
        
        print(f"📥 Downloading file UUID: {file_uuid} ...")
        
        with tqdm(total=5, desc="Downloading", unit="step", 
                bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}]') as pbar:
            
            pbar.set_description("📋 Fetching file metadata")
            metadata = self.api.get_file_metadata(file_uuid)
            
            bucket_id = metadata['bucket']
            network_file_id = metadata['fileId']
            file_size = int(metadata['size'])
            file_name = metadata.get('plainName', 'downloaded_file')
            file_type = metadata.get('type')
            
            # Extract timestamps from metadata
            creation_time = metadata.get('creationTime') or metadata.get('createdAt')
            modification_time = metadata.get('modificationTime') or metadata.get('updatedAt')
            
            if file_type:
                file_name = f"{file_name}.{file_type}"
            
            print(f"     📄 File: {file_name}")
            print(f"     📊 Size: {self._format_size(file_size)}")
            if preserve_timestamps:
                print(f"     🕐 Remote timestamps:")
                if creation_time:
                    print(f"        Creation: {creation_time}")
                if modification_time:
                    print(f"        Modification: {modification_time}")
            
            pbar.update(1)
            
            pbar.set_description("🔗 Fetching download links")
            links_response = self.api.get_download_links(bucket_id, network_file_id, auth=network_auth)
            download_url = links_response['shards'][0]['url']
            file_index_hex = links_response['index']
            print(f"     🔗 Download URL acquired")
            pbar.update(1)
            
            pbar.set_description("☁️  Downloading encrypted data")
            encrypted_data = self.api.download_chunk(download_url)
            print(f"     ☁️  Downloaded {self._format_size(len(encrypted_data))} encrypted")
            pbar.update(1)
            
            pbar.set_description("🔐 Decrypting")
            decrypted_data = self.crypto.decrypt_stream_internxt_protocol(
                encrypted_data, mnemonic, bucket_id, file_index_hex
            )
            
            # Always trim to exact file size
            decrypted_data = decrypted_data[:file_size]
            print(f"     🔐 Decrypted {self._format_size(len(decrypted_data))}")
            pbar.update(1)
            
            destination_path = Path(destination_path_str)
            if destination_path.is_dir():
                destination_path = destination_path / file_name
            
            pbar.set_description(f"💾 Saving to disk")
            with open(destination_path, 'wb') as f:
                f.write(decrypted_data)
            print(f"     💾 Saved to: {destination_path}")
            pbar.update(1)
        
        # Set timestamps if requested
        if preserve_timestamps and (creation_time or modification_time):
            try:
                import os
                from datetime import datetime
                
                stat_info = destination_path.stat()
                
                # Parse timestamps
                if modification_time:
                    try:
                        # Try parsing ISO format
                        mtime = datetime.fromisoformat(modification_time.replace('Z', '+00:00'))
                        mtime_ts = mtime.timestamp()
                        
                        # Set access and modification times
                        os.utime(destination_path, (mtime_ts, mtime_ts))
                        print(f"     🕐 Set modification time: {modification_time}")
                    except Exception as e:
                        print(f"     ⚠️  Could not set modification time: {e}")
                
                # Note: Setting creation time is platform-specific and often not supported
                if creation_time:
                    print(f"     ℹ️  Note: Creation time cannot be set on most systems")
                    
            except Exception as e:
                print(f"     ⚠️  Could not preserve timestamps: {e}")
        
        print(f"✅ Success! File downloaded to '{destination_path}'")
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