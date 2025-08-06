#!/usr/bin/env python3
"""
internxt_cli/services/webdav_provider.py
"""

import os
import io
import time
import tempfile
import threading
from typing import Dict, Any, List, Optional, Iterator, Union
from pathlib import Path

try:
    from wsgidav.dav_provider import DAVProvider, DAVCollection, DAVNonCollection
    from wsgidav.dav_error import DAVError, HTTP_NOT_FOUND, HTTP_FORBIDDEN, HTTP_CONFLICT
    import mimetypes
except ImportError:
    print("❌ Missing WebDAV dependency. Install with: pip install WsgiDAV")
    raise


class WebDAVAPIClient:
    """Isolated API client for WebDAV context"""
    
    def __init__(self):
        self._credentials = None
        self._api_client = None
        self._thread_local = threading.local()
        
    def _get_isolated_session(self):
        """Get a thread-local API session"""
        if not hasattr(self._thread_local, 'api_client'):
            print("🔍 WEBDAV: Creating fresh API session for WebDAV thread")
            
            from services.auth import auth_service
            from utils.api import ApiClient
            
            self._credentials = auth_service.get_auth_details()
            
            fresh_api_client = ApiClient()
            fresh_api_client.set_auth_tokens(
                self._credentials.get('token'), 
                self._credentials.get('newToken')
            )
            
            self._thread_local.api_client = fresh_api_client
            print("✅ WEBDAV: Fresh API session created")
            
        return self._thread_local.api_client
    
    def get_folder_content(self, folder_uuid: str) -> Dict[str, Any]:
        """Get folder content using isolated API session"""
        try:
            print(f"🔍 WEBDAV: Getting content for folder {folder_uuid}")
            api_client = self._get_isolated_session()
            
            folders_response = api_client.get_folder_folders(folder_uuid, 0, 50)
            folders = folders_response.get('result', folders_response.get('folders', []))
            
            files_response = api_client.get_folder_files(folder_uuid, 0, 50)  
            files = files_response.get('result', files_response.get('files', []))
            
            print(f"✅ WEBDAV: Got {len(folders)} folders and {len(files)} files")
            return {'folders': folders, 'files': files}
            
        except Exception as e:
            print(f"❌ WEBDAV: Error getting folder content: {e}")
            return {'folders': [], 'files': []}
    
    def get_credentials(self) -> Dict[str, Any]:
        """Get cached credentials"""
        if not self._credentials:
            from services.auth import auth_service
            self._credentials = auth_service.get_auth_details()
        return self._credentials


# Global instance for WebDAV
webdav_api = WebDAVAPIClient()


class InternxtDAVResource(DAVNonCollection):
    """Represents a file in Internxt Drive for WebDAV access"""
    
    def __init__(self, path: str, environ: dict, file_metadata: dict):
        super().__init__(path, environ)
        self.file_metadata = file_metadata
        self._temp_file_path = None
        
    def get_content_length(self) -> int:
        """Return file size"""
        return int(self.file_metadata.get('size', 0))
    
    def get_content_type(self) -> str:
        """Return MIME type based on file extension"""
        file_name = self.file_metadata.get('plainName', '')
        file_type = self.file_metadata.get('type', '')
        
        if file_type:
            full_name = f"{file_name}.{file_type}"
        else:
            full_name = file_name
            
        content_type, _ = mimetypes.guess_type(full_name)
        return content_type or 'application/octet-stream'
    
    def get_creation_date(self) -> float:
        """Return file creation time as timestamp"""
        try:
            created_at = self.file_metadata.get('createdAt', '')
            if created_at:
                from datetime import datetime
                dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                return dt.timestamp()
        except Exception:
            pass
        return time.time()
    
    def get_last_modified(self) -> float:
        """Return file modification time as timestamp"""
        try:
            updated_at = self.file_metadata.get('updatedAt', '')
            if updated_at:
                from datetime import datetime
                dt = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                return dt.timestamp()
        except Exception:
            pass
        return time.time()
    
    def get_etag(self) -> str:
        """Return ETag for the file resource - FIXED to avoid double quotes"""
        file_uuid = self.file_metadata.get('uuid', 'unknown')[:8]  # First 8 chars
        modified = int(self.get_last_modified())
        size = self.get_content_length()
        # Return WITHOUT quotes - WsgiDAV adds them automatically
        return f"{file_uuid}-{modified}-{size}"
    
    def support_etag(self) -> bool:
        """Support ETags for caching"""
        return True
    
    def support_ranges(self) -> bool:
        """Support byte ranges for resumable downloads"""
        return True
    
    def support_content_length(self) -> bool:
        """Support content length"""
        return True
    
    def support_modified(self) -> bool:
        """Support last modified date"""
        return True
    
    def get_content(self) -> Union[bytes, io.BytesIO]:
        """Return file content as a seekable file-like object"""
        try:
            # Get the file content from Internxt
            from services.drive import drive_service
            from services.auth import auth_service
            
            credentials = auth_service.get_auth_details()
            user = credentials['user']
            mnemonic = user['mnemonic']
            
            # Get file metadata
            file_uuid = self.file_metadata.get('uuid')
            if not file_uuid or file_uuid.startswith('pending-'):
                # This is a newly created file that hasn't been uploaded yet
                return io.BytesIO(b"")
                
            print(f"📥 WEBDAV: Downloading file {file_uuid} for streaming...")
            
            # Use the drive service to download
            api_client = webdav_api._get_isolated_session()
            network_auth = drive_service._get_network_auth(user)
            
            # Get download info
            metadata = api_client.get_file_metadata(file_uuid)
            bucket_id = metadata['bucket']
            network_file_id = metadata['fileId']
            file_size = int(metadata['size'])
            
            # Get download link
            links_response = api_client.get_download_links(bucket_id, network_file_id, auth=network_auth)
            download_url = links_response['shards'][0]['url']
            file_index_hex = links_response['index']
            
            # Download encrypted data
            encrypted_data = api_client.download_chunk(download_url)
            
            # Decrypt
            from services.crypto import crypto_service
            decrypted_data = crypto_service.decrypt_stream_internxt_protocol(
                encrypted_data, mnemonic, bucket_id, file_index_hex
            )
            
            # Trim to exact size if needed
            if len(decrypted_data) > file_size:
                decrypted_data = decrypted_data[:file_size]
            
            print(f"✅ WEBDAV: Downloaded {len(decrypted_data)} bytes, returning as BytesIO")
            
            # Return as a seekable BytesIO object
            return io.BytesIO(decrypted_data)
            
        except Exception as e:
            print(f"❌ WEBDAV: Error downloading file: {e}")
            import traceback
            traceback.print_exc()
            
            # Return error message as content
            error_msg = f"Error downloading file: {str(e)}\n"
            return io.BytesIO(error_msg.encode('utf-8'))
    
    def begin_write(self, content_type=None):
        """Called when starting to write content to the file"""
        print(f"🔍 WEBDAV: begin_write() for {self.path}")
        
        # Create a temporary file to store the upload
        import tempfile
        fd, self._temp_file_path = tempfile.mkstemp()
        os.close(fd)  # Close the file descriptor, we'll use the path
        
        # Return a file handle that WsgiDAV can write to
        return open(self._temp_file_path, 'wb')
    
    def end_write(self, with_errors: bool):
        """Called when writing is complete"""
        print(f"🔍 WEBDAV: end_write(with_errors={with_errors}) for {self.path}")
        
        if with_errors or not self._temp_file_path:
            print("❌ WEBDAV: Upload had errors or no temp file, aborting")
            self._cleanup_temp_file()
            return
        
        try:
            # Get file size
            file_size = os.path.getsize(self._temp_file_path)
            print(f"📤 WEBDAV: Uploading {file_size} bytes to Internxt...")
            
            from services.drive import drive_service
            from services.auth import auth_service
            
            # Get parent folder UUID
            path_parts = self.path.strip('/').split('/')
            if len(path_parts) == 1:
                # File in root
                credentials = auth_service.get_auth_details()
                parent_uuid = credentials['user'].get('rootFolderId', '')
            else:
                # File in subfolder
                parent_path = '/' + '/'.join(path_parts[:-1])
                resolved = drive_service.resolve_path(parent_path)
                parent_uuid = resolved['uuid']
            
            # Get file name
            file_name = path_parts[-1]
            
            # Parse name and extension
            if '.' in file_name:
                plain_name = file_name.rsplit('.', 1)[0]
                file_type = file_name.rsplit('.', 1)[1]
            else:
                plain_name = file_name
                file_type = ''
            
            # Check if we're updating an existing file
            if hasattr(self, 'file_metadata') and self.file_metadata.get('uuid') and not self.file_metadata.get('uuid', '').startswith('pending-'):
                # Update existing file
                file_uuid = self.file_metadata['uuid']
                print(f"📝 WEBDAV: Updating existing file {file_uuid}")
                result = drive_service.update_file(file_uuid, self._temp_file_path)
            else:
                # Create new file
                print(f"📝 WEBDAV: Creating new file {plain_name}.{file_type}")
                result = drive_service.upload_file_to_folder(self._temp_file_path, parent_uuid, plain_name, file_type)
            
            print(f"✅ WEBDAV: Upload successful!")
            
            # Update metadata
            if isinstance(result, dict):
                self.file_metadata.update(result)
            
            # Clear parent folder cache
            if hasattr(self, 'parent') and hasattr(self.parent, '_content_cache'):
                self.parent._content_cache = None
                
        except Exception as e:
            print(f"❌ WEBDAV: Upload failed: {e}")
            import traceback
            traceback.print_exc()
            raise DAVError(HTTP_FORBIDDEN, f"Upload failed: {e}")
        finally:
            self._cleanup_temp_file()
    
    def _cleanup_temp_file(self):
        """Clean up temporary file"""
        if self._temp_file_path and os.path.exists(self._temp_file_path):
            try:
                os.unlink(self._temp_file_path)
                self._temp_file_path = None
            except:
                pass


class InternxtDAVCollection(DAVCollection):
    """Represents a folder in Internxt Drive for WebDAV access"""
    
    def __init__(self, path: str, environ: dict, folder_metadata: dict = None):
        super().__init__(path, environ)
        self.folder_metadata = folder_metadata or {}
        self._content_cache = None
        self._content_cached_time = 0
        self.CACHE_TIMEOUT = 30
        
    def get_member_names(self) -> List[str]:
        """Return list of files and folders in this directory"""
        try:
            content = self._get_content()
            names = content.get('names', [])
            print(f"✅ WEBDAV: Returning {len(names)} member names: {names}")
            return names
        except Exception as e:
            print(f"❌ WEBDAV: Error getting member names for {self.path}: {e}")
            return []
    
    def get_member(self, name: str) -> Optional[Union[DAVCollection, DAVNonCollection]]:
        """Get a specific member (file or folder) by name"""
        try:
            print(f"🔍 WEBDAV: get_member({name}) for path: {self.path}")
            content = self._get_content()
            
            # Check if it's a folder
            for folder in content['folders']:
                folder_name = folder.get('plainName', folder.get('name', ''))
                if folder_name == name:
                    child_path = f"{self.path.rstrip('/')}/{name}" if self.path != '/' else f"/{name}"
                    print(f"✅ WEBDAV: Found folder: {name}")
                    return InternxtDAVCollection(child_path, self.environ, folder)
            
            # Check if it's a file
            for file in content['files']:
                file_name = file.get('plainName', '')
                file_type = file.get('type', '')
                display_name = f"{file_name}.{file_type}" if file_type else file_name
                
                if display_name == name:
                    child_path = f"{self.path.rstrip('/')}/{name}" if self.path != '/' else f"/{name}"
                    print(f"✅ WEBDAV: Found file: {name}")
                    return InternxtDAVResource(child_path, self.environ, file)
            
            print(f"❌ WEBDAV: Member '{name}' not found in {self.path}")
            return None
            
        except Exception as e:
            print(f"❌ WEBDAV: Error getting member {name}: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_creation_date(self) -> float:
        """Return folder creation time"""
        try:
            created_at = self.folder_metadata.get('createdAt', '')
            if created_at:
                from datetime import datetime
                dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                return dt.timestamp()
        except Exception:
            pass
        return time.time()
    
    def get_last_modified(self) -> float:
        """Return folder modification time"""
        try:
            updated_at = self.folder_metadata.get('updatedAt', '')
            if updated_at:
                from datetime import datetime
                dt = datetime.fromisoformat(updated_at.replace('Z', '+00:00'))
                return dt.timestamp()
        except Exception:
            pass
        return time.time()
    
    def get_etag(self) -> str:
        """Return ETag for the folder resource - FIXED to avoid double quotes"""
        folder_uuid = self.folder_metadata.get('uuid', 'root')
        if folder_uuid != 'root':
            folder_uuid = folder_uuid[:8]  # First 8 chars
        modified = int(self.get_last_modified())
        
        # Get member count safely
        try:
            member_count = len(self._get_content().get('names', []))
        except:
            member_count = 0
        
        # Return WITHOUT quotes - WsgiDAV adds them automatically
        return f"{folder_uuid}-{modified}-{member_count}"
    
    def support_etag(self) -> bool:
        """Support ETags for caching"""
        return True
    
    def support_ranges(self) -> bool:
        """Collections don't support ranges"""
        return False
    
    def support_content_length(self) -> bool:
        """Collections don't have content length"""
        return False
    
    def support_modified(self) -> bool:
        """Support last modified date"""
        return True
    
    def _get_content(self) -> Dict[str, Any]:
        """Get folder content with caching"""
        current_time = time.time()
        
        # Check cache
        if (self._content_cache is not None and 
            current_time - self._content_cached_time < self.CACHE_TIMEOUT):
            return self._content_cache
        
        try:
            print(f"🔍 WEBDAV: Fetching fresh content for: {self.path}")
            
            if self.path == '/' or self.path == '':
                # Root folder
                credentials = webdav_api.get_credentials()
                root_folder_uuid = credentials['user'].get('rootFolderId', '')
                
                if not root_folder_uuid:
                    print("❌ WEBDAV: No root folder UUID found")
                    return {'folders': [], 'files': [], 'names': []}
                
                content = webdav_api.get_folder_content(root_folder_uuid)
                
            else:
                # Non-root folder - use existing drive service
                print(f"🔍 WEBDAV: Non-root folder: {self.path}")
                from services.drive import drive_service
                content = drive_service.list_folder_with_paths(self.path)
            
            # Build names list
            names = []
            for folder in content.get('folders', []):
                folder_name = folder.get('plainName', folder.get('name', ''))
                if folder_name:
                    names.append(folder_name)
            
            for file in content.get('files', []):
                file_name = file.get('plainName', '')
                file_type = file.get('type', '')
                display_name = f"{file_name}.{file_type}" if file_type else file_name
                if display_name:
                    names.append(display_name)
            
            result = {
                'folders': content.get('folders', []),
                'files': content.get('files', []),
                'names': names
            }
            
            # Cache the result
            self._content_cache = result
            self._content_cached_time = current_time
            
            print(f"✅ WEBDAV: Cached content - {len(names)} total items")
            return result
            
        except Exception as e:
            print(f"❌ WEBDAV: Error getting content for {self.path}: {e}")
            import traceback
            traceback.print_exc()
            return {'folders': [], 'files': [], 'names': []}
        
    def create_empty_resource(self, name: str):
        """Create a new empty file resource"""
        print(f"🔍 WEBDAV: create_empty_resource({name}) in {self.path}")
        
        # Create a placeholder file resource that will receive content later
        file_metadata = {
            'plainName': name.rsplit('.', 1)[0] if '.' in name else name,
            'type': name.rsplit('.', 1)[1] if '.' in name else '',
            'size': 0,
            'uuid': f'pending-{name}',  # Temporary UUID
            'isUploading': True
        }
        
        child_path = f"{self.path.rstrip('/')}/{name}" if self.path != '/' else f"/{name}"
        return InternxtDAVResource(child_path, self.environ, file_metadata)

    def create_collection(self, name: str):
        """Create a new folder"""
        print(f"🔍 WEBDAV: create_collection({name}) in {self.path}")
        
        try:
            from services.drive import drive_service
            from services.auth import auth_service
            
            # Get parent folder UUID
            if self.path == '/' or self.path == '':
                credentials = auth_service.get_auth_details()
                parent_uuid = credentials['user'].get('rootFolderId', '')
            else:
                # Resolve parent path to get UUID
                resolved = drive_service.resolve_path(self.path)
                parent_uuid = resolved['uuid']
            
            # Create folder
            new_folder = drive_service.create_folder(name, parent_uuid)
            
            # Clear cache so the new folder appears
            self._content_cache = None
            
            print(f"✅ WEBDAV: Created folder {name} with UUID {new_folder['uuid']}")
            
            child_path = f"{self.path.rstrip('/')}/{name}" if self.path != '/' else f"/{name}"
            return InternxtDAVCollection(child_path, self.environ, new_folder)
            
        except Exception as e:
            print(f"❌ WEBDAV: Error creating folder: {e}")
            raise DAVError(HTTP_FORBIDDEN, f"Could not create folder: {e}")


class InternxtDAVProvider(DAVProvider):
    """WebDAV Provider for Internxt Drive - FIXED with proper file/folder detection"""
    
    def __init__(self):
        super().__init__()
        self.readonly = False # Enable write support
        
        print("🔍 WEBDAV: Initializing InternxtDAVProvider (FIXED ETAG VERSION)...")
        
        try:
            credentials = webdav_api.get_credentials()
            user_email = credentials['user'].get('email', 'unknown')
            print(f"✅ WEBDAV: Provider initialized with credentials for: {user_email}")
        except Exception as e:
            print(f"❌ WEBDAV: Provider initialization failed: {e}")
            raise
    
    def get_resource_inst(self, path: str, environ: dict) -> Optional[Union[DAVCollection, DAVNonCollection]]:
        """Get DAV resource for given path - FIXED to properly detect files vs folders"""
        try:
            if not path.startswith('/'):
                path = '/' + path
            
            print(f"🔍 WEBDAV: get_resource_inst() for path: {path}")
            
            # Root is always a collection
            if path == '/' or path == '':
                return InternxtDAVCollection(path, environ)
            
            # For other paths, we need to check if it's a file or folder
            # Parse the path to get parent and name
            path_parts = path.strip('/').split('/')
            parent_path = '/' + '/'.join(path_parts[:-1]) if len(path_parts) > 1 else '/'
            item_name = path_parts[-1]
            
            # Get parent collection
            parent_collection = InternxtDAVCollection(parent_path, environ)
            
            # Try to get the specific member
            member = parent_collection.get_member(item_name)
            if member:
                return member
            
            # If not found, return None (404)
            print(f"❌ WEBDAV: Resource not found: {path}")
            return None
                
        except Exception as e:
            print(f"❌ WEBDAV: Error in get_resource_inst({path}): {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def exists(self, path: str, environ: dict) -> bool:
        """Check if path exists"""
        try:
            resource = self.get_resource_inst(path, environ)
            return resource is not None
        except Exception as e:
            print(f"❌ WEBDAV: Error in exists({path}): {e}")
            return False