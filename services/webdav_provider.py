#!/usr/bin/env python3
"""
internxt_cli/services/webdav_provider.py
WebDAV Provider that presents Internxt Drive as a filesystem
"""

import os
import io
import time
import tempfile
from typing import Dict, Any, List, Optional, Iterator, Union
from pathlib import Path

try:
    from wsgidav.dav_provider import DAVProvider, DAVCollection, DAVNonCollection, HTTP_NOT_FOUND, HTTP_FORBIDDEN
    from wsgidav.dav_error import DAVError, HTTP_CONFLICT
    import mimetypes
except ImportError:
    print("❌ Missing WebDAV dependency. Install with: pip install WsgiDAV")
    raise

from services.drive import drive_service
from services.auth import auth_service


class InternxtDAVResource(DAVNonCollection):
    """Represents a file in Internxt Drive for WebDAV access"""
    
    def __init__(self, path: str, environ: dict, file_metadata: dict):
        super().__init__(path, environ)
        self.file_metadata = file_metadata
        self._content_cache = None
        self._content_cached_time = 0
        self.CACHE_TIMEOUT = 300  # 5 minutes
        
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
            
        # Use Python's mimetypes module to guess content type
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
        """Return ETag for caching"""
        file_uuid = self.file_metadata.get('uuid', '')
        modified = self.get_last_modified()
        return f'"{file_uuid}-{int(modified)}"'
    
    def get_content(self) -> Iterator[bytes]:
        """Stream file content (download and decrypt on demand)"""
        # Check cache first
        current_time = time.time()
        if (self._content_cache is not None and 
            current_time - self._content_cached_time < self.CACHE_TIMEOUT):
            yield self._content_cache
            return
            
        try:
            # Download file to temporary location
            file_uuid = self.file_metadata['uuid']
            
            with tempfile.NamedTemporaryFile() as temp_file:
                # Download and decrypt file
                drive_service.download_file(file_uuid, temp_file.name)
                
                # Read and cache content
                temp_file.seek(0)
                content = temp_file.read()
                
                # Cache for future requests
                self._content_cache = content
                self._content_cached_time = current_time
                
                yield content
                
        except Exception as e:
            raise DAVError(HTTP_NOT_FOUND, f"Failed to download file: {e}")
    
    def begin_write(self, content_type: str = None) -> io.BytesIO:
        """Begin writing to file (for PUT operations)"""
        return io.BytesIO()
    
    def end_write(self, with_errors: bool, stream: io.BytesIO) -> None:
        """Complete file write (upload encrypted content)"""
        if with_errors:
            return
            
        try:
            # Get file content from stream
            stream.seek(0)
            content = stream.read()
            
            # Create temporary file with content
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(content)
                temp_file.flush()
                
                try:
                    # Parse path to get folder
                    path_parts = self.path.strip('/').split('/')
                    file_name = path_parts[-1]
                    folder_path = '/' + '/'.join(path_parts[:-1]) if len(path_parts) > 1 else '/'
                    
                    # Resolve destination folder
                    if folder_path == '/':
                        credentials = auth_service.get_auth_details()
                        folder_uuid = credentials['user'].get('rootFolderId', '')
                    else:
                        resolved = drive_service.resolve_path(folder_path)
                        if resolved['type'] != 'folder':
                            raise DAVError(HTTP_CONFLICT, f"Parent is not a folder: {folder_path}")
                        folder_uuid = resolved['uuid']
                    
                    # Upload file
                    drive_service.upload_file(temp_file.name, folder_uuid)
                    
                    # Clear cache
                    self._content_cache = None
                    
                finally:
                    # Clean up temporary file
                    try:
                        os.unlink(temp_file.name)
                    except OSError:
                        pass
                        
        except Exception as e:
            raise DAVError(HTTP_FORBIDDEN, f"Failed to upload file: {e}")


class InternxtDAVCollection(DAVCollection):
    """Represents a folder in Internxt Drive for WebDAV access"""
    
    def __init__(self, path: str, environ: dict, folder_metadata: dict = None):
        super().__init__(path, environ)
        self.folder_metadata = folder_metadata or {}
        self._content_cache = None
        self._content_cached_time = 0
        self.CACHE_TIMEOUT = 60  # 1 minute for folders
        
    def get_member_names(self) -> List[str]:
        """Return list of files and folders in this directory"""
        try:
            return self._get_cached_content()['names']
        except Exception as e:
            print(f"Error getting member names for {self.path}: {e}")
            return []
    
    def get_member(self, name: str) -> Optional[Union[DAVCollection, DAVNonCollection]]:
        """Get a specific member (file or folder) by name"""
        try:
            content = self._get_cached_content()
            
            # Check if it's a folder
            for folder in content['folders']:
                folder_name = folder.get('plainName', folder.get('name', ''))
                if folder_name == name:
                    child_path = f"{self.path.rstrip('/')}/{name}"
                    return InternxtDAVCollection(child_path, self.environ, folder)
            
            # Check if it's a file
            for file in content['files']:
                file_name = file.get('plainName', '')
                file_type = file.get('type', '')
                display_name = f"{file_name}.{file_type}" if file_type else file_name
                
                if display_name == name:
                    child_path = f"{self.path.rstrip('/')}/{name}"
                    return InternxtDAVResource(child_path, self.environ, file)
            
            return None
            
        except Exception as e:
            print(f"Error getting member {name} from {self.path}: {e}")
            return None
    
    def create_empty_resource(self, name: str) -> DAVNonCollection:
        """Create a new empty file"""
        child_path = f"{self.path.rstrip('/')}/{name}"
        
        # Create placeholder metadata for new file
        file_metadata = {
            'plainName': Path(name).stem,
            'type': Path(name).suffix.lstrip('.') if Path(name).suffix else '',
            'size': 0,
            'uuid': 'new-file',  # Will be updated after upload
        }
        
        # Clear cache since we're adding a new file
        self._content_cache = None
        
        return InternxtDAVResource(child_path, self.environ, file_metadata)
    
    def create_collection(self, name: str) -> DAVCollection:
        """Create a new folder"""
        try:
            # Resolve current folder UUID
            if self.path == '/':
                credentials = auth_service.get_auth_details()
                parent_uuid = credentials['user'].get('rootFolderId', '')
            else:
                resolved = drive_service.resolve_path(self.path)
                parent_uuid = resolved['uuid']
            
            # Create folder
            new_folder = drive_service.create_folder(name, parent_uuid)
            
            # Clear cache
            self._content_cache = None
            
            child_path = f"{self.path.rstrip('/')}/{name}"
            return InternxtDAVCollection(child_path, self.environ, new_folder)
            
        except Exception as e:
            raise DAVError(HTTP_FORBIDDEN, f"Failed to create folder: {e}")
    
    def delete(self) -> None:
        """Delete this folder"""
        try:
            if self.path == '/':
                raise DAVError(HTTP_FORBIDDEN, "Cannot delete root folder")
            
            # Use trash instead of permanent delete for safety
            drive_service.trash_by_path(self.path)
            
        except Exception as e:
            raise DAVError(HTTP_FORBIDDEN, f"Failed to delete folder: {e}")
    
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
    
    def _get_cached_content(self) -> Dict[str, Any]:
        """Get folder content with caching"""
        current_time = time.time()
        
        if (self._content_cache is not None and 
            current_time - self._content_cached_time < self.CACHE_TIMEOUT):
            return self._content_cache
        
        # Get fresh content
        try:
            content = drive_service.list_folder_with_paths(self.path)
            
            # Build member names list
            names = []
            for folder in content['folders']:
                folder_name = folder.get('plainName', folder.get('name', ''))
                if folder_name:
                    names.append(folder_name)
            
            for file in content['files']:
                file_name = file.get('plainName', '')
                file_type = file.get('type', '')
                display_name = f"{file_name}.{file_type}" if file_type else file_name
                if display_name:
                    names.append(display_name)
            
            cached_content = {
                'folders': content['folders'],
                'files': content['files'],
                'names': names
            }
            
            self._content_cache = cached_content
            self._content_cached_time = current_time
            
            return cached_content
            
        except Exception as e:
            print(f"Error caching content for {self.path}: {e}")
            return {'folders': [], 'files': [], 'names': []}


class InternxtDAVProvider(DAVProvider):
    """WebDAV Provider for Internxt Drive"""
    
    def __init__(self):
        super().__init__()
        self.readonly = False  # Allow write operations
        
        # Verify authentication on startup
        try:
            auth_service.get_auth_details()
            print("✅ WebDAV Provider initialized with valid credentials")
        except Exception as e:
            print(f"❌ WebDAV Provider initialization failed: {e}")
            raise
    
    def get_resource_inst(self, path: str, environ: dict) -> Optional[Union[DAVCollection, DAVNonCollection]]:
        """Get DAV resource for given path"""
        try:
            # Normalize path
            if not path.startswith('/'):
                path = '/' + path
            
            # Root folder
            if path == '/':
                return InternxtDAVCollection('/', environ)
            
            # Try to resolve path
            try:
                resolved = drive_service.resolve_path(path)
                
                if resolved['type'] == 'folder':
                    return InternxtDAVCollection(path, environ, resolved['metadata'])
                else:  # file
                    return InternxtDAVResource(path, environ, resolved['metadata'])
                    
            except FileNotFoundError:
                # Path doesn't exist - return None
                return None
                
        except Exception as e:
            print(f"Error resolving path {path}: {e}")
            return None
    
    def exists(self, path: str, environ: dict) -> bool:
        """Check if path exists"""
        try:
            if path == '/':
                return True
            return drive_service.resolve_path(path) is not None
        except FileNotFoundError:
            return False
        except Exception:
            return False