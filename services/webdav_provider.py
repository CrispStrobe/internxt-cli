#!/usr/bin/env python3
"""
internxt_cli/services/webdav_provider.py
ISOLATED VERSION - Creates fresh API session for WebDAV context
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
    """Isolated API client for WebDAV context to avoid session conflicts"""
    
    def __init__(self):
        self._credentials = None
        self._api_client = None
        self._thread_local = threading.local()
        
    def _get_isolated_session(self):
        """Get a thread-local API session"""
        if not hasattr(self._thread_local, 'api_client'):
            print("🔍 WEBDAV: Creating fresh API session for WebDAV thread")
            
            # Import here to avoid circular imports and get fresh instances
            from services.auth import auth_service
            from utils.api import ApiClient
            
            # Get fresh credentials
            self._credentials = auth_service.get_auth_details()
            
            # Create fresh API client instance
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
            
            # Get folders and files separately like the CLI does
            print("🔍 WEBDAV: Fetching folders...")
            folders_response = api_client.get_folder_folders(folder_uuid, 0, 50)
            folders = folders_response.get('result', folders_response.get('folders', []))
            print(f"✅ WEBDAV: Got {len(folders)} folders")
            
            print("🔍 WEBDAV: Fetching files...")
            files_response = api_client.get_folder_files(folder_uuid, 0, 50)  
            files = files_response.get('result', files_response.get('files', []))
            print(f"✅ WEBDAV: Got {len(files)} files")
            
            return {
                'folders': folders,
                'files': files
            }
            
        except Exception as e:
            print(f"❌ WEBDAV: Error getting folder content: {e}")
            import traceback
            traceback.print_exc()
            
            # Try fallback: call the original drive service from main thread
            print("🔍 WEBDAV: Trying fallback method...")
            try:
                from services.drive import drive_service
                return drive_service.get_folder_content(folder_uuid)
            except Exception as e2:
                print(f"❌ WEBDAV: Fallback also failed: {e2}")
                # Return empty content rather than crashing
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
        """Return ETag for caching"""
        file_uuid = self.file_metadata.get('uuid', '')
        modified = int(self.get_last_modified())
        return f'"{file_uuid}-{modified}"'
    
    def support_etag(self) -> bool:
        """FIXED: Implement required abstract method - Support ETags for caching"""
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
    
    def get_content(self) -> Iterator[bytes]:
        """Stream file content - Return dummy content for now"""
        # For debugging, return dummy content
        # TODO: Implement actual file download
        file_name = self.file_metadata.get('plainName', 'unknown')
        file_type = self.file_metadata.get('type', 'txt')
        content = f"DEBUG: This is file {file_name}.{file_type} from Internxt Drive\n"
        content += f"UUID: {self.file_metadata.get('uuid', 'unknown')}\n"
        content += f"Size: {self.file_metadata.get('size', 0)} bytes\n"
        content += f"Path: {self.path}\n"
        content += f"Created: {self.file_metadata.get('createdAt', 'unknown')}\n"
        yield content.encode('utf-8')


class InternxtDAVCollection(DAVCollection):
    """Represents a folder in Internxt Drive for WebDAV access"""
    
    def __init__(self, path: str, environ: dict, folder_metadata: dict = None):
        super().__init__(path, environ)
        self.folder_metadata = folder_metadata or {}
        self._content_cache = None
        self._content_cached_time = 0
        self.CACHE_TIMEOUT = 30  # 30 seconds
        
    def get_member_names(self) -> List[str]:
        """Return list of files and folders in this directory"""
        try:
            print(f"🔍 WEBDAV: get_member_names() for path: {self.path}")
            content = self._get_content()
            names = content.get('names', [])
            print(f"✅ WEBDAV: Returning {len(names)} member names: {names}")
            return names
        except Exception as e:
            print(f"❌ WEBDAV: Error getting member names for {self.path}: {e}")
            import traceback
            traceback.print_exc()
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
                    child_path = f"{self.path.rstrip('/')}/{name}"
                    print(f"✅ WEBDAV: Found folder: {name}")
                    return InternxtDAVCollection(child_path, self.environ, folder)
            
            # Check if it's a file
            for file in content['files']:
                file_name = file.get('plainName', '')
                file_type = file.get('type', '')
                display_name = f"{file_name}.{file_type}" if file_type else file_name
                
                if display_name == name:
                    child_path = f"{self.path.rstrip('/')}/{name}"
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
        """Return ETag for folder caching"""
        folder_uuid = self.folder_metadata.get('uuid', 'root')
        modified = int(self.get_last_modified())
        member_count = len(self._get_content().get('names', []))
        return f'"{folder_uuid}-{modified}-{member_count}"'
    
    def support_etag(self) -> bool:
        """FIXED: Implement required abstract method - Support ETags for caching"""
        return True
    
    def support_ranges(self) -> bool:
        """Support byte ranges"""
        return False  # Collections don't support ranges
    
    def support_content_length(self) -> bool:
        """Support content length"""
        return False  # Collections don't have content length
    
    def support_modified(self) -> bool:
        """Support last modified date"""
        return True
    
    def _get_content(self) -> Dict[str, Any]:
        """Get folder content with caching"""
        current_time = time.time()
        
        # Check cache
        if (self._content_cache is not None and 
            current_time - self._content_cached_time < self.CACHE_TIMEOUT):
            print("✅ WEBDAV: Using cached content")
            return self._content_cache
        
        try:
            print(f"🔍 WEBDAV: Fetching fresh content for: {self.path}")
            
            if self.path == '/' or self.path == '':
                # Root folder - get root folder UUID and fetch content
                credentials = webdav_api.get_credentials()
                root_folder_uuid = credentials['user'].get('rootFolderId', '')
                
                if not root_folder_uuid:
                    print("❌ WEBDAV: No root folder UUID found")
                    return {'folders': [], 'files': [], 'names': []}
                
                print(f"🔍 WEBDAV: Getting root folder content: {root_folder_uuid}")
                content = webdav_api.get_folder_content(root_folder_uuid)
                
            else:
                # Non-root folder - for now return empty
                print(f"🔍 WEBDAV: Non-root folder not implemented yet: {self.path}")
                content = {'folders': [], 'files': []}
            
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


class InternxtDAVProvider(DAVProvider):
    """WebDAV Provider for Internxt Drive - Isolated Version"""
    
    def __init__(self):
        super().__init__()
        self.readonly = False
        
        print("🔍 WEBDAV: Initializing InternxtDAVProvider (Isolated Version)...")
        
        # Test authentication
        try:
            credentials = webdav_api.get_credentials()
            user_email = credentials['user'].get('email', 'unknown')
            print(f"✅ WEBDAV: Provider initialized with credentials for: {user_email}")
        except Exception as e:
            print(f"❌ WEBDAV: Provider initialization failed: {e}")
            raise
    
    def get_resource_inst(self, path: str, environ: dict) -> Optional[Union[DAVCollection, DAVNonCollection]]:
        """Get DAV resource for given path"""
        try:
            if not path.startswith('/'):
                path = '/' + path
            
            print(f"🔍 WEBDAV: get_resource_inst() for path: {path}")
            
            # Always return a collection for now (folders only)
            return InternxtDAVCollection(path, environ)
                
        except Exception as e:
            print(f"❌ WEBDAV: Error in get_resource_inst({path}): {e}")
            return None
    
    def exists(self, path: str, environ: dict) -> bool:
        """Check if path exists"""
        try:
            if path == '/':
                return True
            
            # For now, assume all paths exist
            return True
            
        except Exception as e:
            print(f"❌ WEBDAV: Error in exists({path}): {e}")
            return False