#!/usr/bin/env python3
"""
internxt_cli/services/webdav_server.py
WebDAV Server service for mounting Internxt Drive as local filesystem
FINAL FIXED VERSION - Addresses SSL and HTTP hanging issues
"""

import os
import sys
import time
import signal
import threading
import socket
import tempfile
from typing import Optional, Dict, Any, Tuple
from pathlib import Path

try:
    from wsgidav.wsgidav_app import WsgiDAVApp
    from wsgidav.fs_dav_provider import FilesystemProvider
    from cheroot import wsgi
    from cheroot.ssl.builtin import BuiltinSSLAdapter
    import ssl
except ImportError:
    print("❌ Missing WebDAV dependencies. Install with:")
    print("   pip install WsgiDAV cheroot")
    sys.exit(1)

from config.config import config_service
from services.auth import auth_service
from services.webdav_provider import InternxtDAVProvider


class WebDAVServer:
    """WebDAV Server for Internxt Drive - FINAL FIXED VERSION"""
    
    def __init__(self):
        self.server = None
        self.server_thread = None
        self.is_running = False
        self.config = self._load_config()
        self.ssl_cert_file = None
        self.ssl_key_file = None
        
    def _load_config(self) -> Dict[str, Any]:
        """Load WebDAV server configuration - Force HTTP by default due to SSL issues"""
        webdav_config = config_service.read_webdav_config()
        
        return {
            'host': webdav_config.get('host', 'localhost'),
            'port': int(webdav_config.get('port', 8080)),  # Use 8080 as default
            'use_ssl': False,  # Force HTTP for now - SSL has compatibility issues
            'timeout_minutes': int(webdav_config.get('timeoutMinutes', 30)),
            'verbose': int(webdav_config.get('verbose', 1)),  # Enable some logging by default
        }
    
    def _check_port_available(self, port: int) -> bool:
        """Check if port is available"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                result = sock.connect_ex(('localhost', port))
                return result != 0
        except Exception:
            return False
    
    def _find_available_port(self, start_port: int) -> int:
        """Find next available port starting from given port"""
        port = start_port
        while port < start_port + 100:  # Try up to 100 ports
            if self._check_port_available(port):
                return port
            port += 1
        raise RuntimeError(f"No available ports found starting from {start_port}")
    
    def _create_ssl_certificates(self) -> Optional[Tuple[str, str]]:
        """Create SSL certificates and return file paths (FIXED VERSION)"""
        if not self.config['use_ssl']:
            return None
            
        try:
            print("🔐 Generating SSL certificates...")
            
            # Get SSL certificates from network utils
            from services.network_utils import NetworkUtils
            ssl_certs = NetworkUtils.get_webdav_ssl_certs()
            
            # Create persistent temporary files for SSL certificates (FIXED)
            cert_file = tempfile.NamedTemporaryFile(mode='w', suffix='.crt', prefix='webdav_cert_', delete=False)
            cert_content = ssl_certs['cert'].decode() if isinstance(ssl_certs['cert'], bytes) else ssl_certs['cert']
            cert_file.write(cert_content)
            cert_path = cert_file.name
            cert_file.close()  # Close the file handle
            
            key_file = tempfile.NamedTemporaryFile(mode='w', suffix='.key', prefix='webdav_key_', delete=False)
            key_content = ssl_certs['key'].decode() if isinstance(ssl_certs['key'], bytes) else ssl_certs['key']
            key_file.write(key_content)
            key_path = key_file.name
            key_file.close()  # Close the file handle
            
            # Store paths for cleanup later
            self.ssl_cert_file = cert_path
            self.ssl_key_file = key_path
            
            print("✅ SSL certificates created successfully")
            return (cert_path, key_path)  # Return tuple of paths
            
        except Exception as e:
            print(f"⚠️  Failed to create SSL certificates: {e}")
            print("   Falling back to HTTP")
            self.config['use_ssl'] = False
            return None
    
    def _create_wsgidav_app(self) -> WsgiDAVApp:
        """Create WsgiDAV application with simplified, working configuration"""
        
        # Minimal WebDAV configuration that works with current WsgiDAV versions
        config = {
            'provider_mapping': {
                '/': InternxtDAVProvider(),
            },
            'simple_dc': {
                'user_mapping': {
                    '*': {  # Any domain
                        'internxt': {
                            'password': 'internxt-webdav',
                            'description': 'Internxt Drive User',
                        }
                    }
                }
            },
            'http_authenticator': {
                'domain_controller': 'wsgidav.dc.simple_dc.SimpleDomainController',
                'accept_basic': True,
                'accept_digest': False,
                'default_to_digest': False,
            },
            'verbose': self.config['verbose'],
            'property_manager': True,
            'lock_storage': True,
            'dir_browser': {
                'enable': True,
                'response_trailer': '<p>Internxt WebDAV Server</p>',
            },
        }
        
        return WsgiDAVApp(config)
    
    def start(self, port: Optional[int] = None, background: bool = False) -> Dict[str, Any]:
        """Start WebDAV server with improved error handling"""
        if self.is_running:
            return {
                'success': False,
                'message': 'WebDAV server is already running',
                'url': self._get_server_url()
            }
        
        try:
            # Verify authentication
            auth_service.get_auth_details()
            print("✅ Authentication verified")
        except Exception as e:
            return {
                'success': False,
                'message': f'Not logged in: {e}'
            }
        
        # Determine port
        target_port = int(port or self.config['port'])
        if not self._check_port_available(target_port):
            try:
                target_port = self._find_available_port(target_port)
                print(f"   Port {port or self.config['port']} busy, using {target_port}")
            except RuntimeError as e:
                return {'success': False, 'message': str(e)}
        
        self.config['port'] = target_port
        
        try:
            print(f"🔧 Creating WebDAV application...")
            
            # Create WsgiDAV app
            app = self._create_wsgidav_app()
            
            print(f"🔧 Setting up server on {self.config['host']}:{self.config['port']}...")
            
            # Create server
            bind_host = str(self.config['host'])
            bind_port = int(self.config['port'])
            timeout_seconds = int(self.config['timeout_minutes']) * 60
            
            self.server = wsgi.Server(
                bind_addr=(bind_host, bind_port),
                wsgi_app=app,
                timeout=timeout_seconds,
                server_name="Internxt WebDAV Server",
                # Add these settings to prevent SSL handshake issues
                numthreads=10,
                max=-1,
            )
            
            # Setup SSL if enabled (FIXED VERSION)
            if self.config['use_ssl']:
                print(f"🔐 Setting up SSL...")
                try:
                    ssl_files = self._create_ssl_certificates()
                    if ssl_files:
                        cert_path, key_path = ssl_files
                        
                        # Create SSL adapter with explicit settings to avoid handshake issues
                        self.server.ssl_adapter = BuiltinSSLAdapter(
                            certificate=cert_path,
                            private_key=key_path,
                            certificate_chain=None
                        )
                        
                        # Additional SSL context settings to prevent handshake errors
                        if hasattr(self.server.ssl_adapter, 'context'):
                            self.server.ssl_adapter.context.check_hostname = False
                            self.server.ssl_adapter.context.verify_mode = ssl.CERT_NONE
                        
                        print(f"🔐 SSL setup completed using cert: {cert_path}")
                    else:
                        print(f"🔧 SSL disabled, using HTTP")
                        self.config['use_ssl'] = False
                except Exception as e:
                    print(f"⚠️  SSL setup failed: {e}, falling back to HTTP")
                    self.config['use_ssl'] = False
                    self._cleanup_ssl_files()
            
            print(f"🔧 Server created successfully")
            
            # Start server
            if background:
                self.server_thread = threading.Thread(
                    target=self._run_server_thread,
                    daemon=True
                )
                self.server_thread.start()
                
                # Wait a moment to ensure server starts
                time.sleep(2)
                
                if not self.is_running:
                    return {'success': False, 'message': 'Failed to start server in background'}
            else:
                self._run_server_thread()
            
            return {
                'success': True,
                'message': f'WebDAV server started on {self._get_server_url()}',
                'url': self._get_server_url(),
                'port': self.config['port'],
                'protocol': 'https' if self.config['use_ssl'] else 'http'
            }
            
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"❌ Detailed error: {error_details}")
            
            return {
                'success': False,
                'message': f'Failed to start WebDAV server: {e}'
            }
    
    def _run_server_thread(self):
        """Run server in thread with proper error handling and signal handling"""
        try:
            self.is_running = True
            server_url = self._get_server_url()
            
            print(f"\n🌐 WebDAV server starting on {server_url}")
            print(f"📁 Mount point: {server_url}")
            print(f"👤 Username: internxt")
            print(f"🔑 Password: internxt-webdav")
            print()
            print("🌐 Web interface available at:", server_url)
            print()
            
            # Show connection instructions
            print("💡 Connection Instructions:")
            print("   1. Open Finder")
            print("   2. Press Cmd+K")
            print("   3. Enter server address:", server_url)
            print("   4. Username: internxt")
            print("   5. Password: internxt-webdav")
            print()
            print("Press Ctrl+C to stop the server")
            
            # FIXED: Better signal handling
            def signal_handler(signum, frame):
                print(f"\n🛑 Received signal {signum}, stopping WebDAV server...")
                self.is_running = False
                if self.server:
                    try:
                        self.server.stop()
                    except Exception as e:
                        print(f"Error stopping server: {e}")
                import sys
                sys.exit(0)
            
            import signal
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            # Start the server with better error handling
            try:
                print("🔄 Starting server...")
                self.server.start()
            except KeyboardInterrupt:
                print(f"\n🛑 Server interrupted")
            except Exception as e:
                print(f"❌ Server error: {e}")
                raise
            
        except KeyboardInterrupt:
            print("\n🛑 WebDAV server stopped by user")
        except Exception as e:
            print(f"❌ WebDAV server error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_running = False
            self._cleanup_ssl_files()
            print("🛑 WebDAV server stopped")
    
    def _cleanup_ssl_files(self):
        """Clean up temporary SSL certificate files"""
        if self.ssl_cert_file:
            try:
                os.unlink(self.ssl_cert_file)
                self.ssl_cert_file = None
            except OSError:
                pass
        
        if self.ssl_key_file:
            try:
                os.unlink(self.ssl_key_file)
                self.ssl_key_file = None
            except OSError:
                pass
    
    def stop(self) -> Dict[str, Any]:
        """Stop WebDAV server with improved cleanup"""
        print("🛑 Stopping WebDAV server...")
        
        if not self.is_running and not self.server:
            return {
                'success': False,
                'message': 'WebDAV server is not running'
            }
        
        try:
            self.is_running = False
            
            if self.server:
                print("🛑 Shutting down HTTP server...")
                try:
                    self.server.stop()
                    print("✅ HTTP server stopped")
                except Exception as e:
                    print(f"⚠️  Error stopping HTTP server: {e}")
                finally:
                    self.server = None
            
            if self.server_thread and self.server_thread.is_alive():
                print("🛑 Waiting for server thread to finish...")
                self.server_thread.join(timeout=3)
                if self.server_thread.is_alive():
                    print("⚠️  Server thread did not stop cleanly")
                else:
                    print("✅ Server thread stopped")
            
            self._cleanup_ssl_files()
            print("✅ WebDAV server stopped successfully")
            
            return {
                'success': True,
                'message': 'WebDAV server stopped successfully'
            }
            
        except Exception as e:
            print(f"❌ Error during server shutdown: {e}")
            return {
                'success': False,
                'message': f'Error stopping WebDAV server: {e}'
            }
    
    def status(self) -> Dict[str, Any]:
        """Get server status"""
        if self.is_running:
            return {
                'running': True,
                'url': self._get_server_url(),
                'port': self.config['port'],
                'protocol': 'https' if self.config['use_ssl'] else 'http',
                'host': self.config['host']
            }
        else:
            return {
                'running': False,
                'message': 'WebDAV server is not running'
            }
    
    def _get_server_url(self) -> str:
        """Get server URL"""
        protocol = 'https' if self.config['use_ssl'] else 'http'
        return f"{protocol}://{self.config['host']}:{self.config['port']}/"
    
    def get_mount_instructions(self) -> Dict[str, str]:
        """Get platform-specific mount instructions"""
        url = self._get_server_url()
        
        return {
            'windows': f"""
Windows File Explorer:
1. Open File Explorer
2. Click on "This PC" 
3. Click "Map network drive" in the toolbar
4. Enter: {url}
5. Username: internxt
6. Password: internxt-webdav

Windows Command Line:
net use Z: {url} internxt-webdav /user:internxt
""",
            'macos': f"""
macOS Finder (Recommended):
1. Open Finder
2. Press Cmd+K (Connect to Server)
3. Enter: {url}
4. Click Connect
5. Username: internxt
6. Password: internxt-webdav

macOS Command Line:
mkdir -p ~/InternxtDrive
mount -t webdav {url} ~/InternxtDrive

Test first with: curl -u internxt:internxt-webdav {url}
""",
            'linux': f"""
Linux (davfs2 - Recommended):
sudo apt install davfs2  # Ubuntu/Debian
sudo mkdir -p /mnt/internxt
sudo mount -t davfs {url} /mnt/internxt
Username: internxt
Password: internxt-webdav

Linux (GNOME Files/Nautilus):
1. Open Files (Nautilus)
2. Click "Other Locations" in sidebar
3. In "Connect to Server" box, enter: {url}
4. Username: internxt
5. Password: internxt-webdav
"""
        }
    
    def test_connection(self) -> Dict[str, Any]:
        """Test WebDAV server connection"""
        if not self.is_running:
            return {
                'success': False,
                'message': 'WebDAV server is not running'
            }
        
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            url = self._get_server_url()
            auth = HTTPBasicAuth('internxt', 'internxt-webdav')
            
            # Test basic connectivity
            response = requests.options(url, auth=auth, timeout=10, verify=False)
            
            if response.status_code in [200, 204]:
                return {
                    'success': True,
                    'message': 'WebDAV server is responding correctly',
                    'status_code': response.status_code,
                    'headers': dict(response.headers)
                }
            else:
                return {
                    'success': False,
                    'message': f'Server returned status {response.status_code}',
                    'status_code': response.status_code
                }
                
        except Exception as e:
            return {
                'success': False,
                'message': f'Connection test failed: {e}'
            }


# Global instance
webdav_server = WebDAVServer()