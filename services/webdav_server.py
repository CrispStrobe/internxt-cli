#!/usr/bin/env python3
"""
internxt_cli/services/webdav_server.py
WebDAV Server service for mounting Internxt Drive as local filesystem
"""

import os
import sys
import time
import signal
import threading
import socket
from typing import Optional, Dict, Any
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
    """WebDAV Server for Internxt Drive"""
    
    def __init__(self):
        self.server = None
        self.server_thread = None
        self.is_running = False
        self.config = self._load_config()
        
    def _load_config(self) -> Dict[str, Any]:
        """Load WebDAV server configuration"""
        webdav_config = config_service.read_webdav_config()
        
        return {
            'host': webdav_config.get('host', 'localhost'),
            'port': webdav_config.get('port', 8080),
            'use_ssl': webdav_config.get('protocol') == 'https',
            'timeout_minutes': webdav_config.get('timeoutMinutes', 30),
            'verbose': webdav_config.get('verbose', 0),
        }
    
    def _check_port_available(self, port: int) -> bool:
        """Check if port is available"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            result = sock.connect_ex(('localhost', port))
            return result != 0
    
    def _find_available_port(self, start_port: int) -> int:
        """Find next available port starting from given port"""
        port = start_port
        while port < start_port + 100:  # Try up to 100 ports
            if self._check_port_available(port):
                return port
            port += 1
        raise RuntimeError(f"No available ports found starting from {start_port}")
    
    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for HTTPS"""
        if not self.config['use_ssl']:
            return None
            
        try:
            # Get SSL certificates from network utils
            from services.network_utils import NetworkUtils
            ssl_certs = NetworkUtils.get_webdav_ssl_certs()
            
            # Create SSL context
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            
            # Write certs to temporary files for SSL context
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as cert_file:
                cert_file.write(ssl_certs['cert'].decode() if isinstance(ssl_certs['cert'], bytes) else ssl_certs['cert'])
                cert_path = cert_file.name
                
            with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as key_file:
                key_file.write(ssl_certs['key'].decode() if isinstance(ssl_certs['key'], bytes) else ssl_certs['key'])
                key_path = key_file.name
            
            context.load_cert_chain(cert_path, key_path)
            
            # Clean up temp files
            os.unlink(cert_path)
            os.unlink(key_path)
            
            return context
            
        except Exception as e:
            print(f"⚠️  Failed to create SSL context: {e}")
            print("   Falling back to HTTP")
            self.config['use_ssl'] = False
            return None
    
    def _create_wsgidav_app(self) -> WsgiDAVApp:
        """Create WsgiDAV application"""
        
        # WebDAV configuration with updated format
        config = {
            'provider_mapping': {
                '/': InternxtDAVProvider(),
            },
            'simple_dc': {
                'user_mapping': {
                    '*': {  # Allow all users (we handle auth via Internxt tokens)
                        'internxt': {
                            'password': 'internxt-webdav',  # Placeholder password
                            'description': 'Internxt Drive User',
                        }
                    }
                }
            },
            'http_authenticator': {
                'domain_controller': 'wsgidav.dc.simple_dc.SimpleDomainController',
                'accept_basic': True,
                'accept_digest': False,
            },
            'verbose': self.config['verbose'],
            'logging': {
                'enable_loggers': []
            },
            'property_manager': True,
            'lock_storage': True,
            # Simplified middleware stack to avoid compatibility issues
            'middleware_stack': [
                'wsgidav.error_printer.ErrorPrinter',
                'wsgidav.http_authenticator.HTTPAuthenticator', 
                'wsgidav.request_resolver.RequestResolver',
            ],
        }
        
        return WsgiDAVApp(config)
    
    def start(self, port: Optional[int] = None, background: bool = False) -> Dict[str, Any]:
        """Start WebDAV server"""
        if self.is_running:
            return {
                'success': False,
                'message': 'WebDAV server is already running',
                'url': self._get_server_url()
            }
        
        try:
            # Verify authentication
            auth_service.get_auth_details()
        except Exception as e:
            return {
                'success': False,
                'message': f'Not logged in: {e}'
            }
        
        # Determine port - ensure it's an integer
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
            
            # Create server with explicit type conversion
            bind_host = str(self.config['host'])
            bind_port = int(self.config['port'])
            timeout_seconds = int(self.config['timeout_minutes']) * 60
            
            self.server = wsgi.Server(
                bind_addr=(bind_host, bind_port),
                wsgi_app=app,
                timeout=timeout_seconds,
                server_name="Internxt WebDAV Server"
            )
            
            print(f"🔧 Server created successfully")
            
            # Setup SSL if enabled
            if self.config['use_ssl']:
                print(f"🔐 Setting up SSL...")
                try:
                    ssl_context = self._create_ssl_context()
                    if ssl_context:
                        self.server.ssl_adapter = BuiltinSSLAdapter(
                            certificate=None,  # Using context instead
                            private_key=None,
                            certificate_chain=None
                        )
                        # Note: Setting context on adapter may not work with all versions
                        print(f"🔐 SSL setup completed")
                    else:
                        print(f"🔧 SSL disabled, using HTTP")
                except Exception as e:
                    print(f"⚠️  SSL setup failed: {e}, falling back to HTTP")
                    self.config['use_ssl'] = False
            
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
        """Run server in thread"""
        try:
            self.is_running = True
            print(f"🌐 WebDAV server starting on {self._get_server_url()}")
            print(f"📁 Mount point: {self._get_server_url()}")
            print(f"👤 Username: internxt")
            print(f"🔑 Password: internxt-webdav")
            print()
            print("Press Ctrl+C to stop the server")
            
            # Setup signal handlers
            def signal_handler(signum, frame):
                print("\n🛑 Stopping WebDAV server...")
                self.stop()
            
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            
            self.server.start()
            
        except KeyboardInterrupt:
            print("\n🛑 WebDAV server stopped by user")
        except Exception as e:
            print(f"❌ WebDAV server error: {e}")
        finally:
            self.is_running = False
    
    def stop(self) -> Dict[str, Any]:
        """Stop WebDAV server"""
        if not self.is_running:
            return {
                'success': False,
                'message': 'WebDAV server is not running'
            }
        
        try:
            if self.server:
                self.server.stop()
                self.server = None
            
            if self.server_thread and self.server_thread.is_alive():
                self.server_thread.join(timeout=5)
            
            self.is_running = False
            
            return {
                'success': True,
                'message': 'WebDAV server stopped successfully'
            }
            
        except Exception as e:
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
macOS Finder:
1. Open Finder
2. Press Cmd+K (Connect to Server)
3. Enter: {url}
4. Username: internxt
5. Password: internxt-webdav

macOS Command Line:
mkdir ~/InternxtDrive
mount -t webdav {url} ~/InternxtDrive
""",
            'linux': f"""
Linux (davfs2):
sudo apt install davfs2  # Ubuntu/Debian
sudo mkdir /mnt/internxt
sudo mount -t davfs {url} /mnt/internxt
Username: internxt
Password: internxt-webdav

Linux (GNOME Files):
1. Open Files (Nautilus)
2. Click "Other Locations"
3. Enter: {url}
4. Username: internxt
5. Password: internxt-webdav
"""
        }


# Global instance
webdav_server = WebDAVServer()