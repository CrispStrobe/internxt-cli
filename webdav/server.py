#!/usr/bin/env python3
"""
internxt_cli/webdav/server.py
WebDAV server implementation for Internxt CLI
"""

import os
import sys
import ssl
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List
from xml.etree import ElementTree as ET

# Import Flask and Werkzeug with error handling
try:
    from flask import Flask, request, Response, abort
    from werkzeug.serving import WSGIRequestHandler
except ImportError as e:
    print(f"❌ Flask/Werkzeug not installed: {e}")
    print("Install with: pip install Flask>=2.3.0 Werkzeug>=2.3.0")
    sys.exit(1)

# Fix imports to work both as module and direct script
try:
    from ..services.auth import auth_service
    from ..services.drive import drive_service
    from ..config.config import config_service
except ImportError:
    # Fallback for direct script execution
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from services.auth import auth_service
    from services.drive import drive_service
    from config.config import config_service


class WebDAVHandler:
    """WebDAV request handler"""

    def __init__(self):
        self.auth = auth_service
        self.drive = drive_service
        self.config = config_service

    def authenticate(self):
        """Check if user is authenticated"""
        try:
            user_info = self.auth.whoami()
            return user_info is not None
        except Exception as e:
            print(f"Authentication check failed: {e}")
            return False

    def parse_path(self, path: str) -> Dict[str, Any]:
        """Parse WebDAV path and return resource info"""
        # Remove leading/trailing slashes and decode
        path = urllib.parse.unquote(path.strip('/'))

        if not path:
            # Root folder
            return {
                'type': 'folder',
                'name': '',
                'path': '/',
                'parent_path': '/',
                'is_root': True
            }

        # Determine if it's a file or folder (folders end with /)
        is_folder = path.endswith('/')
        if is_folder:
            path = path.rstrip('/')

        path_parts = path.split('/')
        name = path_parts[-1]
        parent_path = '/'.join(path_parts[:-1])

        return {
            'type': 'folder' if is_folder else 'file',
            'name': name,
            'path': '/' + path,
            'parent_path': '/' + parent_path if parent_path else '/',
            'is_root': False
        }

    def get_folder_uuid_by_path(self, path: str) -> Optional[str]:
        """Get folder UUID by path (simplified implementation)"""
        if path == '/':
            # Root folder
            try:
                user_info = self.auth.whoami()
                return user_info.get('rootFolderId')
            except Exception as e:
                print(f"Failed to get root folder ID: {e}")
                return None

        # For this simple implementation, we'll just return root
        # In a full implementation, you'd traverse the path
        try:
            user_info = self.auth.whoami()
            return user_info.get('rootFolderId')
        except Exception as e:
            print(f"Failed to get folder UUID for path {path}: {e}")
            return None

    def format_date_rfc2822(self, date_str: str) -> str:
        """Format date for WebDAV (RFC 2822 format)"""
        try:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return dt.strftime('%a, %d %b %Y %H:%M:%S GMT')
        except Exception:
            return datetime.now().strftime('%a, %d %b %Y %H:%M:%S GMT')

    def create_propfind_response(self, resources: List[Dict[str, Any]]) -> str:
        """Create PROPFIND XML response"""
        multistatus = ET.Element('D:multistatus')
        multistatus.set('xmlns:D', 'DAV:')

        for resource in resources:
            response = ET.SubElement(multistatus, 'D:response')

            # href
            href = ET.SubElement(response, 'D:href')
            href.text = resource['path']

            # propstat
            propstat = ET.SubElement(response, 'D:propstat')

            # status
            status = ET.SubElement(propstat, 'D:status')
            status.text = 'HTTP/1.1 200 OK'

            # prop
            prop = ET.SubElement(propstat, 'D:prop')

            # displayname
            displayname = ET.SubElement(prop, 'D:displayname')
            displayname.text = resource['name']

            # getlastmodified
            getlastmodified = ET.SubElement(prop, 'D:getlastmodified')
            getlastmodified.text = resource.get('modified', self.format_date_rfc2822(datetime.now().isoformat()))

            if resource['type'] == 'folder':
                # resourcetype (collection for folders)
                resourcetype = ET.SubElement(prop, 'D:resourcetype')
                collection = ET.SubElement(resourcetype, 'D:collection')
            else:
                # resourcetype (empty for files)
                resourcetype = ET.SubElement(prop, 'D:resourcetype')

                # getcontentlength
                getcontentlength = ET.SubElement(prop, 'D:getcontentlength')
                getcontentlength.text = str(resource.get('size', 0))

                # getcontenttype
                getcontenttype = ET.SubElement(prop, 'D:getcontenttype')
                getcontenttype.text = 'application/octet-stream'

        return ET.tostring(multistatus, encoding='unicode')


class WebDAVServer:
    """WebDAV server for Internxt Drive"""

    def __init__(self):
        self.app = Flask(__name__)
        self.handler = WebDAVHandler()
        self.setup_routes()

    def setup_routes(self):
        """Setup WebDAV routes"""

        @self.app.before_request
        def authenticate():
            """Authenticate all requests"""
            if not self.handler.authenticate():
                return Response(
                    '<?xml version="1.0" encoding="utf-8"?><D:error xmlns:D="DAV:"><D:responsedescription>Authentication required</D:responsedescription></D:error>',
                    status=401,
                    headers={'WWW-Authenticate': 'Basic realm="Internxt Drive"'}
                )

        @self.app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
        @self.app.route('/<path:path>', methods=['OPTIONS'])
        def options(path):
            """Handle OPTIONS requests"""
            return Response(
                status=200,
                headers={
                    'Allow': 'OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, MKCOL, MOVE',
                    'DAV': '1, 2',
                    'Content-Length': '0'
                }
            )

        @self.app.route('/', defaults={'path': ''}, methods=['PROPFIND'])
        @self.app.route('/<path:path>', methods=['PROPFIND'])
        def propfind(path):
            """Handle PROPFIND requests"""
            resource_info = self.handler.parse_path('/' + path)
            depth = request.headers.get('Depth', '1')

            if resource_info['type'] == 'folder':
                try:
                    folder_uuid = self.handler.get_folder_uuid_by_path(resource_info['path'])
                    if not folder_uuid:
                        print(f"Folder UUID not found for path: {resource_info['path']}")
                        abort(404)

                    resources = []

                    # Add the folder itself
                    resources.append({
                        'type': 'folder',
                        'name': resource_info['name'] or 'Internxt Drive',
                        'path': resource_info['path'] if resource_info['path'] != '/' else '/',
                        'modified': self.handler.format_date_rfc2822(datetime.now().isoformat())
                    })

                    # If depth is 1, add children
                    if depth == '1':
                        try:
                            contents = drive_service.list_folder(folder_uuid)

                            # Add folders
                            for folder in contents['folders']:
                                folder_name = folder.get('plainName', 'Unknown')
                                folder_path = f"{resource_info['path'].rstrip('/')}/{folder_name}/"
                                resources.append({
                                    'type': 'folder',
                                    'name': folder_name,
                                    'path': folder_path,
                                    'modified': self.handler.format_date_rfc2822(folder.get('updatedAt', ''))
                                })

                            # Add files
                            for file in contents['files']:
                                file_name = file.get('plainName', 'Unknown')
                                file_type = file.get('type', '')
                                if file_type:
                                    file_name = f"{file_name}.{file_type}"

                                file_path = f"{resource_info['path'].rstrip('/')}/{file_name}"
                                resources.append({
                                    'type': 'file',
                                    'name': file_name,
                                    'path': file_path,
                                    'size': file.get('size', 0),
                                    'modified': self.handler.format_date_rfc2822(file.get('updatedAt', ''))
                                })
                        except Exception as e:
                            print(f"Failed to list folder contents: {e}")
                            # Continue with just the folder itself

                    xml_response = self.handler.create_propfind_response(resources)
                    return Response(
                        f'<?xml version="1.0" encoding="utf-8"?>{xml_response}',
                        status=207,
                        content_type='application/xml; charset=utf-8'
                    )

                except Exception as e:
                    print(f"PROPFIND error: {e}")
                    abort(500)
            else:
                # File PROPFIND - simplified
                print(f"File PROPFIND not implemented for: {resource_info['path']}")
                abort(404)

        @self.app.route('/', defaults={'path': ''}, methods=['GET'])
        @self.app.route('/<path:path>', methods=['GET'])
        def get(path):
            """Handle GET requests (download files)"""
            resource_info = self.handler.parse_path('/' + path)

            if resource_info['type'] == 'file':
                # For this simple implementation, we'll return a placeholder
                # In a full implementation, you'd download and decrypt the file
                return Response(
                    "File download not implemented in basic WebDAV server",
                    status=501,
                    content_type='text/plain'
                )
            else:
                # Folder GET - redirect to PROPFIND
                return Response(
                    "Folder listing - use PROPFIND",
                    status=405,
                    content_type='text/plain'
                )

        @self.app.route('/', defaults={'path': ''}, methods=['PUT'])
        @self.app.route('/<path:path>', methods=['PUT'])
        def put(path):
            """Handle PUT requests (upload files)"""
            resource_info = self.handler.parse_path('/' + path)

            if resource_info['type'] == 'file':
                try:
                    # Get file content from request
                    file_content = request.get_data()

                    if not file_content:
                        return Response("No file content", status=400)

                    # Create temporary file
                    import tempfile
                    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{resource_info['name']}") as temp_file:
                        temp_file.write(file_content)
                        temp_file_path = temp_file.name

                    try:
                        # Get parent folder UUID
                        parent_folder_uuid = self.handler.get_folder_uuid_by_path(resource_info['parent_path'])

                        # Upload file
                        drive_service.upload_file(temp_file_path, parent_folder_uuid)

                        return Response(status=201)  # Created
                    finally:
                        # Clean up temporary file
                        os.unlink(temp_file_path)

                except Exception as e:
                    print(f"PUT error: {e}")
                    return Response(f"Upload failed: {e}", status=500)
            else:
                return Response("Cannot PUT to folder", status=405)

        @self.app.route('/', defaults={'path': ''}, methods=['MKCOL'])
        @self.app.route('/<path:path>', methods=['MKCOL'])
        def mkcol(path):
            """Handle MKCOL requests (create folders)"""
            resource_info = self.handler.parse_path('/' + path)

            try:
                parent_folder_uuid = self.handler.get_folder_uuid_by_path(resource_info['parent_path'])
                if not parent_folder_uuid:
                    print(f"Parent folder not found for path: {resource_info['parent_path']}")
                    abort(409)  # Conflict - parent doesn't exist

                folder = drive_service.create_folder(resource_info['name'], parent_folder_uuid)
                print(f"Created folder: {resource_info['name']}")
                return Response(status=201)

            except Exception as e:
                print(f"MKCOL error: {e}")
                return Response(f"Failed to create folder: {e}", status=500)

        @self.app.route('/', defaults={'path': ''}, methods=['DELETE'])
        @self.app.route('/<path:path>', methods=['DELETE'])
        def delete(path):
            """Handle DELETE requests"""
            resource_info = self.handler.parse_path('/' + path)

            try:
                if resource_info['type'] == 'folder':
                    # Delete folder - simplified implementation
                    return Response("Folder deletion not implemented", status=501)
                else:
                    # Delete file - simplified implementation
                    return Response("File deletion not implemented", status=501)
            except Exception as e:
                print(f"DELETE error: {e}")
                return Response(f"Delete failed: {e}", status=500)

        @self.app.route('/', defaults={'path': ''}, methods=['MOVE'])
        @self.app.route('/<path:path>', methods=['MOVE'])
        def move(path):
            """Handle MOVE requests"""
            return Response("MOVE not implemented", status=501)

        @self.app.errorhandler(404)
        def not_found(error):
            """Handle 404 errors"""
            return Response(
                '<?xml version="1.0" encoding="utf-8"?><D:error xmlns:D="DAV:"><D:responsedescription>Not Found</D:responsedescription></D:error>',
                status=404,
                content_type='application/xml'
            )

        @self.app.errorhandler(500)
        def internal_error(error):
            """Handle 500 errors"""
            return Response(
                '<?xml version="1.0" encoding="utf-8"?><D:error xmlns:D="DAV:"><D:responsedescription>Internal Server Error</D:responsedescription></D:error>',
                status=500,
                content_type='application/xml'
            )

    def run(self, host='127.0.0.1', port=3005, use_ssl=True):
        """Run the WebDAV server"""
        print(f"🌐 Starting WebDAV server...")
        print(f"🔗 URL: {'https' if use_ssl else 'http'}://{host}:{port}")
        print(f"🔐 Authentication: Required (login first with 'internxt login')")
        print(f"📁 Mount this URL in your file manager to access your Internxt Drive")
        print(f"⚠️  Note: This is a basic WebDAV implementation")
        print(f"   - File download/upload may have limitations")
        print(f"   - Use Ctrl+C to stop the server")
        print()

        if use_ssl:
            try:
                # Create self-signed certificate for HTTPS
                cert_file, key_file = self._create_self_signed_cert()
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.load_cert_chain(cert_file, key_file)

                self.app.run(
                    host=host,
                    port=port,
                    ssl_context=context,
                    debug=False,
                    threaded=True
                )
            except Exception as e:
                print(f"❌ HTTPS server failed: {e}")
                print("🔄 Falling back to HTTP...")
                self.app.run(
                    host=host,
                    port=port,
                    debug=False,
                    threaded=True
                )
        else:
            self.app.run(
                host=host,
                port=port,
                debug=False,
                threaded=True
            )

    def _create_self_signed_cert(self):
        """Create self-signed certificate for HTTPS"""
        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            import datetime
        except ImportError as e:
            raise ImportError(f"Cryptography library required for HTTPS: {e}")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"webdav.local.internxt.com"),
        ])

        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"webdav.local.internxt.com"),
                x509.DNSName(u"localhost"),
                x509.IPAddress(u"127.0.0.1"),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Save certificate and key
        cert_dir = config_service.config_dir / 'certs'
        cert_dir.mkdir(exist_ok=True)

        cert_file = cert_dir / 'cert.pem'
        key_file = cert_dir / 'key.pem'

        with open(cert_file, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        with open(key_file, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))

        print(f"🔒 Created self-signed certificate: {cert_file}")
        return str(cert_file), str(key_file)


def main():
    """Main function for running WebDAV server standalone"""
    import argparse

    parser = argparse.ArgumentParser(description='Internxt WebDAV Server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=3005, help='Port to bind to')
    parser.add_argument('--http', action='store_true', help='Use HTTP instead of HTTPS')

    args = parser.parse_args()

    try:
        # Check authentication
        if not auth_service.whoami():
            print("❌ Please login first: internxt login")
            return

        server = WebDAVServer()
        server.run(host=args.host, port=args.port, use_ssl=not args.http)

    except KeyboardInterrupt:
        print("\n👋 WebDAV server stopped")
    except Exception as e:
        print(f"❌ WebDAV server error: {e}")


if __name__ == "__main__":
    main()