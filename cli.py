#!/usr/bin/env python3
"""
internxt_cli/cli.py
Main CLI interface for Internxt Python CLI
"""

import click
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

# Fix imports to work both as module and direct script
try:
    from .services.auth import auth_service
    from .services.drive import drive_service
    from .config.config import config_service
except ImportError:
    # Fallback for direct script execution
    current_dir = os.path.dirname(os.path.abspath(__file__))
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
    from services.auth import auth_service
    from services.drive import drive_service
    from config.config import config_service


def format_size(size_bytes: int) -> str:
    """Format file size in human readable format"""
    if not size_bytes:
        return "0 B"

    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0

    return f"{size_bytes:.1f} PB"


def format_date(date_string: str) -> str:
    """Format date string for display"""
    try:
        dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        return dt.strftime('%d %B, %Y at %H:%M')
    except Exception:
        return date_string


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """Internxt Python CLI - Encrypted cloud storage"""
    pass


@cli.command()
@click.option('--email', '-e', prompt=True, help='Your Internxt email')
@click.option('--password', '-p', prompt=True, hide_input=True, help='Your password')
@click.option('--tfa', '--2fa', help='Two-factor authentication code (6 digits)')
def login(email: str, password: str, tfa: Optional[str]):
    """Login to your Internxt account"""
    try:
        # Check if 2FA is needed
        if not tfa and auth_service.is_2fa_needed(email):
            tfa = click.prompt('Enter your 2FA code', type=str)

        click.echo("🔐 Logging in...")
        credentials = auth_service.login(email, password, tfa)

        user_email = credentials['user']['email']
        click.echo(f"✅ Successfully logged in as: {user_email}")

    except Exception as e:
        click.echo(f"❌ Login failed: {e}", err=True)
        sys.exit(1)


@cli.command()
def logout():
    """Logout from your Internxt account"""
    try:
        auth_service.logout()
        click.echo("✅ Successfully logged out")
    except Exception as e:
        click.echo(f"❌ Logout failed: {e}", err=True)
        sys.exit(1)


@cli.command()
def whoami():
    """Show current logged in user"""
    try:
        user_info = auth_service.whoami()
        if user_info:
            click.echo(f"📧 Logged in as: {user_info['email']}")
            click.echo(f"🆔 User ID: {user_info['uuid']}")
        else:
            click.echo("❌ Not logged in")
            sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command('list')
@click.option('--folder-id', '-f', help='Folder UUID to list (defaults to root)')
@click.option('--extended', '-e', is_flag=True, help='Show extended information')
def list_folder(folder_id: Optional[str], extended: bool):
    """List contents of a folder"""
    try:
        click.echo("📂 Getting folder contents...")
        contents = drive_service.list_folder(folder_id)

        folders = contents['folders']
        files = contents['files']

        if not folders and not files:
            click.echo("📁 Folder is empty")
            return

        # Display folders
        if folders:
            click.echo("\n📁 Folders:")
            click.echo("-" * 80)

            if extended:
                click.echo(f"{'Name':<30} {'ID':<40} {'Modified':<20}")
                click.echo("-" * 80)
                for folder in folders:
                    name = folder.get('plainName', folder.get('name', 'Unknown'))
                    folder_id = folder.get('uuid', 'N/A')
                    modified = format_date(folder.get('updatedAt', ''))
                    click.echo(f"{name:<30} {folder_id:<40} {modified:<20}")
            else:
                for folder in folders:
                    name = folder.get('plainName', folder.get('name', 'Unknown'))
                    click.echo(f"📁 {name}")

        # Display files
        if files:
            click.echo("\n📄 Files:")
            click.echo("-" * 80)

            if extended:
                click.echo(f"{'Name':<30} {'Size':<10} {'ID':<40} {'Modified':<20}")
                click.echo("-" * 80)
                for file in files:
                    name = file.get('plainName', file.get('name', 'Unknown'))
                    file_type = file.get('type', '')
                    if file_type:
                        name = f"{name}.{file_type}"

                    size = format_size(file.get('size', 0))
                    file_id = file.get('uuid', 'N/A')
                    modified = format_date(file.get('updatedAt', ''))
                    click.echo(f"{name:<30} {size:<10} {file_id:<40} {modified:<20}")
            else:
                for file in files:
                    name = file.get('plainName', file.get('name', 'Unknown'))
                    file_type = file.get('type', '')
                    if file_type:
                        name = f"{name}.{file_type}"

                    size = format_size(file.get('size', 0))
                    click.echo(f"📄 {name} ({size})")

        click.echo(f"\n📊 Total: {len(folders)} folders, {len(files)} files")

    except Exception as e:
        click.echo(f"❌ Failed to list folder: {e}", err=True)
        sys.exit(1)


@cli.command('mkdir')
@click.argument('name')
@click.option('--parent-id', '-p', help='Parent folder UUID (defaults to root)')
def create_folder(name: str, parent_id: Optional[str]):
    """Create a new folder"""
    try:
        click.echo(f"📁 Creating folder '{name}'...")
        folder = drive_service.create_folder(name, parent_id)

        folder_uuid = folder.get('uuid', 'N/A')
        click.echo(f"✅ Folder created successfully!")
        click.echo(f"🆔 Folder ID: {folder_uuid}")
        click.echo(f"🔗 View at: {config_service.get('DRIVE_WEB_URL')}/folder/{folder_uuid}")

    except Exception as e:
        click.echo(f"❌ Failed to create folder: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--folder-id', '-f', help='Destination folder UUID (defaults to root)')
def upload(file_path: str, folder_id: Optional[str]):
    """Upload a file to Internxt Drive"""
    try:
        file_path = Path(file_path)

        if not file_path.is_file():
            click.echo(f"❌ Not a file: {file_path}", err=True)
            sys.exit(1)

        drive_file = drive_service.upload_file(str(file_path), folder_id)

        click.echo(f"🆔 File ID: {drive_file.get('uuid', 'N/A')}")

    except Exception as e:
        click.echo(f"❌ Upload failed: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('file_id')
@click.option('--output', '-o', help='Output file path (optional)')
def download(file_id: str, output: Optional[str]):
    """Download a file from Internxt Drive"""
    try:
        output_path = drive_service.download_file(file_id, output)
        click.echo(f"🆔 File ID: {file_id}")

    except Exception as e:
        click.echo(f"❌ Download failed: {e}", err=True)
        sys.exit(1)


@cli.command()
def config():
    """Show configuration information"""
    try:
        user_info = auth_service.whoami()
        if not user_info:
            click.echo("❌ Not logged in")
            sys.exit(1)

        click.echo("⚙️ Configuration:")
        click.echo("-" * 40)
        click.echo(f"Email: {user_info['email']}")
        click.echo(f"User ID: {user_info['uuid']}")
        click.echo(f"Root Folder ID: {user_info['rootFolderId']}")
        click.echo(f"Drive Web URL: {config_service.get('DRIVE_WEB_URL')}")
        click.echo(f"Config Directory: {config_service.config_dir}")

    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--host', default='127.0.0.1', help='Host to bind to')
@click.option('--port', default=3005, help='Port to bind to')
@click.option('--http', is_flag=True, help='Use HTTP instead of HTTPS')
def webdav(host, port, http):
    """Start WebDAV server"""
    try:
        # Check authentication
        if not auth_service.whoami():
            click.echo("❌ Please login first: internxt login")
            return

        try:
            from .webdav.server import WebDAVServer
        except ImportError:
            try:
                from webdav.server import WebDAVServer
            except ImportError as e:
                click.echo(f"❌ WebDAV server not available: {e}")
                click.echo("Install with: pip install Flask>=2.3.0 Werkzeug>=2.3.0")
                return

        server = WebDAVServer()
        server.run(host=host, port=port, use_ssl=not http)

    except KeyboardInterrupt:
        click.echo("\n👋 WebDAV server stopped")
    except Exception as e:
        click.echo(f"❌ WebDAV server error: {e}", err=True)


@cli.command()
def test():
    """Test the CLI installation and components"""
    click.echo("🧪 Testing Internxt CLI components...")
    
    tests_passed = 0
    total_tests = 5
    
    # Test 1: Import services
    try:
        from services.auth import auth_service
        from services.drive import drive_service
        from services.crypto import crypto_service
        from config.config import config_service
        from utils.api import api_client
        click.echo("✅ All services imported successfully")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ Service import failed: {e}")
    
    # Test 2: Config service
    try:
        config_value = config_service.get('DRIVE_WEB_URL')
        assert config_value == 'https://drive.internxt.com'
        click.echo("✅ Config service working")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ Config service failed: {e}")
    
    # Test 3: Crypto service
    try:
        test_text = "Hello World"
        encrypted = crypto_service.encrypt_text(test_text)
        decrypted = crypto_service.decrypt_text(encrypted)
        assert decrypted == test_text
        click.echo("✅ Crypto service working")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ Crypto service failed: {e}")
    
    # Test 4: API client
    try:
        api_client.drive_api_url
        api_client.network_url
        click.echo("✅ API client initialized")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ API client failed: {e}")
    
    # Test 5: WebDAV server (optional)
    try:
        from webdav.server import WebDAVServer
        click.echo("✅ WebDAV server available")
        tests_passed += 1
    except ImportError:
        click.echo("⚠️  WebDAV server not available (Flask/Werkzeug not installed)")
        tests_passed += 1  # Count as pass since it's optional
    except Exception as e:
        click.echo(f"❌ WebDAV server test failed: {e}")
    
    click.echo(f"\n📊 Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        click.echo("🎉 All tests passed! CLI is ready to use.")
    else:
        click.echo("⚠️  Some tests failed. Check the errors above.")


if __name__ == '__main__':
    cli()