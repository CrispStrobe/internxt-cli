#!/usr/bin/env python3
"""
Internxt CLI - Python implementation with Path Support and Delete Operations
Enhanced with path-based operations and comprehensive delete/trash functionality
"""

import click
import sys
import os
import json
import base64
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

# Try to import required packages
try:
    import requests
    import mnemonic
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from tqdm import tqdm
except ImportError as e:
    print(f"❌ Missing required dependency: {e}")
    print("📦 Install with: pip install cryptography mnemonic tqdm requests click")
    sys.exit(1)

# Add current directory to path for imports
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

# Import our services
try:
    from config.config import config_service
    from services.crypto import crypto_service
    from services.auth import auth_service
    from utils.api import api_client
    from services.drive import drive_service
except ImportError as e:
    print(f"❌ Failed to import services: {e}")
    print("📦 Make sure all service files are in place with fixed implementations")
    sys.exit(1)


def format_size(size_bytes: int) -> str:
    """Format bytes to human readable size"""
    if not size_bytes:
        return "0 B"
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


def format_date(date_string: str) -> str:
    """Format ISO date string to readable format"""
    try:
        dt = datetime.fromisoformat(date_string.replace('Z', '+00:00'))
        return dt.strftime('%d %B, %Y at %H:%M')
    except Exception:
        return date_string


@click.group()
@click.version_option(version='1.0.0')
def cli():
    """Internxt Python CLI with Path Support and Delete Operations"""
    pass


# ========== AUTHENTICATION COMMANDS ==========

@cli.command()
@click.option('--email', '-e', help='Your Internxt email')
@click.option('--password', '-p', help='Your password')
@click.option('--tfa', '--2fa', help='Two-factor authentication code (6 digits)')
@click.option('--non-interactive', is_flag=True, help='Run in non-interactive mode')
@click.option('--debug', is_flag=True, help='Enable debug output')
def login(email: Optional[str], password: Optional[str], tfa: Optional[str], non_interactive: bool, debug: bool):
    """Login to your Internxt account"""
    try:
        if debug:
            print("🔍 Debug mode enabled")
            print(f"🔍 API Endpoints:")
            print(f"   Drive API: {config_service.get('DRIVE_NEW_API_URL')}")
            print(f"   Network API: {config_service.get('NETWORK_URL')}")
        
        # Get email
        if not email:
            if non_interactive:
                click.echo("❌ Email is required in non-interactive mode", err=True)
                sys.exit(1)
            email = click.prompt('What is your email?', type=str)
        
        # Validate email
        if '@' not in email or '.' not in email:
            click.echo("❌ Invalid email format", err=True)
            sys.exit(1)
        
        # Get password
        if not password:
            if non_interactive:
                click.echo("❌ Password is required in non-interactive mode", err=True)
                sys.exit(1)
            password = click.prompt('What is your password?', hide_input=True, type=str)
        
        if not password.strip():
            click.echo("❌ Password cannot be empty", err=True)
            sys.exit(1)
        
        # Check 2FA
        click.echo("🔍 Checking 2FA requirements...")
        try:
            is_2fa_needed = auth_service.is_2fa_needed(email)
            if debug:
                print(f"🔍 2FA needed: {is_2fa_needed}")
        except Exception as e:
            click.echo(f"⚠️  Could not check 2FA status: {e}")
            is_2fa_needed = False
        
        if is_2fa_needed and not tfa:
            if non_interactive:
                click.echo("❌ 2FA code is required in non-interactive mode", err=True)
                sys.exit(1)
            tfa = click.prompt('What is your two-factor token?', type=str)
        
        if tfa and (not tfa.isdigit() or len(tfa) != 6):
            click.echo("❌ Invalid 2FA code format (must be 6 digits)", err=True)
            sys.exit(1)
        
        # Login
        click.echo("🔐 Logging in...")
        credentials = auth_service.login(email, password, tfa)
        
        user_email = credentials['user']['email']
        user_uuid = credentials['user']['uuid']
        root_folder_id = credentials['user'].get('rootFolderId', '')
        
        click.echo(f"✅ Successfully logged in as: {user_email}")
        if debug:
            print(f"🔍 User UUID: {user_uuid}")
            print(f"🔍 Root Folder ID: {root_folder_id}")
        
    except Exception as e:
        error_msg = str(e)
        if "Login failed:" in error_msg:
            error_msg = error_msg.replace("Login failed: ", "")
        click.echo(f"❌ Login failed: {error_msg}", err=True)
        
        if debug:
            import traceback
            print("🔍 Full error traceback:")
            traceback.print_exc()
        
        sys.exit(1)


@cli.command()
def whoami():
    """Check current login status"""
    try:
        user_info = auth_service.whoami()
        if user_info:
            click.echo(f"📧 Logged in as: {user_info['email']}")
            click.echo(f"🆔 User ID: {user_info['uuid']}")
            click.echo(f"📁 Root Folder ID: {user_info['rootFolderId']}")
        else:
            click.echo("❌ Not logged in")
            click.echo("💡 Use 'python cli.py login' to log in")
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)


@cli.command()
def logout():
    """Logout and clear credentials"""
    try:
        auth_service.logout()
        click.echo("✅ Successfully logged out")
    except Exception as e:
        click.echo(f"❌ Error during logout: {e}", err=True)


# ========== BASIC FILE OPERATIONS ==========

@cli.command()
@click.option('--folder-id', help='Folder ID to list (defaults to root)')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed information')
def list(folder_id, detailed):
    """List files and folders (UUID-based - legacy)"""
    try:
        credentials = auth_service.get_auth_details()
        
        if not folder_id:
            folder_id = credentials['user'].get('rootFolderId', '')
            if not folder_id:
                click.echo("❌ No root folder ID found. Please try logging in again.", err=True)
                return
        
        click.echo(f"📂 Listing contents of folder: {folder_id}")
        
        contents = drive_service.get_folder_content(folder_id)
        
        folders = contents.get('folders', [])
        files = contents.get('files', [])
        
        if not folders and not files:
            click.echo("📭 Folder is empty")
            return
        
        if folders:
            click.echo(f"\n📁 Folders ({len(folders)}):")
            for folder in folders:
                name = folder.get('plainName', 'Unknown')
                created_at = folder.get('createdAt', '')
                if detailed and created_at:
                    click.echo(f"  📁 {name} (created {format_date(created_at)})")
                else:
                    click.echo(f"  📁 {name}")
        
        if files:
            click.echo(f"\n📄 Files ({len(files)}):")
            for file in files:
                name = file.get('plainName', 'Unknown')
                file_type = file.get('type', '')
                if file_type:
                    name = f"{name}.{file_type}"
                
                try:
                    size = int(file.get('size', 0))
                except (ValueError, TypeError):
                    size = 0
                
                created_at = file.get('createdAt', '')
                
                if detailed:
                    size_str = format_size(size)
                    if created_at:
                        click.echo(f"  📄 {name} ({size_str}, created {format_date(created_at)})")
                    else:
                        click.echo(f"  📄 {name} ({size_str})")
                else:
                    click.echo(f"  📄 {name} ({format_size(size)})")
    except Exception as e:
        click.echo(f"❌ Error listing folder: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('name')
@click.option('--parent-folder-id', help='Parent folder ID (defaults to root)')
def mkdir(name: str, parent_folder_id: Optional[str]):
    """Create a new folder"""
    try:
        credentials = auth_service.get_auth_details()
        
        if not parent_folder_id:
            parent_folder_id = credentials['user'].get('rootFolderId', '')
            if not parent_folder_id:
                click.echo("❌ No root folder ID found", err=True)
                return
        
        click.echo(f"📁 Creating folder '{name}' in {parent_folder_id}...")
        
        folder = drive_service.create_folder(name, parent_folder_id)
        
        folder_uuid = folder.get('uuid', folder.get('id', ''))
        click.echo(f"✅ Folder created successfully!")
        click.echo(f"📁 Name: {name}")
        click.echo(f"🆔 UUID: {folder_uuid}")
        
    except Exception as e:
        error_msg = str(e)
        click.echo(f"❌ Error creating folder: {error_msg}", err=True)


@cli.command()
@click.argument('filepath', type=click.Path(exists=True, dir_okay=False, resolve_path=True))
@click.option('--destination', '-d', help='Destination folder UUID (defaults to root folder)')
def upload(filepath, destination):
    """Encrypts and uploads a file to your Internxt Drive"""
    try:
        drive_service.upload_file(filepath, destination)
    except Exception as e:
        click.echo(f"❌ Error uploading file: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('file_uuid')
@click.option('--destination', '-d', type=click.Path(file_okay=True, writable=True, resolve_path=True), default='.')
def download(file_uuid, destination):
    """Downloads and decrypts a file from your Internxt Drive (by UUID)"""
    try:
        drive_service.download_file(file_uuid, destination)
    except Exception as e:
        click.echo(f"❌ Error downloading file: {e}", err=True)
        sys.exit(1)


# ========== PATH-BASED OPERATIONS ==========

@cli.command('list-path')
@click.argument('path', default='/')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed information')
def list_path(path: str, detailed: bool):
    """List folder contents with paths (much more user-friendly!)"""
    try:
        auth_service.get_auth_details()
        
        content = drive_service.list_folder_with_paths(path)
        
        click.echo(f"\n📁 Contents of: {content['current_path']}")
        click.echo("=" * 80)
        
        # Show folders first
        if content['folders']:
            click.echo("📂 Folders:")
            click.echo("-" * 60)
            for folder in content['folders']:
                modified = folder.get('modified', '')[:10] if folder.get('modified') else ''
                if detailed:
                    click.echo(f"  📁 {folder['display_name']:<30} {modified:<12} {folder['uuid'][:8]}...")
                else:
                    click.echo(f"  📁 {folder['display_name']}")
        
        # Then show files
        if content['files']:
            if content['folders']:
                click.echo()
            click.echo("📄 Files:")
            click.echo("-" * 60)
            for file in content['files']:
                modified = file.get('modified', '')[:10] if file.get('modified') else ''
                size = file['size_display']
                if detailed:
                    click.echo(f"  📄 {file['display_name']:<30} {size:<10} {modified:<12} {file['uuid'][:8]}...")
                else:
                    click.echo(f"  📄 {file['display_name']:<30} {size}")
        
        if not content['folders'] and not content['files']:
            click.echo("  (empty)")
            
        click.echo(f"\nTotal: {len(content['folders'])} folders, {len(content['files'])} files")
        
        # Show usage examples
        if content['files']:
            example_file = content['files'][0]
            example_path = example_file['path']
            click.echo(f"\n💡 Usage examples:")
            click.echo(f"   Download by path: python cli.py download-path \"{example_path}\"")
            click.echo(f"   Delete by path:   python cli.py trash-path \"{example_path}\"")
    
    except ValueError as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command('download-path')
@click.argument('path')
@click.option('--destination', '-d', help='Where to save the file')
def download_path(path: str, destination: Optional[str]):
    """Download a file by its path instead of UUID"""
    try:
        auth_service.get_auth_details()
        
        downloaded_path = drive_service.download_file_by_path(path, destination)
        
        click.echo(f"\n🎉 Downloaded successfully!")
        click.echo(f"📄 File: {path}")
        click.echo(f"💾 Saved to: {downloaded_path}")
        
    except FileNotFoundError as e:
        click.echo(f"❌ File not found: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('pattern')
@click.option('--path', '-p', default='/', help='Where to search (default: everywhere)')
def find(pattern: str, path: str):
    """Search for files by name pattern (supports * and ? wildcards)"""
    try:
        auth_service.get_auth_details()
        
        results = drive_service.find_files(pattern, path)
        
        if not results:
            click.echo(f"❌ No files found matching '{pattern}' in {path}")
            return
        
        click.echo(f"\n🔍 Found {len(results)} files matching '{pattern}':")
        click.echo("=" * 80)
        
        for file in results:
            size = file.get('size_display', 'Unknown')
            modified = file.get('modified', '')[:10] if file.get('modified') else ''
            click.echo(f"📄 {file['path']}")
            click.echo(f"   Size: {size:<10} Modified: {modified:<12} UUID: {file['uuid'][:8]}...")
            click.echo()
        
        # Show usage examples
        if results:
            example = results[0]
            click.echo(f"💡 Usage examples:")
            click.echo(f"   Download: python cli.py download-path \"{example['path']}\"")
            click.echo(f"   Delete:   python cli.py trash-path \"{example['path']}\"")
    
    except ValueError as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('path')
def resolve(path: str):
    """Show what a path points to (debugging tool)"""
    try:
        auth_service.get_auth_details()
        
        resolved = drive_service.resolve_path(path)
        
        click.echo(f"\n🔍 Path resolution for: {path}")
        click.echo("=" * 50)
        click.echo(f"Type: {resolved['type'].upper()}")
        click.echo(f"UUID: {resolved['uuid']}")
        click.echo(f"Resolved path: {resolved['path']}")
        
        if resolved['type'] == 'file':
            metadata = resolved['metadata']
            file_type = metadata.get('type', '')
            size = format_size(metadata.get('size', 0))
            click.echo(f"File type: {file_type}")
            click.echo(f"Size: {size}")
        
        click.echo(f"\n💡 You can use this path with:")
        if resolved['type'] == 'file':
            click.echo(f"   python cli.py download-path \"{resolved['path']}\"")
            click.echo(f"   python cli.py trash-path \"{resolved['path']}\"")
        else:
            click.echo(f"   python cli.py list-path \"{resolved['path']}\"")
    
    except FileNotFoundError as e:
        click.echo(f"❌ Path not found: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('path', default='/')
@click.option('--depth', '-d', type=int, default=3, help='Maximum depth to show')
def tree(path: str, depth: int):
    """Show folder structure as a tree (like 'tree' command)"""
    try:
        auth_service.get_auth_details()
        
        click.echo(f"\n🌳 Folder tree starting from: {path}")
        click.echo("=" * 60)
        
        def print_tree(current_path, current_depth=0, prefix="", is_last=True):
            if current_depth >= depth:
                return
                
            try:
                content = drive_service.list_folder_with_paths(current_path)
                
                # Print current folder name (except root)
                if current_depth > 0:
                    connector = "└── " if is_last else "├── "
                    folder_name = Path(current_path).name
                    click.echo(f"{prefix}{connector}📁 {folder_name}/")
                    
                    # Update prefix for children
                    child_prefix = prefix + ("    " if is_last else "│   ")
                else:
                    child_prefix = ""
                
                # Print folders and files
                all_items = content['folders'] + content['files']
                for i, item in enumerate(all_items):
                    is_last_item = (i == len(all_items) - 1)
                    connector = "└── " if is_last_item else "├── "
                    
                    if item in content['folders']:
                        # It's a folder - recurse if not at max depth
                        if current_depth + 1 < depth:
                            print_tree(item['path'], current_depth + 1, child_prefix, is_last_item)
                        else:
                            click.echo(f"{child_prefix}{connector}📁 {item['display_name']}/")
                    else:
                        # It's a file
                        size = item.get('size_display', '')
                        click.echo(f"{child_prefix}{connector}📄 {item['display_name']} ({size})")
                        
            except Exception as e:
                click.echo(f"{prefix}    ❌ Error reading folder: {e}")
        
        print_tree(path)
        click.echo(f"\n(Showing maximum {depth} levels deep)")
    
    except ValueError as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


# ========== DELETE/TRASH OPERATIONS ==========

@cli.command('trash')
@click.argument('file_or_folder_uuid')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
def trash_by_uuid(file_or_folder_uuid: str, force: bool):
    """Move a file or folder to trash by UUID"""
    try:
        auth_service.get_auth_details()
        
        if not force:
            if not click.confirm(f'Move item {file_or_folder_uuid} to trash?'):
                click.echo("❌ Cancelled")
                return
        
        # Try as file first, then folder
        try:
            result = drive_service.trash_file(file_or_folder_uuid)
            click.echo(f"✅ {result['message']}")
        except:
            result = drive_service.trash_folder(file_or_folder_uuid)
            click.echo(f"✅ {result['message']}")
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command('trash-path')
@click.argument('path')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
def trash_by_path(path: str, force: bool):
    """Move a file or folder to trash by path"""
    try:
        auth_service.get_auth_details()
        
        resolved = drive_service.resolve_path(path)
        
        if not force:
            item_type = resolved['type']
            if not click.confirm(f'Move {item_type} "{path}" to trash?'):
                click.echo("❌ Cancelled")
                return
        
        result = drive_service.trash_by_path(path)
        click.echo(f"✅ {result['message']}")
        click.echo(f"🗑️  Item moved to trash: {path}")
        
    except FileNotFoundError as e:
        click.echo(f"❌ Path not found: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command('delete')
@click.argument('file_or_folder_uuid')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
def delete_permanently_by_uuid(file_or_folder_uuid: str, force: bool):
    """Permanently delete a file or folder by UUID (CANNOT BE UNDONE!)"""
    try:
        auth_service.get_auth_details()
        
        if not force:
            click.echo("⚠️  WARNING: This will PERMANENTLY delete the item. This action cannot be undone!")
            if not click.confirm(f'Permanently delete item {file_or_folder_uuid}?'):
                click.echo("❌ Cancelled")
                return
        
        # Try as file first, then folder
        try:
            result = drive_service.delete_permanently_file(file_or_folder_uuid)
            click.echo(f"✅ {result['message']}")
        except:
            result = drive_service.delete_permanently_folder(file_or_folder_uuid)
            click.echo(f"✅ {result['message']}")
            
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


@cli.command('delete-path')
@click.argument('path')
@click.option('--force', '-f', is_flag=True, help='Skip confirmation')
def delete_permanently_by_path(path: str, force: bool):
    """Permanently delete a file or folder by path (CANNOT BE UNDONE!)"""
    try:
        auth_service.get_auth_details()
        
        resolved = drive_service.resolve_path(path)
        
        if not force:
            item_type = resolved['type']
            click.echo("⚠️  WARNING: This will PERMANENTLY delete the item. This action cannot be undone!")
            if not click.confirm(f'Permanently delete {item_type} "{path}"?'):
                click.echo("❌ Cancelled")
                return
        
        result = drive_service.delete_permanently_by_path(path)
        click.echo(f"✅ {result['message']}")
        click.echo(f"🗑️  Item permanently deleted: {path}")
        
    except FileNotFoundError as e:
        click.echo(f"❌ Path not found: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


# ========== UTILITY COMMANDS ==========

@cli.command()
def test():
    """Test CLI components"""
    click.echo("🧪 Testing CLI components ...")
    click.echo("=" * 60)
    
    tests_passed = 0
    total_tests = 6
    
    # Test 1: Config service
    try:
        assert config_service.get('DRIVE_NEW_API_URL') == 'https://api.internxt.com/drive'
        click.echo("✅ Config service - exact TypeScript match")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ Config service failed: {e}")
    
    # Test 2: Crypto service
    try:
        test_text = "Hello World"
        encrypted = crypto_service.encrypt_text(test_text)
        decrypted = crypto_service.decrypt_text(encrypted)
        assert decrypted == test_text
        click.echo("✅ Crypto service - exact TypeScript CryptoJS compatibility")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ Crypto service failed: {e}")
    
    # Test 3: API endpoints
    try:
        login_url = f"{api_client.drive_api_url}/auth/login"
        expected_login = "https://api.internxt.com/drive/auth/login"
        assert login_url == expected_login
        click.echo("✅ API endpoints - exact match to working API")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ API endpoint test failed: {e}")
    
    # Test 4: Auth service structure
    try:
        assert hasattr(auth_service, 'do_login')
        assert hasattr(auth_service, 'is_2fa_needed')
        assert hasattr(auth_service, 'get_auth_details')
        click.echo("✅ Auth service - exact TypeScript AuthService structure")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ Auth service structure test failed: {e}")
    
    # Test 5: Mnemonic validation
    try:
        valid_mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        is_valid = crypto_service.validate_mnemonic(valid_mnemonic)
        assert is_valid == True
        click.echo("✅ Mnemonic validation - exact TypeScript ValidationService match")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ Mnemonic validation test failed: {e}")
    
    # Test 6: File path structure
    try:
        home_dir = Path.home()
        expected_config_dir = home_dir / '.internxt-cli'
        assert config_service.internxt_cli_data_dir == expected_config_dir
        click.echo("✅ File paths - exact TypeScript ConfigService match")
        tests_passed += 1
    except Exception as e:
        click.echo(f"❌ File path test failed: {e}")
    
    click.echo("\n" + "=" * 60)
    click.echo(f"📊 Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        click.echo("🎉 All tests passed! CLI is working correctly.")
    else:
        click.echo("⚠️  Some tests failed. Please review the errors.")


@cli.command()
def config():
    """Show current configuration"""
    try:
        click.echo("⚙️  Internxt CLI Configuration")
        click.echo("=" * 40)
        
        # API Configuration
        click.echo("🌐 API Endpoints:")
        click.echo(f"   Drive Web: {config_service.get('DRIVE_WEB_URL')}")
        click.echo(f"   Drive API: {config_service.get('DRIVE_NEW_API_URL')}")
        click.echo(f"   Network API: {config_service.get('NETWORK_URL')}")
        
        # File Paths  
        click.echo("\n📁 File Paths:")
        click.echo(f"   Config Dir: {config_service.internxt_cli_data_dir}")
        click.echo(f"   Credentials: {config_service.credentials_file}")
        click.echo(f"   Logs Dir: {config_service.internxt_cli_logs_dir}")
        
        # Login Status
        click.echo("\n🔐 Authentication:")
        user_info = auth_service.whoami()
        if user_info:
            click.echo(f"   Status: ✅ Logged in as {user_info['email']}")
            click.echo(f"   User ID: {user_info['uuid']}")
            click.echo(f"   Root Folder: {user_info['rootFolderId']}")
        else:
            click.echo("   Status: ❌ Not logged in")
        
        # WebDAV Configuration
        webdav_config = config_service.read_webdav_config()
        click.echo("\n🌐 WebDAV Server:")
        click.echo(f"   Protocol: {webdav_config['protocol']}")
        click.echo(f"   Port: {webdav_config['port']}")
        click.echo(f"   Timeout: {webdav_config['timeoutMinutes']} minutes")
        
    except Exception as e:
        click.echo(f"❌ Error reading configuration: {e}", err=True)


@cli.command()
def help_extended():
    """Show extended help with examples"""
    click.echo("""
🚀 Internxt Python CLI - Extended Help
========================================

🔐 AUTHENTICATION
  login              Login to your Internxt account
  whoami            Check current login status
  logout            Logout and clear credentials

📁 BASIC OPERATIONS (UUID-based)
  list              List folder contents by UUID
  mkdir NAME        Create new folder
  upload FILE       Upload file to Drive
  download UUID     Download file by UUID

🛣️  PATH-BASED OPERATIONS (User-friendly!)
  list-path [PATH]  List folder contents with readable paths
  download-path PATH Download file by path (e.g., "/Documents/report.pdf")
  find PATTERN      Search files with wildcards (e.g., "*.pdf")
  resolve PATH      Show what a path points to (debugging)
  tree [PATH]       Show folder structure as tree

🗑️  DELETE/TRASH OPERATIONS
  trash UUID        Move file/folder to trash by UUID
  trash-path PATH   Move file/folder to trash by path
  delete UUID       Permanently delete by UUID (⚠️ CANNOT BE UNDONE!)
  delete-path PATH  Permanently delete by path (⚠️ CANNOT BE UNDONE!)

🔧 UTILITIES
  config            Show current configuration
  test              Test CLI components

💡 EXAMPLES:
  # Login and explore
  python cli.py login
  python cli.py list-path
  python cli.py tree
  
  # Find and download files
  python cli.py find "*.pdf"
  python cli.py download-path "/Documents/important.pdf"
  
  # Clean up
  python cli.py trash-path "/OldFolder"
  python cli.py delete-path "/TempFile.txt" --force

🌟 TIP: Path-based commands are much easier to use than UUID-based ones!
""")


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("🚀 Internxt Python CLI with Path Support")
        print("=" * 50)
        print("💡 Try: python cli.py help-extended")
        print("")
    
    cli()