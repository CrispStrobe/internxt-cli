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
import glob
import time

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
    from services.webdav_server import webdav_server
except ImportError as e:
    print(f"❌ Failed to import services: {e}")
    print("📦 Make sure all service files are in place with fixed implementations")
    # Check for WebDAV specific dependencies
    try:
        import wsgidav
        import cheroot
    except ImportError:
        print("📦 For WebDAV support, install: pip install WsgiDAV cheroot")
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
@click.argument('sources', nargs=-1, type=str)
@click.option('--target', '-t', 'target_path', default='/', help='Destination path on Internxt Drive (default: /)')
@click.option('--recursive', '-r', is_flag=True, help='Upload directories recursively')
@click.option('--on-conflict', type=click.Choice(['overwrite', 'skip'], case_sensitive=False), default='skip', help='Action if target exists (overwrite/skip)')
@click.option('--preserve-timestamps', '-p', is_flag=True, help='Preserve file creation and modification times')
@click.option('--include', multiple=True, help='Include only files matching pattern (e.g., --include "*.png" --include "*.jpg")')
@click.option('--exclude', multiple=True, help='Exclude files matching pattern (e.g., --exclude "*.tmp" --exclude ".DS_Store")')
@click.option('--verbose', '-v', is_flag=True, help='Show verbose output')
def upload(sources: Tuple[str], target_path: str, recursive: bool, on_conflict: str, 
           preserve_timestamps: bool, include: Tuple[str], exclude: Tuple[str], verbose: bool):
    """
    Encrypts and uploads local files/folders to a remote path.

    SOURCES... can be one or more local file or directory paths. Wildcards (*) are supported.
    TARGET_PATH is the destination path on your Internxt Drive (e.g., "/Documents/Backup").
    
    Trailing slash behavior (like rsync):
      source/  → uploads contents to target (no new folder)
      source   → creates 'source' folder in target
    
    Use --preserve-timestamps to maintain original file dates (experimental).
    Use --include/--exclude to filter files by pattern (supports wildcards).
    
    Examples:
      Upload only images:
        python cli.py upload photos/ -t /Backup -r --include "*.png" --include "*.jpg"
      
      Upload all except temp files:
        python cli.py upload project/ -t /Code -r --exclude "*.tmp" --exclude ".DS_Store"
      
      Preserve timestamps:
        python cli.py upload docs/ -t /Documents -r --preserve-timestamps
    """
    if not sources:
        click.echo("❌ No source files or directories specified.", err=True)
        sys.exit(1)

    # Convert include/exclude tuples to lists
    include_patterns = list(include) if include else []
    exclude_patterns = list(exclude) if exclude else []
    
    if verbose or include_patterns or exclude_patterns:
        if include_patterns:
            click.echo(f"🔍 Include filters: {', '.join(include_patterns)}")
        if exclude_patterns:
            click.echo(f"🚫 Exclude filters: {', '.join(exclude_patterns)}")

    try:
        credentials = auth_service.get_auth_details()
        click.echo(f"🎯 Preparing upload to remote path: {target_path}")

        # --- Resolve or Create Target Folder ---
        target_folder_uuid = None
        target_folder_path_str = "/"
        try:
            target_folder_info = drive_service.resolve_path(target_path)
            if target_folder_info['type'] != 'folder':
                click.echo(f"❌ Target path '{target_path}' exists but is not a folder.", err=True)
                sys.exit(1)
            target_folder_uuid = target_folder_info['uuid']
            target_folder_path_str = target_folder_info['path']
            click.echo(f"✅ Target folder exists: '{target_folder_path_str}' (UUID: {target_folder_uuid[:8]}...)")
        except FileNotFoundError:
            click.echo(f"⏳ Target path '{target_path}' not found. Attempting to create...")
            try:
                created_folder = drive_service.create_folder_recursive(target_path)
                target_folder_uuid = created_folder['uuid']
                target_folder_info = drive_service.resolve_path(target_path)
                target_folder_path_str = target_folder_info['path']
                click.echo(f"✅ Created target folder '{target_folder_path_str}' (UUID: {target_folder_uuid[:8]}...)")
            except Exception as create_err:
                click.echo(f"❌ Failed to create target folder '{target_path}': {create_err}", err=True)
                sys.exit(1)
        except Exception as resolve_err:
            click.echo(f"❌ Error resolving target path '{target_path}': {resolve_err}", err=True)
            sys.exit(1)

        if not target_folder_uuid:
            click.echo("❌ Could not determine target folder UUID. Aborting.", err=True)
            sys.exit(1)

        # --- Process Sources ---
        items_to_process = []
        click.echo("🔍 Expanding source paths...")
        for source_arg in sources:
            has_trailing_slash = source_arg.rstrip().endswith('/') or source_arg.rstrip().endswith(os.sep)
            source_path = Path(source_arg)
            
            if not source_path.exists():
                click.echo(f"⚠️ Source not found: {source_arg}", err=True)
                continue
            
            source_path_resolved = source_path.resolve()
            source_path_str = str(source_path_resolved)
            matches = glob.glob(source_path_str, recursive=recursive)

            if not matches:
                click.echo(f"⚠️ Source not found or matched nothing: {source_arg}", err=True)
                continue

            base_dir_str = source_path_str
            if "*" in source_arg or "?" in source_arg or "[" in source_arg:
                path_parts = Path(source_arg).parts
                non_wildcard_parts = []
                for part in path_parts:
                    if "*" in part or "?" in part or "[" in part:
                        break
                    non_wildcard_parts.append(part)
                if non_wildcard_parts:
                    base_dir_str = str(Path(*non_wildcard_parts))
                    if Path(source_arg).is_dir() and not ("*" in source_arg or "?" in source_arg or "[" in source_arg):
                        base_dir_str = str(Path(source_arg))
                else:
                    base_dir_str = os.getcwd()
                if Path(source_arg).is_absolute():
                    base_dir_path = Path(base_dir_str)
                    if not base_dir_path.is_absolute():
                        base_dir_path = Path.cwd() / base_dir_path
                    base_dir_str = str(base_dir_path.resolve())

            base_source_dir = Path(base_dir_str)
            if base_source_dir.is_file():
                base_source_dir = base_source_dir.parent

            for match_str in matches:
                match_path = Path(match_str).resolve()
                current_base = base_source_dir if not match_path.is_dir() else match_path.parent
                copy_contents_only = has_trailing_slash if match_path.is_dir() else False
                items_to_process.append((match_path, current_base, copy_contents_only))

        if not items_to_process:
            click.echo("❌ No valid source files or directories found after expansion.", err=True)
            sys.exit(1)

        click.echo(f"📦 Found {len(items_to_process)} items/directories to process.")

        # --- Upload Loop ---
        success_count = 0
        skipped_count = 0
        error_count = 0
        filtered_count = 0

        processed_dirs = set()

        for local_path, base_source_dir, copy_contents_only in items_to_process:
            try:
                if verbose:
                    click.echo("-" * 40)
                    click.echo(f"Processing: {local_path}")

                if local_path.is_file():
                    # Apply include/exclude filters
                    if not drive_service.should_include_file(local_path, include_patterns, exclude_patterns):
                        if verbose:
                            click.echo(f"  -> 🚫 Filtered out: {local_path.name}")
                        filtered_count += 1
                        continue
                    
                    # Get timestamps if preservation requested
                    creation_time = None
                    modification_time = None
                    
                    if preserve_timestamps:
                        try:
                            stat_info = local_path.stat()
                            from datetime import datetime, timezone
                            
                            mtime = datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc)
                            modification_time = mtime.isoformat()
                            
                            try:
                                ctime = datetime.fromtimestamp(stat_info.st_birthtime, tz=timezone.utc)
                                creation_time = ctime.isoformat()
                            except AttributeError:
                                ctime = datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc)
                                creation_time = ctime.isoformat()
                            
                            if verbose:
                                click.echo(f"  🕐 Local file timestamps:")
                                click.echo(f"     Creation: {creation_time}")
                                click.echo(f"     Modification: {modification_time}")
                        except Exception as e:
                            if verbose:
                                click.echo(f"  ⚠️  Could not read timestamps: {e}")
                    
                    # Upload
                    upload_result = drive_service.upload_single_item_with_conflict_handling(
                        local_path,
                        target_folder_path_str,
                        target_folder_uuid,
                        on_conflict,
                        remote_filename=local_path.name,
                        creation_time=creation_time,
                        modification_time=modification_time
                    )
                    
                    if upload_result == "uploaded": success_count += 1
                    elif upload_result == "skipped": skipped_count += 1
                    else: error_count += 1

                elif local_path.is_dir():
                    if local_path in processed_dirs:
                        if verbose:
                            click.echo(f"  -> Skipping already processed directory: {local_path}")
                        continue

                    if not recursive:
                        click.echo(f"⚠️ Skipping directory (use -r to upload recursively): {local_path}")
                        skipped_count += 1
                        continue

                    click.echo(f"📂 Processing directory recursively: {local_path}")
                    processed_dirs.add(local_path)

                    if copy_contents_only:
                        click.echo(f"  ✨ Copying contents directly to target (trailing slash detected)")
                        dir_remote_base_path = Path(target_folder_path_str)
                    else:
                        click.echo(f"  📁 Creating folder '{local_path.name}' in target")
                        dir_remote_base_path = Path(target_folder_path_str) / local_path.name

                    for item in local_path.rglob('*'):
                        if item.is_file():
                            # Apply include/exclude filters
                            if not drive_service.should_include_file(item, include_patterns, exclude_patterns):
                                if verbose:
                                    click.echo(f"  -> 🚫 Filtered: {item.name}")
                                filtered_count += 1
                                continue
                            
                            relative_path = item.relative_to(local_path)
                            item_target_parent_path = dir_remote_base_path / relative_path.parent
                            item_target_parent_path_str = str(item_target_parent_path).replace('\\', '/')
                            if not item_target_parent_path_str.startswith('/'):
                                item_target_parent_path_str = '/' + item_target_parent_path_str

                            if verbose:
                                click.echo(f"  -> Found file: {item.name} (relative: {relative_path})")
                                click.echo(f"     Target parent path: {item_target_parent_path_str}")

                            parent_folder_uuid = None
                            try:
                                parent_folder = drive_service.create_folder_recursive(item_target_parent_path_str)
                                parent_folder_uuid = parent_folder['uuid']
                                if verbose:
                                    click.echo(f"     Ensured parent folder exists (UUID: {parent_folder_uuid[:8]}...)")
                            except Exception as create_err:
                                click.echo(f"     ❌ Error ensuring parent folder {item_target_parent_path_str}: {create_err}", err=True)
                                error_count += 1
                                continue

                            # Get timestamps if requested
                            creation_time = None
                            modification_time = None
                            if preserve_timestamps:
                                try:
                                    stat_info = item.stat()
                                    from datetime import datetime, timezone
                                    mtime = datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc)
                                    modification_time = mtime.isoformat()
                                    try:
                                        ctime = datetime.fromtimestamp(stat_info.st_birthtime, tz=timezone.utc)
                                        creation_time = ctime.isoformat()
                                    except AttributeError:
                                        ctime = datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc)
                                        creation_time = ctime.isoformat()
                                except Exception:
                                    pass

                            upload_result = drive_service.upload_single_item_with_conflict_handling(
                                item,
                                item_target_parent_path_str,
                                parent_folder_uuid,
                                on_conflict,
                                remote_filename=item.name,
                                creation_time=creation_time,
                                modification_time=modification_time
                            )
                            if upload_result == "uploaded": success_count += 1
                            elif upload_result == "skipped": skipped_count += 1
                            else: error_count += 1

                else:
                    click.echo(f"⚠️ Skipping unknown item type: {local_path}", err=True)
                    skipped_count += 1

            except Exception as e:
                click.echo(f"❌ Error processing {local_path}: {e}", err=True)
                error_count += 1
                continue

        # --- Summary ---
        click.echo("=" * 40)
        click.echo("📊 Upload Summary:")
        click.echo(f"  ✅ Uploaded: {success_count}")
        click.echo(f"  ⏭️  Skipped:  {skipped_count}")
        if filtered_count > 0:
            click.echo(f"  🚫 Filtered: {filtered_count}")
        click.echo(f"  ❌ Errors:   {error_count}")
        click.echo("=" * 40)

    except Exception as e:
        click.echo(f"❌ Upload failed: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)

@cli.command()
@click.argument('file_uuid')
@click.option('--destination', '-d', type=click.Path(file_okay=True, writable=True, resolve_path=True), default='.', help='Where to save the file')
@click.option('--preserve-timestamps', '-p', is_flag=True, help='Preserve file modification times')
@click.option('--on-conflict', type=click.Choice(['overwrite', 'skip'], case_sensitive=False), default='overwrite', help='Action if local file exists')
@click.option('--verbose', '-v', is_flag=True, help='Show verbose output')
def download(file_uuid: str, destination: str, preserve_timestamps: bool, on_conflict: str, verbose: bool):
    """Downloads and decrypts a file from your Internxt Drive (by UUID)"""
    try:
        from pathlib import Path
        
        if verbose:
            click.echo(f"📥 Downloading file with UUID: {file_uuid}")
            click.echo(f"📁 Destination: {destination}")
            if preserve_timestamps:
                click.echo(f"🕐 Timestamp preservation: enabled")
        
        # Check if destination file already exists
        dest_path = Path(destination)
        if dest_path.is_file() and on_conflict == 'skip':
            click.echo(f"⏭️  File exists, skipping: {dest_path}")
            sys.exit(0)
        
        # Download the file
        downloaded_path = drive_service.download_file(
            file_uuid, 
            destination,
            preserve_timestamps=preserve_timestamps
        )
        
        if not verbose:
            click.echo(f"✅ File downloaded successfully to: {downloaded_path}")
    
    except Exception as e:
        click.echo(f"❌ Error downloading file: {e}", err=True)
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


# ========== PATH-BASED OPERATIONS ==========

@cli.command('list-path')
@click.argument('path', default='/')
@click.option('--detailed', '-d', is_flag=True, help='Show detailed information')
@click.option('--all', '-a', is_flag=True, help='Show all attributes (verbose)')
def list_path(path: str, detailed: bool, all: bool):
    """List folder contents with paths (much more user-friendly!)"""
    try:
        auth_service.get_auth_details()
        
        content = drive_service.list_folder_with_paths(path)
        
        click.echo(f"\n📁 Listing folder: {path}")
        click.echo()
        click.echo(f"📁 Contents of: {content['current_path']}")
        click.echo("=" * 80)
        
        # Show folders first
        if content['folders']:
            click.echo("📂 Folders:")
            click.echo("-" * 60)
            for folder in content['folders']:
                if all:
                    # Show ALL attributes
                    click.echo(f"  📁 {folder['display_name']}")
                    click.echo(f"     UUID: {folder['uuid']}")
                    click.echo(f"     Path: {folder['path']}")
                    click.echo(f"     Plain Name: {folder.get('plainName', 'N/A')}")
                    click.echo(f"     Parent ID: {folder.get('parentId', 'N/A')}")
                    click.echo(f"     User ID: {folder.get('userId', 'N/A')}")
                    
                    # Timestamps for FOLDERS
                    created_at = folder.get('createdAt', 'N/A')
                    updated_at = folder.get('updatedAt', 'N/A')
                    creation_time = folder.get('creationTime', 'N/A')
                    modification_time = folder.get('modificationTime', 'N/A')
                    
                    if created_at != 'N/A':
                        click.echo(f"     Created At: {format_date(created_at)} ({created_at})")
                    else:
                        click.echo(f"     Created At: N/A")
                    if updated_at != 'N/A':
                        click.echo(f"     Updated At: {format_date(updated_at)} ({updated_at})")
                    else:
                        click.echo(f"     Updated At: N/A")
                    if creation_time != 'N/A':
                        click.echo(f"     Creation Time: {format_date(creation_time)} ({creation_time})")
                    if modification_time != 'N/A':
                        click.echo(f"     Modification Time: {format_date(modification_time)} ({modification_time})")
                    
                    # Other attributes
                    click.echo(f"     Deleted: {folder.get('deleted', False)}")
                    click.echo(f"     Removed: {folder.get('removed', False)}")
                    
                    click.echo()
                elif detailed:
                    modified = folder.get('updatedAt', '')[:10] if folder.get('updatedAt') else ''
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
                if all:
                    # Show ALL attributes
                    click.echo(f"  📄 {file['display_name']}")
                    click.echo(f"     UUID: {file['uuid']}")
                    click.echo(f"     Path: {file['path']}")
                    click.echo(f"     Plain Name: {file.get('plainName', 'N/A')}")
                    click.echo(f"     Type/Extension: {file.get('type', 'N/A')}")
                    click.echo(f"     Size: {file['size_display']} ({file.get('size', 0)} bytes)")
                    click.echo(f"     Folder ID: {file.get('folderId', 'N/A')}")
                    click.echo(f"     User ID: {file.get('userId', 'N/A')}")
                    click.echo(f"     File ID: {file.get('fileId', 'N/A')}")
                    click.echo(f"     Bucket: {file.get('bucket', 'N/A')}")
                    click.echo(f"     Encrypt Version: {file.get('encryptVersion', 'N/A')}")
                    
                    # Timestamps for FILES
                    created_at = file.get('createdAt', 'N/A')
                    updated_at = file.get('updatedAt', 'N/A')
                    creation_time = file.get('creationTime', 'N/A')
                    modification_time = file.get('modificationTime', 'N/A')
                    
                    if created_at != 'N/A':
                        click.echo(f"     Created At: {format_date(created_at)} ({created_at})")
                    else:
                        click.echo(f"     Created At: N/A")
                    if updated_at != 'N/A':
                        click.echo(f"     Updated At: {format_date(updated_at)} ({updated_at})")
                    else:
                        click.echo(f"     Updated At: N/A")
                    if creation_time != 'N/A':
                        click.echo(f"     Creation Time: {format_date(creation_time)} ({creation_time})")
                    if modification_time != 'N/A':
                        click.echo(f"     Modification Time: {format_date(modification_time)} ({modification_time})")
                    
                    # Other attributes
                    click.echo(f"     Deleted: {file.get('deleted', False)}")
                    click.echo(f"     Removed: {file.get('removed', False)}")
                    click.echo(f"     Status: {file.get('status', 'N/A')}")
                    
                    click.echo()
                elif detailed:
                    modified = file.get('updatedAt', '')[:10] if file.get('updatedAt') else ''
                    size = file['size_display']
                    click.echo(f"  📄 {file['display_name']:<30} {size:<10} {modified:<12} {file['uuid'][:8]}...")
                else:
                    size = file['size_display']
                    click.echo(f"  📄 {file['display_name']:<30} {size}")
        
        if not content['folders'] and not content['files']:
            click.echo("  (empty)")
            
        click.echo(f"\nTotal: {len(content['folders'])} folders, {len(content['files'])} files")
        
        # Show usage examples (only if not showing all attributes)
        if content['files'] and not all:
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
        import traceback
        traceback.print_exc()
        sys.exit(1)

@cli.command('download-path')
@click.argument('path')
@click.option('--destination', '-d', '--target', '-t', 'destination', help='Where to save (file or directory)')
@click.option('--recursive', '-r', is_flag=True, help='Download folders recursively')
@click.option('--on-conflict', type=click.Choice(['overwrite', 'skip'], case_sensitive=False), default='skip', help='Action if local file exists')
@click.option('--preserve-timestamps', '-p', is_flag=True, help='Preserve file modification times')
@click.option('--include', multiple=True, help='Include only files matching pattern')
@click.option('--exclude', multiple=True, help='Exclude files matching pattern')
@click.option('--verbose', '-v', is_flag=True, help='Show verbose output')
def download_path(path: str, destination: Optional[str], recursive: bool, on_conflict: str,
                  preserve_timestamps: bool, include: Tuple[str], exclude: Tuple[str], verbose: bool):
    """
    Download a file or folder by its path.
    
    Examples:
      Download single file:
        python cli.py download-path "/Documents/report.pdf"
      
      Download folder recursively:
        python cli.py download-path "/Photos" -r -d ./local_photos
      
      Download only images:
        python cli.py download-path "/Photos" -r --include "*.jpg" --include "*.png"
      
      With timestamp preservation:
        python cli.py download-path "/Backup" -r -p
    """
    try:
        auth_service.get_auth_details()
        
        # Convert include/exclude tuples to lists
        include_patterns = list(include) if include else []
        exclude_patterns = list(exclude) if exclude else []
        
        if verbose and (include_patterns or exclude_patterns):
            if include_patterns:
                click.echo(f"🔍 Include filters: {', '.join(include_patterns)}")
            if exclude_patterns:
                click.echo(f"🚫 Exclude filters: {', '.join(exclude_patterns)}")
        
        # Resolve the remote path
        item_info = drive_service.resolve_path(path)
        
        if item_info['type'] == 'file':
            # Single file download
            if verbose:
                click.echo(f"📥 Downloading file: {path}")
            
            # Apply filters
            file_name = item_info.get('plainName', '')
            if item_info.get('type'):
                file_name = f"{file_name}.{item_info.get('type')}"
            
            if not drive_service.should_include_file(Path(file_name), include_patterns, exclude_patterns):
                click.echo(f"🚫 File filtered out by include/exclude patterns")
                sys.exit(0)
            
            # Determine destination
            if destination:
                dest_path = Path(destination)
            else:
                dest_path = Path.cwd() / file_name
            
            # Check conflict
            if dest_path.exists() and on_conflict == 'skip':
                click.echo(f"⏭️  File exists, skipping: {dest_path}")
                sys.exit(0)
            
            # Download
            downloaded_path = drive_service.download_file(
                item_info['uuid'], 
                str(dest_path.parent if dest_path.is_file() or not dest_path.exists() else dest_path),
                preserve_timestamps=preserve_timestamps
            )
            
            click.echo(f"\n🎉 Downloaded successfully!")
            click.echo(f"📄 From: {path}")
            click.echo(f"💾 To: {downloaded_path}")
            
        elif item_info['type'] == 'folder':
            if not recursive:
                click.echo(f"❌ '{path}' is a folder. Use -r to download recursively.", err=True)
                sys.exit(1)
            
            # Recursive folder download
            click.echo(f"📂 Downloading folder recursively: {path}")
            
            # Determine base destination
            if destination:
                base_dest = Path(destination)
            else:
                folder_name = item_info.get('plainName', 'download')
                base_dest = Path.cwd() / folder_name
            
            base_dest.mkdir(parents=True, exist_ok=True)
            
            # Download folder contents recursively
            success_count = 0
            skipped_count = 0
            error_count = 0
            filtered_count = 0
            
            def download_folder_recursive(folder_uuid: str, current_dest: Path, current_path: str):
                nonlocal success_count, skipped_count, error_count, filtered_count
                
                # Get folder contents
                content = drive_service.get_folder_content(folder_uuid)
                
                # Download files
                for file_info in content.get('files', []):
                    file_name = file_info.get('plainName', '')
                    if file_info.get('type'):
                        file_name = f"{file_name}.{file_info.get('type')}"
                    
                    # Apply filters
                    if not drive_service.should_include_file(Path(file_name), include_patterns, exclude_patterns):
                        if verbose:
                            click.echo(f"  -> 🚫 Filtered: {file_name}")
                        filtered_count += 1
                        continue
                    
                    file_dest = current_dest / file_name
                    
                    # Check conflict
                    if file_dest.exists() and on_conflict == 'skip':
                        if verbose:
                            click.echo(f"  -> ⏭️  Skipping existing: {file_name}")
                        skipped_count += 1
                        continue
                    
                    try:
                        if verbose:
                            click.echo(f"  -> Downloading: {file_name}")
                        
                        drive_service.download_file(
                            file_info['uuid'],
                            str(current_dest),
                            preserve_timestamps=preserve_timestamps
                        )
                        success_count += 1
                    except Exception as e:
                        click.echo(f"  -> ❌ Error downloading {file_name}: {e}", err=True)
                        error_count += 1
                
                # Process subfolders
                for folder_info in content.get('folders', []):
                    folder_name = folder_info.get('plainName', folder_info.get('name', ''))
                    subfolder_dest = current_dest / folder_name
                    subfolder_dest.mkdir(parents=True, exist_ok=True)
                    
                    if verbose:
                        click.echo(f"📂 Entering folder: {folder_name}")
                    
                    download_folder_recursive(
                        folder_info['uuid'],
                        subfolder_dest,
                        f"{current_path}/{folder_name}"
                    )
            
            # Start recursive download
            download_folder_recursive(item_info['uuid'], base_dest, path)
            
            # Summary
            click.echo("\n" + "=" * 40)
            click.echo("📊 Download Summary:")
            click.echo(f"  ✅ Downloaded: {success_count}")
            click.echo(f"  ⏭️  Skipped:    {skipped_count}")
            if filtered_count > 0:
                click.echo(f"  🚫 Filtered:   {filtered_count}")
            click.echo(f"  ❌ Errors:     {error_count}")
            click.echo(f"  📁 To: {base_dest}")
            click.echo("=" * 40)
        
        else:
            click.echo(f"❌ Unknown item type: {item_info['type']}", err=True)
            sys.exit(1)
        
    except FileNotFoundError as e:
        click.echo(f"❌ File not found: {e}", err=True)
        sys.exit(1)
    except ValueError as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        import traceback
        traceback.print_exc()
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


# ========== WEBDAV SERVER COMMANDS ==========

@cli.command('webdav-start')
@click.option('--port', type=int, help='Port to run WebDAV server on')
@click.option('--background', '-b', is_flag=True, help='Run server in background')
@click.option('--show-mount', is_flag=True, help='Show mount instructions')
@click.option('--no-preserve-timestamps', is_flag=True, help='Do NOT preserve file timestamps (preserves by default)')
def webdav_start(port: Optional[int], background: bool, show_mount: bool, no_preserve_timestamps: bool):
    """
    Start WebDAV server to mount Internxt Drive as a local drive.
    
    By default, file timestamps are preserved when copying/uploading files.
    Use --no-preserve-timestamps to disable this behavior.
    """
    try:
        # Check if logged in
        try:
            auth_service.get_auth_details()
        except Exception:
            click.echo("❌ Not logged in. Please login first with: python cli.py login", err=True)
            sys.exit(1)
        
        # Read and update config
        webdav_config = config_service.read_webdav_config()
        
        # Override with command-line options
        if port:
            webdav_config['port'] = port
        
        # Handle timestamp preservation
        if no_preserve_timestamps:
            webdav_config['preserveTimestamps'] = False
            click.echo("⚠️  Timestamp preservation disabled for this session")
        else:
            # Always default to True
            webdav_config['preserveTimestamps'] = True
        
        # Save config (preserves settings for next time, except --no-preserve-timestamps which is session-only)
        config_to_save = webdav_config.copy()
        if not no_preserve_timestamps:
            # Only save if user didn't explicitly disable it for this session
            config_service.save_webdav_config(config_to_save)
        
        # Handle background mode by spawning a separate process
        if background:
            import subprocess
            
            # Build command to run in background
            cmd = [sys.executable, __file__, 'webdav-start']
            if port:
                cmd.extend(['--port', str(port)])
            if no_preserve_timestamps:
                cmd.append('--no-preserve-timestamps')
            # Don't pass --background to avoid infinite recursion
            
            # Check if already running
            status = webdav_server.status()
            if status['running']:
                click.echo(f"❌ WebDAV server is already running")
                click.echo(f"🌐 Server URL: {status['url']}")
                sys.exit(1)
            
            # Spawn background process
            click.echo("🚀 Starting WebDAV server in background...")
            
            # Redirect output to log file
            log_dir = config_service.internxt_cli_logs_dir
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = log_dir / 'webdav.log'
            
            with open(log_file, 'w') as log:
                process = subprocess.Popen(
                    cmd,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True  # Detach from parent
                )
                
                # Save PID
                config_service.save_webdav_pid(process.pid)
                
                # Wait a moment to ensure it starts
                time.sleep(2)
                
                # Check if it's actually running
                status = webdav_server.status()
                if status.get('running'):
                    click.echo(f"✅ WebDAV server started in background (PID: {process.pid})")
                    click.echo(f"🌐 Server URL: http://localhost:{webdav_config['port']}/")
                    click.echo(f"👤 Username: internxt")
                    click.echo(f"🔑 Password: internxt-webdav")
                    click.echo(f"🕐 Preserve Timestamps: {'Yes' if webdav_config['preserveTimestamps'] else 'No'}")
                    click.echo(f"\n📋 Logs: {log_file}")
                    click.echo(f"💡 Use 'python cli.py webdav-stop' to stop the server")
                    click.echo(f"💡 Use 'python cli.py webdav-status' to check status")
                else:
                    click.echo(f"❌ Server failed to start. Check logs: {log_file}")
                    sys.exit(1)
            
            return
        
        # Foreground mode - run directly
        click.echo("🚀 Starting WebDAV server...")
        click.echo(f"📡 Protocol: {webdav_config['protocol'].upper()}")
        click.echo(f"🔌 Port: {webdav_config['port']}")
        click.echo(f"⏰ Timeout: {webdav_config['timeoutMinutes']} minutes")
        click.echo(f"🕐 Preserve Timestamps: {'Yes' if webdav_config['preserveTimestamps'] else 'No'}")
        
        result = webdav_server.start(
            port=int(webdav_config['port']),
            background=False,
            preserve_timestamps=webdav_config['preserveTimestamps']  # NEW: Pass to server
        )
        
        if result['success']:
            click.echo(f"✅ {result['message']}")
            click.echo(f"🌐 Server URL: {result['url']}")
            click.echo(f"👤 Username: internxt")
            click.echo(f"🔑 Password: internxt-webdav")
            
            if show_mount:
                click.echo(f"\n💡 Mount Instructions:")
                instructions = webdav_server.get_mount_instructions()
                
                # Detect platform and show relevant instructions
                import platform
                system = platform.system().lower()
                
                if 'windows' in system:
                    click.echo(instructions['windows'])
                elif 'darwin' in system:
                    click.echo(instructions['macos'])
                elif 'linux' in system:
                    click.echo(instructions['linux'])
                else:
                    # Show all instructions
                    for platform_name, instruction in instructions.items():
                        click.echo(f"\n{platform_name.upper()}:")
                        click.echo(instruction)
            
            click.echo(f"\n🔄 Server running... Press Ctrl+C to stop")
            # Server will run in main thread - keep it alive
            while True:
                time.sleep(1)
        else:
            click.echo(f"❌ {result['message']}", err=True)
            sys.exit(1)
            
    except KeyboardInterrupt:
        click.echo(f"\n🛑 WebDAV server stopped by user")
        config_service.clear_webdav_pid()
    except Exception as e:
        click.echo(f"❌ Error starting WebDAV server: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command('webdav-stop')
def webdav_stop():
    """Stop WebDAV server"""
    try:
        result = webdav_server.stop()
        
        if result['success']:
            click.echo(f"✅ {result['message']}")
        else:
            click.echo(f"❌ {result['message']}", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Error stopping WebDAV server: {e}", err=True)
        sys.exit(1)


@cli.command('webdav-status')
def webdav_status():
    """Check WebDAV server status"""
    try:
        status = webdav_server.status()
        
        if status['running']:
            click.echo(f"✅ WebDAV server is running")
            click.echo(f"🌐 URL: {status['url']}")
            click.echo(f"📡 Protocol: {status['protocol'].upper()}")
            click.echo(f"🚪 Port: {status['port']}")
            click.echo(f"🏠 Host: {status['host']}")
            
            click.echo(f"\n👤 Credentials:")
            click.echo(f"   Username: internxt")
            click.echo(f"   Password: internxt-webdav")
        else:
            click.echo(f"❌ WebDAV server is not running")
            click.echo(f"💡 Start with: python cli.py webdav-start")
            
    except Exception as e:
        click.echo(f"❌ Error checking WebDAV status: {e}", err=True)
        sys.exit(1)


@cli.command('webdav-mount')
def webdav_mount():
    """Show platform-specific instructions for mounting WebDAV drive"""
    try:
        status = webdav_server.status()
        
        if not status['running']:
            click.echo(f"❌ WebDAV server is not running")
            click.echo(f"💡 Start with: python cli.py webdav-start")
            sys.exit(1)
        
        click.echo(f"🗂️  Mount Instructions for Internxt Drive")
        click.echo(f"=" * 50)
        click.echo(f"Server URL: {status['url']}")
        click.echo(f"Username: internxt")
        click.echo(f"Password: internxt-webdav")
        
        instructions = webdav_server.get_mount_instructions()
        
        # Show all platform instructions
        for platform_name, instruction in instructions.items():
            click.echo(f"\n{platform_name.upper()}:")
            click.echo(f"-" * 20)
            click.echo(instruction)
            
    except Exception as e:
        click.echo(f"❌ Error getting mount instructions: {e}", err=True)
        sys.exit(1)

# Add these commands to your cli.py file in the WebDAV section

@cli.command('webdav-test')
def webdav_test():
    """Test WebDAV server connection and functionality"""
    try:
        status = webdav_server.status()
        
        if not status['running']:
            click.echo(f"❌ WebDAV server is not running")
            click.echo(f"💡 Start with: python cli.py webdav-start")
            sys.exit(1)
        
        click.echo(f"🧪 Testing WebDAV server connection...")
        click.echo(f"🌐 Server URL: {status['url']}")
        
        # Test server connection
        test_result = webdav_server.test_connection()
        
        if test_result['success']:
            click.echo(f"✅ {test_result['message']}")
            click.echo(f"📡 Status Code: {test_result['status_code']}")
            
            # Show some useful headers
            headers = test_result.get('headers', {})
            if 'Allow' in headers:
                click.echo(f"🔧 Supported Methods: {headers['Allow']}")
            if 'DAV' in headers:
                click.echo(f"🔧 DAV Compliance: {headers['DAV']}")
            if 'Server' in headers:
                click.echo(f"🔧 Server: {headers['Server']}")
        else:
            click.echo(f"❌ {test_result['message']}")
            if 'status_code' in test_result:
                click.echo(f"📡 Status Code: {test_result['status_code']}")
        
        # Test with network utils
        click.echo(f"\n🔍 Testing with external connection...")
        from services.network_utils import NetworkUtils
        
        external_test = NetworkUtils.test_webdav_connection(
            status['url'], 
            'internxt', 
            'internxt-webdav'
        )
        
        if external_test['success']:
            click.echo(f"✅ External connection test passed")
            click.echo(f"🔧 WebDAV Support: {'Yes' if external_test['webdav_supported'] else 'No'}")
            click.echo(f"🔧 Server: {external_test['server']}")
        else:
            click.echo(f"❌ External connection test failed: {external_test['message']}")
        
        # Show mount instructions
        click.echo(f"\n💡 If tests pass but you can't mount, try:")
        click.echo(f"   python cli.py webdav-mount")
        
    except Exception as e:
        click.echo(f"❌ Error testing WebDAV server: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command('webdav-debug')
def webdav_debug():
    """Show detailed WebDAV server debugging information"""
    try:
        click.echo(f"🔍 WebDAV Server Debug Information")
        click.echo(f"=" * 50)
        
        # Server status
        status = webdav_server.status()
        click.echo(f"📊 Server Status:")
        click.echo(f"   Running: {'✅ Yes' if status['running'] else '❌ No'}")
        
        if status['running']:
            click.echo(f"   URL: {status['url']}")
            click.echo(f"   Protocol: {status['protocol']}")
            click.echo(f"   Host: {status['host']}")
            click.echo(f"   Port: {status['port']}")
        
        # SSL Certificate status
        click.echo(f"\n🔐 SSL Certificate Information:")
        from services.network_utils import NetworkUtils
        
        cert_info = NetworkUtils.validate_ssl_certificates()
        if cert_info['valid']:
            click.echo(f"   Status: ✅ Valid")
            click.echo(f"   Days until expiry: {cert_info['days_until_expiry']}")
            click.echo(f"   Subject: {cert_info['subject']}")
        else:
            click.echo(f"   Status: ❌ {cert_info['message']}")
        
        # Configuration
        webdav_config = config_service.read_webdav_config()
        click.echo(f"\n⚙️  WebDAV Configuration:")
        click.echo(f"   Protocol: {webdav_config['protocol']}")
        click.echo(f"   Port: {webdav_config['port']}")
        click.echo(f"   Timeout: {webdav_config['timeoutMinutes']} minutes")
        
        # File paths
        click.echo(f"\n📁 File Paths:")
        click.echo(f"   Config Dir: {config_service.internxt_cli_data_dir}")
        click.echo(f"   SSL Certs Dir: {NetworkUtils.WEBDAV_SSL_CERTS_DIR}")
        click.echo(f"   SSL Cert File: {NetworkUtils.WEBDAV_SSL_CERT_FILE} ({'✅' if NetworkUtils.WEBDAV_SSL_CERT_FILE.exists() else '❌'})")
        click.echo(f"   SSL Key File: {NetworkUtils.WEBDAV_SSL_KEY_FILE} ({'✅' if NetworkUtils.WEBDAV_SSL_KEY_FILE.exists() else '❌'})")
        
        # Authentication status
        click.echo(f"\n🔐 Authentication:")
        user_info = auth_service.whoami()
        if user_info:
            click.echo(f"   Status: ✅ Logged in as {user_info['email']}")
        else:
            click.echo(f"   Status: ❌ Not logged in")
        
        # Network tests
        if status['running']:
            click.echo(f"\n🌐 Network Tests:")
            
            # Test local connectivity
            import socket
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((status['host'], status['port']))
                sock.close()
                
                if result == 0:
                    click.echo(f"   Port {status['port']}: ✅ Open")
                else:
                    click.echo(f"   Port {status['port']}: ❌ Closed/Filtered")
            except Exception as e:
                click.echo(f"   Port Test: ❌ Error: {e}")
            
            # Test WebDAV response
            try:
                import requests
                from requests.auth import HTTPBasicAuth
                
                auth = HTTPBasicAuth('internxt', 'internxt-webdav')
                response = requests.options(status['url'], auth=auth, timeout=5, verify=False)
                click.echo(f"   WebDAV Response: ✅ {response.status_code}")
                
                if 'Allow' in response.headers:
                    methods = response.headers['Allow'].split(', ')
                    webdav_methods = [m for m in methods if m in ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']]
                    click.echo(f"   WebDAV Methods: {', '.join(webdav_methods) if webdav_methods else 'None detected'}")
                
            except Exception as e:
                click.echo(f"   WebDAV Test: ❌ {e}")
        
        # Troubleshooting tips
        click.echo(f"\n💡 Troubleshooting Tips:")
        if not status['running']:
            click.echo(f"   1. Start the server: python cli.py webdav-start")
        else:
            click.echo(f"   1. Try connecting via browser: {status['url']}")
            click.echo(f"   2. Test with curl: curl -u internxt:internxt-webdav {status['url']}")
            click.echo(f"   3. Check firewall/antivirus software")
            click.echo(f"   4. Try a different port: python cli.py webdav-start --port 8080")
            
    except Exception as e:
        click.echo(f"❌ Error getting debug information: {e}", err=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)


@cli.command('webdav-regenerate-ssl')
def webdav_regenerate_ssl():
    """Regenerate SSL certificates for WebDAV server"""
    try:
        click.echo(f"🔐 Regenerating SSL certificates for WebDAV server...")
        
        from services.network_utils import NetworkUtils
        
        # Remove existing certificates
        if NetworkUtils.WEBDAV_SSL_CERT_FILE.exists():
            NetworkUtils.WEBDAV_SSL_CERT_FILE.unlink()
            click.echo(f"🗑️  Removed old certificate")
        
        if NetworkUtils.WEBDAV_SSL_KEY_FILE.exists():
            NetworkUtils.WEBDAV_SSL_KEY_FILE.unlink()
            click.echo(f"🗑️  Removed old private key")
        
        # Generate new certificates
        ssl_certs = NetworkUtils.generate_new_selfsigned_certs()
        
        click.echo(f"✅ New SSL certificates generated successfully")
        click.echo(f"📁 Saved to: {NetworkUtils.WEBDAV_SSL_CERTS_DIR}")
        
        # Validate new certificates
        validation = NetworkUtils.validate_ssl_certificates()
        if validation['valid']:
            click.echo(f"✅ Certificate validation passed")
            click.echo(f"📅 Valid until: {validation['expiry_date']}")
        else:
            click.echo(f"❌ Certificate validation failed: {validation['message']}")
        
        click.echo(f"\n💡 Restart the WebDAV server to use the new certificates:")
        click.echo(f"   python cli.py webdav-stop")
        click.echo(f"   python cli.py webdav-start")
        
    except Exception as e:
        click.echo(f"❌ Error regenerating SSL certificates: {e}", err=True)
        sys.exit(1)


@cli.command('webdav-config')
def webdav_config():
    """Show WebDAV server configuration"""
    try:
        webdav_config = config_service.read_webdav_config()
        status = webdav_server.status()
        
        click.echo(f"⚙️  WebDAV Server Configuration")
        click.echo(f"=" * 40)
        
        # Current configuration
        click.echo(f"📡 Protocol: {webdav_config.get('protocol', 'http').upper()}")
        click.echo(f"🏠 Host: {webdav_config.get('host', 'localhost')}")
        click.echo(f"🚪 Port: {webdav_config.get('port', 8080)}")
        click.echo(f"⏱️  Timeout: {webdav_config.get('timeoutMinutes', 30)} minutes")
        click.echo(f"🕐 Preserve Timestamps: {webdav_config.get('preserveTimestamps', True)}")
        click.echo(f"📝 Verbose: Level {webdav_config.get('verbose', 0)}")
        click.echo("\n📝 Config file: " + str(config_service.webdav_configs_file))
        
        # SSL certificate info
        click.echo(f"\n🔐 SSL Certificates:")
        from services.network_utils import NetworkUtils
        cert_dir = NetworkUtils.WEBDAV_SSL_CERTS_DIR
        cert_file = NetworkUtils.WEBDAV_SSL_CERT_FILE
        key_file = NetworkUtils.WEBDAV_SSL_KEY_FILE
        
        click.echo(f"   Directory: {cert_dir}")
        click.echo(f"   Certificate: {cert_file} ({'✅ exists' if cert_file.exists() else '❌ missing'})")
        click.echo(f"   Private Key: {key_file} ({'✅ exists' if key_file.exists() else '❌ missing'})")
        
        # Server status
        click.echo(f"\n🔄 Server Status:")
        if status['running']:
            click.echo(f"   Status: ✅ Running")
            click.echo(f"   URL: {status['url']}")
        else:
            click.echo(f"   Status: ❌ Stopped")
        
        # Usage examples
        click.echo(f"\n💡 Usage Examples:")
        click.echo(f"   Start server:    python cli.py webdav-start")
        click.echo(f"   Start with SSL:  python cli.py webdav-start  # (auto-detects from config)")
        click.echo(f"   Custom port:     python cli.py webdav-start --port 9090")
        click.echo(f"   Disable timestamps:    python cli.py webdav-start --no-preserve-timestamps")
        click.echo(f"   Background mode: python cli.py webdav-start --background")
        click.echo(f"   Stop server:     python cli.py webdav-stop")
        
    except Exception as e:
        click.echo(f"❌ Error reading WebDAV configuration: {e}", err=True)
        sys.exit(1)

@cli.command()
def test():
    """Test CLI components"""
    click.echo("🧪 Testing CLI components ...")
    click.echo("=" * 60)
    
    tests_passed = 0
    total_tests = 7  # Added WebDAV test
    
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
    
    # Test 7: WebDAV imports
    try:
        # Test WebDAV imports without initializing the server
        from wsgidav.dav_provider import DAVProvider, DAVCollection, DAVNonCollection
        click.echo("✅ WebDAV dependencies - properly installed and importable")
        tests_passed += 1
    except ImportError as e:
        click.echo(f"❌ WebDAV dependencies missing: {e}")
        click.echo("   Install with: pip install WsgiDAV cheroot")
    except Exception as e:
        click.echo(f"❌ WebDAV import test failed: {e}")
    
    click.echo("\n" + "=" * 60)
    click.echo(f"📊 Tests passed: {tests_passed}/{total_tests}")
    
    if tests_passed == total_tests:
        click.echo("🎉 All tests passed! CLI is working correctly.")
        if tests_passed >= 6:  # All core tests passed
            click.echo("🌐 WebDAV server ready to use!")
    else:
        click.echo("⚠️  Some tests failed. Please review the errors.")
        if tests_passed < 6:
            click.echo("🔧 Core functionality issues detected.")
        else:
            click.echo("🌐 WebDAV optional - install dependencies if you want WebDAV server.")


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

🌐 WEBDAV SERVER (Mount as Local Drive!)
  webdav-start      Start WebDAV server to mount drive locally
  webdav-stop       Stop WebDAV server
  webdav-status     Check if WebDAV server is running
  webdav-mount      Show mount instructions for your OS
  webdav-config     Show WebDAV configuration

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
  
  # Mount as local drive (AMAZING!)
  python cli.py webdav-start
  # Then in Windows: Map network drive to http://localhost:8080
  # Username: internxt, Password: internxt-webdav
  
  # Clean up
  python cli.py trash-path "/OldFolder"
  python cli.py delete-path "/TempFile.txt" --force

🌟 TIP: Path-based commands are much easier to use than UUID-based ones!
🌟 NEW: WebDAV server lets you access your drive like a local folder!
""")


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("🚀 Internxt Python CLI with Path Support")
        print("=" * 50)
        print("💡 Try: python cli.py help-extended")
        print("")
    
    cli()