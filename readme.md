# Internxt Python CLI

A Python implementation of the Internxt CLI for encrypted cloud storage with **path-based operations**, **timestamp preservation**, and a **built-in WebDAV server**.

## ⚠️ Disclaimer

This is an unofficial, open-source project and is **not** affiliated with, endorsed by, or supported by Internxt, Inc. It is a personal project built for learning and to provide an alternative interface. Use it at your own risk.

## ✨ Features

### 🌐 **WebDAV Server**

  - ✅ **Mount as a local drive**: Access your Internxt Drive directly from Finder, File Explorer, or any WebDAV client.
  - ✅ **Cross-platform support**: Works on Windows, macOS, and Linux.
  - ✅ **Stable and Compatible**: Uses `waitress` (recommended) or `cheroot` for the best client compatibility.
  - ✅ **Server Choice**: Force `waitress` or `cheroot` with the `--server` flag for debugging.

### 🛣️ **Path-Based Operations**

  - ✅ **Human-readable paths**: Use `/Documents/report.pdf` instead of UUIDs.
  - ✅ **Fuzzy Search**: Instantly find files and folders with a fast, server-side `search` command.
  - ✅ **Wildcard Find**: Use `find` with patterns like `*.pdf`, `report*`, etc.
  - ✅ **Tree visualization**: See your folder structure at a glance.
  - ✅ **Path navigation**: Browse folders like your local filesystem.

### 🔐 **Core Functionality**

  - ✅ **Timestamp Preservation**: Preserves original file modification/creation dates on `upload` and `download-path`.
  - ✅ **Secure authentication**: Login/logout with 2FA support.
  - ✅ **File operations**: Upload, download with progress indicators.
  - ✅ **Folder management**: Create and organize folders.
  - ✅ **Zero-knowledge encryption**: AES-256-CTR client-side encryption.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# (Recommended for WebDAV)
pip install waitress

# Login to your account
python cli.py login

# Mount your drive locally! (EASIEST WAY TO USE)
python cli.py webdav-start

# Or, use path-based commands
python cli.py list-path
python cli.py search "report"
python cli.py find /Documents "*.pdf"
python cli.py upload -r -p ./my-docs /Backups
```

## 📖 Usage Guide

### 🔐 Authentication

```bash
# Login with interactive prompts
python cli.py login

# Login non-interactively
python cli.py login --email user@example.com --password mypass --2fa 123456

# Check current user
python cli.py whoami

# Logout and clear credentials
python cli.py logout
```

### 🌐 WebDAV Server

Mount your Internxt Drive as a local disk.

```bash
# Start the WebDAV server (it will print the URL and credentials)
python cli.py webdav-start

# Start in the background
python cli.py webdav-start --background

# Force a specific server (e.g., cheroot for SSL)
python cli.py webdav-start --server cheroot

# Check if the server is running
python cli.py webdav-status

# Stop the server
python cli.py webdav-stop

# Show mount instructions for your OS
python cli.py webdav-mount

# Test if the server is responding correctly
python cli.py webdav-test

# Show full WebDAV configuration and paths
python cli.py webdav-config

# Show advanced debugging info
python cli.py webdav-debug

# Regenerate SSL certs
python cli.py webdav-regenerate-ssl
```

After starting, open your file manager (Finder/File Explorer) or Client (like CyberDuck) and connect to the server (e.g., `http://localhost:8080`) with username `internxt` and password `internxt-webdav`.

### 🛣️ Path-Based Operations

#### List & Navigate

```bash
# List root folder with readable paths
python cli.py list-path

# List specific folders
python cli.py list-path "/Documents"
python cli.py list-path "/Photos/2023/Summer"

# Show detailed information (size, date)
python cli.py list-path "/Documents" --detailed

# Show folder structure as tree
python cli.py tree
python cli.py tree "/Projects" --depth 2
```

#### Search & Find

```bash
# Fast, global, server-side fuzzy search
python cli.py search "report"

# Show full details (size, date, full path) (slow!)
python cli.py search "report" --detailed

# Slow, client-side wildcard find (POSIX-like syntax, slow!)
python cli.py find / "*.pdf"              # All PDF files in entire drive
python cli.py find /Photos "*.jpg"        # All JPGs in /Photos
python cli.py find . "report*"            # Files starting with "report" in current path
```

#### ⬆️⬇️ Upload & Download

**Upload**

```bash
# Upload a single file, preserving its timestamp
python cli.py upload -p ./local-report.pdf /Documents/

# Upload a whole folder recursively, preserving all timestamps
python cli.py upload -r -p ./my-project /Backups/

# Upload with filters and overwrite conflicts
python cli.py upload -r ./photos /Photos --include "*.jpg" --on-conflict overwrite
```

**Download**

```bash
# Download a file by path, preserving its timestamp
python cli.py download-path -p "/Documents/report.pdf"

# Download a folder recursively to a local directory
python cli.py download-path -r "/Photos/2023" --destination ./My-Photos

# Download a folder with filters
python cli.py download-path -r "/Music" --include "*.mp3" --exclude "demo_*"
```

### 🗑️ Delete & Trash Operations

#### Move to Trash (Recoverable)

```bash
# Move to trash by path
python cli.py trash-path "/OldDocuments/outdated.pdf"
python cli.py trash-path "/TempFolder"
```

#### Permanent Delete (⚠️ Cannot Be Undone)

```bash
# Permanently delete by path (with warnings)
python cli.py delete-path "/TempFile.txt"
```

### 📁 Traditional Operations (UUID-based)

```bash
# List folders (old way with UUIDs)
python cli.py list
python cli.py list --folder-id <folder-uuid>

# Create folders
python cli.py mkdir "My New Folder"

# Upload/Download by UUID (see path-based commands for more features)
python cli.py upload ./document.pdf
python cli.py download <file-uuid>
```

### 🔧 Utility Commands

```bash
# Show current configuration
python cli.py config

# Test CLI components
python cli.py test

# Extended help with examples
python cli.py help-extended

# Debug path resolution
python cli.py resolve "/Documents/report.pdf"
```

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/CrispStrobe/internxt-python
cd internxt-python

# Install dependencies
pip install -r requirements.txt

# For the best WebDAV experience, install 'waitress'
pip install waitress  # (Highly recommended for WebDAV)

# Start using immediately
python cli.py login
python cli.py webdav-start
```

### Requirements

  - **Python 3.8+**
  - **Dependencies**: `cryptography`, `mnemonic`, `tqdm`, `requests`, `click`, `WsgiDAV`
  - **WebDAV Server**: `waitress` (recommended) or `cheroot`

## 🔒 Security & Privacy

This CLI implements **the same security model** as official Internxt clients:

  - **Client-side encryption**: All files encrypted on your device before upload (AES-256-CTR).
  - **Zero-knowledge**: Internxt servers never see your unencrypted data or keys.
  - **Secure Credentials**: Encrypted and stored locally in `~/.internxt-cli/`.

## 🏗️ Development

### Project Structure

```
internxt-python/
├── cli.py                    # Main CLI interface with all commands
├── config/
│   └── config.py             # Configuration management
├── services/
│   ├── auth.py               # Authentication & login
│   ├── crypto.py             # Encryption/decryption
│   ├── drive.py              # Drive operations & path resolution
│   ├── webdav_provider.py    # WsgiDAV provider for Internxt
│   └── webdav_server.py      # WebDAV server management
└── utils/
    └── api.py                # HTTP API client
```

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/CrispStrobe/internxt-python.git
cd internxt-python

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS

# Install in development mode
pip install -e .
pip install -r requirements.txt
```

### Getting Help

```bash
python cli.py --help
python cli.py help-extended
python cli.py <command> --help
```

## 📄 License

**AGPL-3.0 license**

-----

*Made with ❤️ for the Internxt community*