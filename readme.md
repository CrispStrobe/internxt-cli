# Internxt Python CLI

A Python implementation of the Internxt CLI for encrypted cloud storage with **path-based operations**: You can navigate your drive like a local filesystem with readable paths.

## ✨ Features

### 🛣️ **Path-Based Operations**
- ✅ **Human-readable paths**: Use `/Documents/report.pdf` instead of UUIDs
- ✅ **Wildcard search**: Find files with `*.pdf`, `report*`, etc.
- ✅ **Tree visualization**: See your folder structure at a glance
- ✅ **Path navigation**: Browse folders like your local filesystem

### 🔐 **Core Functionality**
- ✅ **Secure authentication**: Login/logout with 2FA support
- ✅ **File operations**: Upload, download with progress indicators
- ✅ **Folder management**: Create and organize folders
- ✅ **Zero-knowledge encryption**: AES-256-CTR client-side encryption
- ✅ **Cross-platform**: Windows, macOS, Linux support

### 🚧 **Coming Soon**
- 🚧 **Move/rename operations**: Reorganize files and folders
- 🚧 **Trash management**: List, restore, and clear trash
- 🚧 **WebDAV server**: Mount your Internxt Drive as local drive

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Login to your account
python cli.py login

# Explore your drive the new way!
python cli.py list-path          # List root with paths
python cli.py tree               # Visual folder structure
python cli.py find "*.pdf"       # Find all PDF files

# Download files the easy way
python cli.py download-path "/Documents/important.pdf"
```

## 📖 Complete Usage Guide

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

### 🛣️ Path-Based Operations

#### Navigate & List
```bash
# List root folder with readable paths
python cli.py list-path

# Navigate to specific folders
python cli.py list-path "/Documents" 
python cli.py list-path "/Photos/2023/Summer"

# Show detailed information
python cli.py list-path "/Documents" --detailed
```

#### Search & Find
```bash
# Find files with wildcards
python cli.py find "*.pdf"              # All PDF files
python cli.py find "report*"            # Files starting with "report"
python cli.py find "*2023*"             # Files containing "2023"

# Search in specific locations
python cli.py find "*.jpg" --path "/Photos"
python cli.py find "budget*" --path "/Documents/Finance"
```

#### Visual Navigation
```bash
# Show folder structure as tree
python cli.py tree                      # From root
python cli.py tree "/Projects"          # From specific folder
python cli.py tree "/" --depth 2        # Limit depth
```

#### Download Files
```bash
# Download by path (much easier!)
python cli.py download-path "/Documents/report.pdf"
python cli.py download-path "/Photos/vacation.jpg" --destination ~/Downloads/

# Download from nested paths
python cli.py download-path "/Projects/Website/assets/logo.png"
```

### 🗑️ Delete & Trash Operations

#### Move to Trash (Recoverable)
```bash
# Move to trash by path
python cli.py trash-path "/OldDocuments/outdated.pdf"
python cli.py trash-path "/TempFolder"

# Skip confirmation prompt
python cli.py trash-path "/TempFile.txt" --force

# Move to trash by UUID (if you have it)
python cli.py trash a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6
```

#### Permanent Delete (⚠️ Cannot Be Undone)
```bash
# Permanently delete by path (with warnings)
python cli.py delete-path "/TempFile.txt"
python cli.py delete-path "/EmptyFolder"

# Skip confirmation (dangerous!)
python cli.py delete-path "/TempFile.txt" --force

# Permanently delete by UUID
python cli.py delete a1b2c3d4-e5f6-g7h8-i9j0-k1l2m3n4o5p6 --force
```

### 📁 Traditional Operations (UUID-based)

#### File & Folder Management
```bash
# List folders (old way with UUIDs)
python cli.py list                             # Root folder
python cli.py list --folder-id <folder-uuid>   # Specific folder
python cli.py list --detailed                  # With extra info

# Create folders
python cli.py mkdir "My New Folder"
python cli.py mkdir "Subfolder" --parent-folder-id <folder-uuid>

# Upload files
python cli.py upload ./document.pdf
python cli.py upload ./file.txt --destination <folder-uuid>

# Download files by UUID
python cli.py download <file-uuid>
python cli.py download <file-uuid> --destination ./downloads/
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
git clone https://github.com/internxt/python-cli.git
cd python-cli

# Install dependencies
pip install requirements.txt

# optionally, install
pip install -e .

# Start using immediately
python cli.py login
python cli.py list-path
```

### Requirements
- **Python 3.8+**
- **Dependencies**: `cryptography`, `mnemonic`, `tqdm`, `requests`, `click`
- **Platforms**: Windows, macOS, Linux

## 🔒 Security & Privacy

This CLI implements **the same security model** as official Internxt clients:

### 🛡️ **Zero-Knowledge Architecture**
- **Client-side encryption**: All files encrypted on your device before upload
- **Server-blind**: Internxt servers never see your unencrypted data
- **Key derivation**: Uses your account mnemonic as the master key

### 🔐 **Encryption Standards**
- **File content**: AES-256-CTR encryption
- **File keys**: Unique per file, derived from mnemonic + bucket ID
- **Filenames**: AES-256-GCM encrypted metadata  
- **Key hierarchy**: BIP39 mnemonic → Bucket key → File key

### 💾 **Local Security**
- **Credentials**: Encrypted and stored in `~/.internxt-cli/`
- **No plaintext**: Passwords and mnemonics never stored in plaintext
- **Session tokens**: Securely managed with automatic refresh

## 🏗️ Development

### Project Structure
```
internxt-cli/
├── cli.py                    # Main CLI interface with all commands
├── config/
│   ├── __init__.py
│   └── config.py            # Configuration management
├── services/
│   ├── __init__.py
│   ├── auth.py              # Authentication & login
│   ├── crypto.py            # Encryption/decryption (exact TypeScript match)
│   └── drive.py             # Drive operations & path resolution
├── utils/
│   ├── __init__.py
│   └── api.py               # HTTP API client
└── requirements.txt         # Python dependencies
```

### Key Components

#### 🔐 **Crypto Service** (`services/crypto.py`)
- **EXACT TypeScript compatibility**: Matches inxt-js encryption
- **BIP39 mnemonic handling**: Same as official clients
- **Key derivation**: Identical to TypeScript implementation
- **File encryption**: AES-256-CTR with proper IV handling

#### 🛣️ **Drive Service** (`services/drive.py`)  
- **Path resolution**: Navigate with `/folder/file.txt` paths
- **Search functionality**: Wildcard pattern matching
- **Tree visualization**: Recursive folder structure display
- **Smart operations**: Handles files and folders intelligently

#### 🌐 **API Client** (`utils/api.py`)
- **Complete endpoints**: All Drive and Network API operations
- **Authentication**: Bearer tokens and Basic auth for network
- **Error handling**: Proper HTTP error management
- **Upload/download**: Chunked file operations

### Adding New Features

1. **Commands**: Add new Click commands in `cli.py`
2. **Business Logic**: Implement in appropriate service (`auth.py`, `drive.py`, etc.)
3. **API Integration**: Add endpoints to `api.py` if needed
4. **Path Support**: Extend `resolve_path()` for new path-based operations
5. **Testing**: Add tests and update documentation

### Development Setup
```bash
# Clone and setup development environment
git clone https://github.com/internxt/python-cli.git
cd python-cli

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install in development mode
pip install -e .
pip install -r requirements.txt

# Run tests
python cli.py test
```

### Debug Commands
```bash
python cli.py resolve "/path/to/check"    # Debug path resolution
python cli.py config                      # Check configuration
python cli.py test                        # Test all components
python cli.py whoami                      # Check login status
```

### Getting Help
```bash
python cli.py --help                      # Basic help
python cli.py help-extended               # Detailed examples
python cli.py <command> --help            # Command-specific help
```

## 📄 License

**MIT License** - See [LICENSE](LICENSE) file for details.

---

*Made with ❤️ for the Internxt community*