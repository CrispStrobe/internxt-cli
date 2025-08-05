# Internxt Python CLI

A Python implementation of the Internxt CLI for encrypted cloud storage.

## Features

- ✅ **Login/Logout**: Secure authentication with 2FA support
- ✅ **List Files**: Browse your encrypted folders and files
- ✅ **Upload Files**: Upload and encrypt files to your Internxt Drive
- ✅ **Download Files**: Download and decrypt files from your Internxt Drive
- ✅ **Create Folders**: Organize your files in folders
- 🚧 **WebDAV Server**: (Coming soon) Mount your Internxt Drive as a local drive

## Installation

```bash
# Clone the repository
git clone https://github.com/internxt/python-cli.git
cd python-cli

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Usage

### Authentication

```bash
# Login to your account
internxt login

# Check who is logged in
internxt whoami

# Logout
internxt logout
```

### File Operations

```bash
# List root folder contents
internxt list

# List with extended information
internxt list --extended

# List specific folder
internxt list --folder-id <folder-uuid>

# Create a folder
internxt mkdir "My New Folder"

# Upload a file
internxt upload /path/to/file.txt

# Upload to specific folder
internxt upload /path/to/file.txt --folder-id <folder-uuid>

# Download a file
internxt download <file-uuid>

# Download to specific location
internxt download <file-uuid> --output /path/to/save/file.txt
```

### Configuration

```bash
# Show configuration
internxt config
```

## Security

This CLI implements the same security model as the official Internxt clients:

- **Zero-knowledge encryption**: All encryption happens client-side
- **AES-256-CTR**: File content encryption
- **BIP39 mnemonic**: Key derivation from user's mnemonic
- **PGP encryption**: Metadata and filename encryption
- **Local credential storage**: Encrypted with app-specific secrets

## Development

### Project Structure

```
internxt_cli/
├── __init__.py
├── cli.py              # Main CLI interface
├── config/
│   ├── __init__.py
│   └── config.py       # Configuration management
├── services/
│   ├── __init__.py
│   ├── auth.py         # Authentication service
│   ├── crypto.py       # Encryption/decryption
│   └── drive.py        # Drive operations
└── utils/
    ├── __init__.py
    └── api.py          # API client
```

### Adding New Features

1. Add new commands in `cli.py`
2. Implement business logic in appropriate service
3. Add API endpoints in `utils/api.py` if needed
4. Update tests and documentation

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## Support

For issues and questions:
- GitHub Issues: https://github.com/internxt/python-cli/issues
- Internxt Support: https://internxt.com/support