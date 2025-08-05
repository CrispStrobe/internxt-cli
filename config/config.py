#!/usr/bin/env python3
"""
internxt_cli/config/config.py
Configuration management for Internxt CLI
"""

import os
import json
import sys
from pathlib import Path
from typing import Optional, Dict, Any


class ConfigService:
    """Manages local configuration and credential storage"""

    def __init__(self):
        self.home_dir = Path.home()
        self.config_dir = self.home_dir / '.internxt-cli'
        self.credentials_file = self.config_dir / '.inxtcli'
        self.webdav_config_file = self.config_dir / 'config.webdav.inxt'
        self.logs_dir = self.config_dir / 'logs'

        # App configuration
        self.config = {
            'DRIVE_WEB_URL': 'https://drive.internxt.com',
            'DRIVE_NEW_API_URL': 'https://api.internxt.com/drive',
            'NETWORK_URL': 'https://api.internxt.com',
            'APP_CRYPTO_SECRET': '6KYQBP847D4ATSFA',
            'APP_MAGIC_IV': 'd139cb9a2cd17092e79e1861cf9d7023',
            'APP_MAGIC_SALT': '38dce0391b49efba88dbc8c39ebf868f0267eb110bb0012ab27dc52a528d61b1d1ed9d76f400ff58e3240028442b1eab9bb84e111d9dadd997982dbde9dbd25e'
        }

        self._ensure_config_dir()

    def _ensure_config_dir(self):
        """Ensure configuration directory exists"""
        self.config_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)

    def get(self, key: str) -> str:
        """Get configuration value"""
        if key not in self.config:
            raise ValueError(f"Config key {key} not found")
        return self.config[key]

    def save_user_credentials(self, credentials: Dict[str, Any]) -> None:
        """Save encrypted user credentials to file"""
        # Import here to avoid circular imports
        try:
            from ..services.crypto import crypto_service
        except ImportError:
            try:
                from internxt_cli.services.crypto import crypto_service
            except ImportError:
                current_dir = os.path.dirname(os.path.abspath(__file__))
                parent_dir = os.path.dirname(current_dir)
                if parent_dir not in sys.path:
                    sys.path.insert(0, parent_dir)
                from services.crypto import crypto_service

        credentials_json = json.dumps(credentials)
        encrypted_credentials = crypto_service.encrypt_text(credentials_json)

        with open(self.credentials_file, 'w') as f:
            f.write(encrypted_credentials)

    def read_user_credentials(self) -> Optional[Dict[str, Any]]:
        """Read and decrypt user credentials from file"""
        if not self.credentials_file.exists():
            return None

        try:
            with open(self.credentials_file, 'r') as f:
                encrypted_credentials = f.read()

            if not encrypted_credentials.strip():
                return None

            # Import here to avoid circular imports
            try:
                from ..services.crypto import crypto_service
            except ImportError:
                try:
                    from internxt_cli.services.crypto import crypto_service
                except ImportError:
                    current_dir = os.path.dirname(os.path.abspath(__file__))
                    parent_dir = os.path.dirname(current_dir)
                    if parent_dir not in sys.path:
                        sys.path.insert(0, parent_dir)
                    from services.crypto import crypto_service

            credentials_json = crypto_service.decrypt_text(encrypted_credentials)
            return json.loads(credentials_json)
        except Exception:
            return None

    def clear_user_credentials(self) -> None:
        """Clear user credentials"""
        if self.credentials_file.exists():
            self.credentials_file.unlink()

    def save_webdav_config(self, config: Dict[str, Any]) -> None:
        """Save WebDAV configuration"""
        with open(self.webdav_config_file, 'w') as f:
            json.dump(config, f)

    def read_webdav_config(self) -> Dict[str, Any]:
        """Read WebDAV configuration with defaults"""
        default_config = {
            'port': '3005',
            'protocol': 'https',
            'timeout_minutes': 0
        }

        if not self.webdav_config_file.exists():
            return default_config

        try:
            with open(self.webdav_config_file, 'r') as f:
                config = json.load(f)
            return {**default_config, **config}
        except Exception:
            return default_config


# Global instance
config_service = ConfigService()