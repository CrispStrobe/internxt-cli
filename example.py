#!/usr/bin/env python3
"""
Example usage of Internxt Python CLI
"""

from internxt_cli.services.auth import auth_service
from internxt_cli.services.drive import drive_service

def example_usage():
    try:
        # Check if logged in
        user_info = auth_service.whoami()
        if not user_info:
            print("Please login first: internxt login")
            return

        print(f"Logged in as: {user_info['email']}")

        # List root folder
        print("\\nListing root folder:")
        contents = drive_service.list_folder()

        for folder in contents['folders']:
            name = folder.get('plainName', 'Unknown')
            print(f"📁 {name}")

        for file in contents['files']:
            name = file.get('plainName', 'Unknown')
            file_type = file.get('type', '')
            if file_type:
                name = f"{name}.{file_type}"
            size = file.get('size', 0)
            print(f"📄 {name} ({size} bytes)")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    example_usage()