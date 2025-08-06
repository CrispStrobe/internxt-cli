#!/usr/bin/env python3
"""
debug_upload.py
Test script to debug the Internxt upload process
"""

import os
import sys
import tempfile
import hashlib
from pathlib import Path

# Add the parent directory to the path to import our modules
current_dir = Path(__file__).parent
parent_dir = current_dir.parent
if str(parent_dir) not in sys.path:
    sys.path.insert(0, str(parent_dir))

from services.crypto import crypto_service
from services.auth import auth_service
from services.drive import drive_service

def test_crypto_against_known_values():
    """Test our crypto implementation against known values"""
    print("🧪 Testing crypto implementation...")
    
    # Test data
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    bucket_id = "507f1f77bcf86cd799439011"  # Example ObjectId as hex
    test_data = b"Hello, World!"
    
    print(f"   Mnemonic: {mnemonic}")
    print(f"   Bucket ID: {bucket_id}")
    print(f"   Test data: {test_data}")
    
    # Test encryption
    encrypted_data, file_index_hex = crypto_service.encrypt_stream_internxt_protocol(test_data, mnemonic, bucket_id)
    print(f"   Encrypted size: {len(encrypted_data)} bytes")
    print(f"   File index: {file_index_hex}")
    
    # Test decryption
    decrypted_data = crypto_service.decrypt_stream_internxt_protocol(encrypted_data, mnemonic, bucket_id, file_index_hex)
    print(f"   Decrypted: {decrypted_data}")
    
    # Verify
    if test_data == decrypted_data:
        print("   ✅ Crypto test PASSED!")
        return True
    else:
        print("   ❌ Crypto test FAILED!")
        print(f"   Expected: {test_data}")
        print(f"   Got: {decrypted_data}")
        return False

def test_key_generation():
    """Test key generation matches expected pattern"""
    print("\n🔑 Testing key generation...")
    
    mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    bucket_id = "507f1f77bcf86cd799439011"
    index = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    
    # Test bucket key generation
    bucket_key = crypto_service.generate_file_bucket_key(mnemonic, bucket_id)
    print(f"   Bucket key length: {len(bucket_key)} bytes")
    print(f"   Bucket key (hex): {bucket_key.hex()[:32]}...")
    
    # Test file key generation
    file_key = crypto_service.generate_file_key(mnemonic, bucket_id, index)
    print(f"   File key length: {len(file_key)} bytes")
    print(f"   File key (hex): {file_key.hex()}")
    
    print("   ✅ Key generation test completed!")
    return True

def create_test_file():
    """Create a small test file"""
    test_content = "This is a test file for Internxt upload.\nIt contains multiple lines.\nAnd some unicode: 🚀✨"
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        f.write(test_content)
        return f.name

def test_full_upload_download():
    """Test the full upload and download process"""
    print("\n📤 Testing full upload/download process...")
    
    try:
        # Check if we're logged in
        auth_details = auth_service.get_auth_details()
        print(f"   Logged in as: {auth_details['user'].get('email')}")
        
        # Create test file
        test_file_path = create_test_file()
        print(f"   Created test file: {test_file_path}")
        
        # Read original content
        with open(test_file_path, 'r') as f:
            original_content = f.read()
        print(f"   Original content length: {len(original_content)} chars")
        
        # Upload the file
        print("   Starting upload...")
        uploaded_file = drive_service.upload_file(test_file_path)
        file_uuid = uploaded_file['uuid']
        print(f"   ✅ Upload successful! File UUID: {file_uuid}")
        
        # Download the file
        print("   Starting download...")
        download_path = f"/tmp/downloaded_{file_uuid}.txt"
        downloaded_path = drive_service.download_file(file_uuid, download_path)
        print(f"   ✅ Download successful! Downloaded to: {downloaded_path}")
        
        # Verify content
        with open(downloaded_path, 'r') as f:
            downloaded_content = f.read()
        
        if original_content == downloaded_content:
            print("   ✅ Content verification PASSED!")
            print("   🎉 Full upload/download test SUCCESSFUL!")
        else:
            print("   ❌ Content verification FAILED!")
            print(f"   Original length: {len(original_content)}")
            print(f"   Downloaded length: {len(downloaded_content)}")
            print(f"   First 100 chars original: {repr(original_content[:100])}")
            print(f"   First 100 chars downloaded: {repr(downloaded_content[:100])}")
        
        # Cleanup
        os.unlink(test_file_path)
        os.unlink(downloaded_path)
        
        return True
        
    except Exception as e:
        print(f"   ❌ Upload/download test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("🔍 Internxt Python CLI Debug Test")
    print("=" * 40)
    
    # Test 1: Basic crypto
    if not test_crypto_against_known_values():
        print("\n❌ Crypto test failed - stopping")
        return
    
    # Test 2: Key generation
    if not test_key_generation():
        print("\n❌ Key generation test failed - stopping")
        return
    
    # Test 3: Full upload/download (only if logged in)
    try:
        auth_service.get_auth_details()
        test_full_upload_download()
    except ValueError:
        print("\n⚠️  Not logged in - skipping upload/download test")
        print("   Run 'python main.py login' first to test upload/download")
    
    print("\n🏁 Debug test completed!")

if __name__ == "__main__":
    main()