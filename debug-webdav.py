#!/usr/bin/env python3
"""
Test script for WebDAV connection issues - run this to diagnose problems
"""

import requests
import socket
import subprocess
import sys
from requests.auth import HTTPBasicAuth
from urllib.parse import urlparse

def test_webdav_connection(url="http://localhost:8080", username="internxt", password="internxt-webdav"):
    """Comprehensive WebDAV connection test"""
    
    print(f"🧪 Testing WebDAV connection to {url}")
    print("=" * 60)
    
    # Parse URL
    parsed_url = urlparse(url)
    host = parsed_url.hostname or 'localhost'
    port = parsed_url.port or (80 if parsed_url.scheme == 'http' else 443)
    
    # Test 1: Basic network connectivity
    print(f"1. Testing network connectivity to {host}:{port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"   ✅ Port {port} is open and reachable")
        else:
            print(f"   ❌ Port {port} is closed or unreachable")
            return False
    except Exception as e:
        print(f"   ❌ Network test failed: {e}")
        return False
    
    # Test 2: HTTP connectivity
    print(f"2. Testing HTTP connectivity...")
    try:
        response = requests.get(url, timeout=10, verify=False)
        print(f"   ✅ HTTP connection successful (Status: {response.status_code})")
        
        if response.status_code == 401:
            print(f"   ℹ️  Server requires authentication (as expected)")
        elif response.status_code == 200:
            print(f"   ℹ️  Server accessible without authentication")
        
    except Exception as e:
        print(f"   ❌ HTTP connection failed: {e}")
        return False
    
    # Test 3: WebDAV authentication
    print(f"3. Testing WebDAV authentication...")
    try:
        auth = HTTPBasicAuth(username, password)
        response = requests.get(url, auth=auth, timeout=10, verify=False)
        
        if response.status_code in [200, 207]:
            print(f"   ✅ Authentication successful (Status: {response.status_code})")
        else:
            print(f"   ❌ Authentication failed (Status: {response.status_code})")
            print(f"       Response: {response.text[:200]}...")
            return False
            
    except Exception as e:
        print(f"   ❌ Authentication test failed: {e}")
        return False
    
    # Test 4: WebDAV OPTIONS method
    print(f"4. Testing WebDAV OPTIONS method...")
    try:
        auth = HTTPBasicAuth(username, password)
        response = requests.options(url, auth=auth, timeout=10, verify=False)
        
        if response.status_code in [200, 204]:
            print(f"   ✅ OPTIONS request successful")
            
            # Check WebDAV headers
            allow_methods = response.headers.get('Allow', '').split(', ')
            dav_header = response.headers.get('DAV', '')
            server_header = response.headers.get('Server', 'Unknown')
            
            print(f"   📋 Server: {server_header}")
            print(f"   📋 DAV Header: {dav_header}")
            print(f"   📋 Allowed Methods: {', '.join(allow_methods)}")
            
            # Check for WebDAV-specific methods
            webdav_methods = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE']
            supported_webdav = [m for m in webdav_methods if m in allow_methods]
            
            if supported_webdav:
                print(f"   ✅ WebDAV methods supported: {', '.join(supported_webdav)}")
            else:
                print(f"   ⚠️  No WebDAV methods detected")
                
            # Check for macOS requirements
            if 'LOCK' in allow_methods and 'UNLOCK' in allow_methods:
                print(f"   ✅ LOCK/UNLOCK support (required by macOS)")
            else:
                print(f"   ⚠️  Missing LOCK/UNLOCK support (may cause macOS issues)")
                
            if '2' in dav_header:
                print(f"   ✅ DAV Level 2 support (required by macOS for read/write)")
            else:
                print(f"   ⚠️  Missing DAV Level 2 support (macOS may be read-only)")
                
        else:
            print(f"   ❌ OPTIONS request failed (Status: {response.status_code})")
            return False
            
    except Exception as e:
        print(f"   ❌ OPTIONS test failed: {e}")
        return False
    
    # Test 5: WebDAV PROPFIND method
    print(f"5. Testing WebDAV PROPFIND method...")
    try:
        auth = HTTPBasicAuth(username, password)
        headers = {
            'Depth': '1',
            'Content-Type': 'application/xml; charset=utf-8'
        }
        
        propfind_body = '''<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:">
    <D:prop>
        <D:resourcetype/>
        <D:getcontenttype/>
        <D:getcontentlength/>
        <D:getlastmodified/>
    </D:prop>
</D:propfind>'''
        
        response = requests.request(
            'PROPFIND', url, 
            auth=auth, 
            headers=headers, 
            data=propfind_body,
            timeout=10, 
            verify=False
        )
        
        if response.status_code == 207:
            print(f"   ✅ PROPFIND request successful")
            print(f"   📋 Response length: {len(response.text)} characters")
            
            # Check if we got XML back
            if '<D:multistatus' in response.text or '<multistatus' in response.text:
                print(f"   ✅ Valid WebDAV XML response")
            else:
                print(f"   ⚠️  Response may not be valid WebDAV XML")
                
        else:
            print(f"   ❌ PROPFIND request failed (Status: {response.status_code})")
            print(f"       Response: {response.text[:200]}...")
            return False
            
    except Exception as e:
        print(f"   ❌ PROPFIND test failed: {e}")
        return False
    
    # Test 6: macOS-specific compatibility checks
    print(f"6. Testing macOS compatibility...")
    
    # Check for MS-Author-Via header (required for Office)
    auth = HTTPBasicAuth(username, password)
    response = requests.options(url, auth=auth, timeout=10, verify=False)
    
    ms_author_via = response.headers.get('MS-Author-Via', '').upper()
    if 'DAV' in ms_author_via:
        print(f"   ✅ MS-Author-Via header present (Microsoft Office compatible)")
    else:
        print(f"   ⚠️  Missing MS-Author-Via header (Office may not work)")
    
    # Test with macOS-style User-Agent
    macos_headers = {
        'User-Agent': 'WebDAVFS/3.0.0 (03008000) Darwin/20.6.0 (x86_64)'
    }
    
    try:
        response = requests.options(
            url, 
            auth=auth, 
            headers=macos_headers,
            timeout=10, 
            verify=False
        )
        
        if response.status_code in [200, 204]:
            print(f"   ✅ macOS WebDAVFS user-agent accepted")
        else:
            print(f"   ⚠️  macOS WebDAVFS user-agent rejected ({response.status_code})")
            
    except Exception as e:
        print(f"   ⚠️  macOS user-agent test failed: {e}")
    
    print(f"\n🎉 All tests passed! WebDAV server appears to be working correctly.")
    
    # Provide connection instructions
    print(f"\n💡 Connection instructions:")
    print(f"   1. Open Finder")
    print(f"   2. Press Cmd+K")
    print(f"   3. Enter: {url}")
    print(f"   4. Username: {username}")
    print(f"   5. Password: {password}")
    
    return True

def test_macos_keychain_cleanup():
    """Help clean up macOS keychain issues"""
    print(f"\n🔑 macOS Keychain Cleanup:")
    print(f"If you're having connection issues, try:")
    print(f"1. Open Keychain Access")
    print(f"2. Search for 'internxt' or 'webdav' or 'localhost'")
    print(f"3. Delete any old entries")
    print(f"4. Try connecting again")
    
def test_command_line_mount():
    """Test command line mounting"""
    print(f"\n🖥️  Command Line Mount Test:")
    print(f"Try these commands:")
    print(f"mkdir -p ~/InternxtDrive")
    print(f"mount -t webdav http://localhost:8080 ~/InternxtDrive")
    print(f"# Enter username: internxt")
    print(f"# Enter password: internxt-webdav")

if __name__ == "__main__":
    # Default values
    url = "http://localhost:8080"
    username = "internxt" 
    password = "internxt-webdav"
    
    # Allow command line arguments
    if len(sys.argv) > 1:
        url = sys.argv[1]
    if len(sys.argv) > 2:
        username = sys.argv[2]
    if len(sys.argv) > 3:
        password = sys.argv[3]
    
    print(f"WebDAV Connection Test Tool")
    print(f"Usage: python test_webdav.py [url] [username] [password]")
    print(f"Using: {url} with {username}:{password}")
    print()
    
    success = test_webdav_connection(url, username, password)
    
    if not success:
        print(f"\n❌ WebDAV connection test failed!")
        print(f"💡 Try these troubleshooting steps:")
        print(f"   1. Make sure the WebDAV server is running")
        print(f"   2. Check firewall settings")
        print(f"   3. Try a different port")
        print(f"   4. Clear browser cache and keychain")
        
        test_macos_keychain_cleanup()
        test_command_line_mount()
        
        sys.exit(1)
    else:
        print(f"\n✅ WebDAV server is working correctly!")
        sys.exit(0)