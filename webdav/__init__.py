"""
WebDAV server implementation
"""

try:
    from .server import WebDAVServer, WebDAVHandler
    __all__ = ['WebDAVServer', 'WebDAVHandler']
except ImportError as e:
    # Flask/Werkzeug not available
    print(f"Warning: WebDAV server not available: {e}")
    print("Install with: pip install Flask>=2.3.0 Werkzeug>=2.3.0")
    __all__ = []