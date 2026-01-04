"""
Thin wrapper around the existing BXSS callback server for SSRF callbacks.
"""
from bxss.oob.callback_server import start_server, start_server_background, get_callbacks, CALLBACK_DB

__all__ = ["start_server", "start_server_background", "get_callbacks", "CALLBACK_DB"]
