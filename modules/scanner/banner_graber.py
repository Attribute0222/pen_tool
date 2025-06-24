import socket
import ssl
from typing import Optional

def grab_banner(
    host: str, 
    port: int, 
    timeout: float = 3.0,
    ssl_context: bool = False
) -> Optional[str]:
    """
    Grabs service banners from TCP ports (supports SSL/TLS).
    
    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout in seconds
        ssl_context: Whether to use SSL/TLS
        
    Returns:
        Banner string or None if failed
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if ssl_context:
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                    return _get_banner(secure_sock, host)
            return _get_banner(sock, host)
    except (socket.timeout, ConnectionRefusedError):
        return None
    except Exception as e:
        return f"ERROR: {str(e)}"

def _get_banner(sock: socket.socket, host: str) -> str:
    """Internal: Handles protocol-specific banner grabbing"""
    try:
        # HTTP
        sock.sendall(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        return sock.recv(4096).decode(errors='ignore').strip()
        
        # For other protocols (add your cases):
        # if port == 21:  # FTP
        #     return sock.recv(1024).decode()
    except Exception:
        return "No banner retrieved"