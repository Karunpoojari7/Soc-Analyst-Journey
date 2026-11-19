"""PAYGUARD SOC - Network Isolation Enforcement.

Strictly restricts outbound network communication at the socket and DNS level to ensure
the application remains entirely local and synthetic. Any attempt to reach an external
financial network, payment gateway, public internet endpoint, or perform external DNS lookup
raises an immediate RuntimeError.
"""

import socket
import logging

logger = logging.getLogger("payguard.security.network_isolation")

_ORIGINAL_SOCKET_CONNECT = socket.socket.connect
_ORIGINAL_CREATE_CONNECTION = socket.create_connection
_ORIGINAL_GETADDRINFO = socket.getaddrinfo

ALLOWED_HOSTS = {"127.0.0.1", "::1", "localhost", "testserver"}
_ISOLATION_ACTIVE = False


def _is_loopback(host: str) -> bool:
    """Check if the destination address is strictly loopback / local."""
    if not host:
        return True
    host_str = str(host).lower().strip()
    if host_str in ALLOWED_HOSTS:
        return True
    try:
        # Check standard localhost subnet (127.0.0.0/8)
        if host_str.startswith("127."):
            return True
    except Exception:
        pass
    return False


def _guarded_connect(self, address):
    """Guarded socket.connect that prohibits non-local outbound traffic."""
    if not _ISOLATION_ACTIVE:
        return _ORIGINAL_SOCKET_CONNECT(self, address)
        
    host = address[0] if isinstance(address, (tuple, list)) else address
    if not _is_loopback(str(host)):
        error_msg = (
            f"NETWORK_ISOLATION_VIOLATION: Attempted outbound socket connection to '{host}'. "
            "All external financial networks and internet traffic are strictly prohibited in the PAYGUARD synthetic lab."
        )
        logger.critical(error_msg)
        raise RuntimeError(error_msg)
        
    return _ORIGINAL_SOCKET_CONNECT(self, address)


def _guarded_create_connection(address, timeout=None, source_address=None, **kwargs):
    """Guarded socket.create_connection that prohibits non-local outbound traffic."""
    if not _ISOLATION_ACTIVE:
        return _ORIGINAL_CREATE_CONNECTION(address, timeout, source_address, **kwargs)
        
    host = address[0] if isinstance(address, (tuple, list)) else address
    if not _is_loopback(str(host)):
        error_msg = (
            f"NETWORK_ISOLATION_VIOLATION: Attempted outbound connection to '{host}'. "
            "All external financial networks and internet traffic are strictly prohibited in the PAYGUARD synthetic lab."
        )
        logger.critical(error_msg)
        raise RuntimeError(error_msg)
        
    return _ORIGINAL_CREATE_CONNECTION(address, timeout, source_address, **kwargs)


def _guarded_getaddrinfo(host, port, *args, **kwargs):
    """Guarded socket.getaddrinfo that blocks outbound DNS resolution attempts."""
    if not _ISOLATION_ACTIVE:
        return _ORIGINAL_GETADDRINFO(host, port, *args, **kwargs)

    if not _is_loopback(str(host)):
        error_msg = (
            f"NETWORK_ISOLATION_VIOLATION: Attempted DNS resolution for external host '{host}'. "
            "Outbound DNS and internet communication are strictly prohibited in the PAYGUARD synthetic lab."
        )
        logger.critical(error_msg)
        raise RuntimeError(error_msg)

    return _ORIGINAL_GETADDRINFO(host, port, *args, **kwargs)


def enable_network_isolation() -> None:
    """Activate socket- and DNS-level network isolation."""
    global _ISOLATION_ACTIVE
    if not _ISOLATION_ACTIVE:
        socket.socket.connect = _guarded_connect
        socket.create_connection = _guarded_create_connection
        socket.getaddrinfo = _guarded_getaddrinfo
        _ISOLATION_ACTIVE = True
        logger.info("PAYGUARD Network Isolation ACTIVE: Non-local outbound connections and DNS queries blocked.")


def disable_network_isolation() -> None:
    """Deactivate network isolation (for controlled testing teardown)."""
    global _ISOLATION_ACTIVE
    if _ISOLATION_ACTIVE:
        socket.socket.connect = _ORIGINAL_SOCKET_CONNECT
        socket.create_connection = _ORIGINAL_CREATE_CONNECTION
        socket.getaddrinfo = _ORIGINAL_GETADDRINFO
        _ISOLATION_ACTIVE = False
        logger.info("PAYGUARD Network Isolation deactivated.")


def is_network_isolation_active() -> bool:
    return _ISOLATION_ACTIVE
