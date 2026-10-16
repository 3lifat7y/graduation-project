"""
Common Utilities & Network Interface Detection Package
"""

from .network_detector import (
    auto_detect_primary_interface,
    get_active_routable_ip,
    check_capture_drivers,
    is_admin_user,
    find_tshark_path,
)

__all__ = [
    "auto_detect_primary_interface",
    "get_active_routable_ip",
    "check_capture_drivers",
    "is_admin_user",
    "find_tshark_path",
]
