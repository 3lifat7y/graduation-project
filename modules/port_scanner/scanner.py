#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DDoS-Guard: Independent High-Performance Port & Network Scanner Engine
Architecture: Pure Python standard library implementation (asyncio, socket, ipaddress).
Completely decoupled and isolated from the DDoS monitoring core, WinDivert, IPC, and ML models.
"""

import sys
import time
import socket
import asyncio
import ipaddress
import threading
from typing import Dict, List, Optional, Tuple, Any, Callable

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')


# ==============================================================================
# 1. Comprehensive Port & Service Registry (150+ Standard Services)
# ==============================================================================
COMMON_SERVICES: Dict[int, str] = {
    # Core Infrastructure & Remote Management
    20: "FTP-Data",
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet",
    25: "SMTP (Simple Mail Transfer)",
    53: "DNS (Domain Name System)",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP (Trivial File Transfer)",
    80: "HTTP (World Wide Web)",
    88: "Kerberos",
    110: "POP3 (Post Office Protocol v3)",
    111: "RPCBind / Portmapper",
    123: "NTP (Network Time Protocol)",
    135: "Microsoft EPMAP / RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP (Internet Message Access)",
    161: "SNMP (Simple Network Management)",
    162: "SNMP-Trap",
    179: "BGP (Border Gateway Protocol)",
    194: "IRC (Internet Relay Chat)",
    389: "LDAP (Lightweight Directory Access)",
    443: "HTTPS (HTTP Secure / SSL)",
    445: "Microsoft-DS / SMB",
    465: "SMTPS (SMTP over SSL)",
    500: "ISAKMP / IKE (IPsec)",
    514: "Syslog",
    515: "LPD (Printer Daemon)",
    587: "SMTP (Mail Submission)",
    636: "LDAPS (LDAP over SSL)",
    873: "Rsync",
    990: "FTPS (FTP over SSL)",
    993: "IMAPS (IMAP over SSL)",
    995: "POP3S (POP3 over SSL)",
    1080: "SOCKS Proxy",
    
    # Databases & Caching Engines
    1433: "Microsoft SQL Server (MSSQL)",
    1434: "Microsoft SQL Monitor",
    1521: "Oracle Database",
    2049: "NFS (Network File System)",
    2375: "Docker REST API (Plain)",
    2376: "Docker REST API (TLS)",
    3000: "Node.js / React Dev Server",
    3306: "MySQL Database",
    3389: "Microsoft RDP (Remote Desktop)",
    4369: "Erlang Port Mapper (EPMD)",
    5000: "Flask / DDoS-Guard Dashboard",
    5050: "Mesh / IPC",
    5432: "PostgreSQL Database",
    5672: "RabbitMQ (AMQP)",
    5900: "VNC (Virtual Network Computing)",
    5985: "WinRM (Windows Remote Management HTTP)",
    5986: "WinRM (Windows Remote Management HTTPS)",
    6379: "Redis In-Memory Store",
    6443: "Kubernetes API Server",
    7000: "Cassandra Inter-Node",
    7001: "Cassandra SSL",
    8000: "HTTP Alternate / Django / Web",
    8080: "HTTP Alternate / Tomcat / Proxy",
    8443: "HTTPS Alternate",
    8888: "Jupyter Notebook / Web Server",
    9000: "SonarQube / Portainer / PHP-FPM",
    9092: "Apache Kafka",
    9200: "Elasticsearch REST API",
    9300: "Elasticsearch Cluster",
    11211: "Memcached",
    15672: "RabbitMQ Management Web UI",
    27017: "MongoDB Database",
    27018: "MongoDB Shard",
    28017: "MongoDB Web Status",
    50505: "DDoS-Guard Windows Service IPC"
}

# Standard Port Presets
TOP_20_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
    443, 445, 1433, 1521, 3306, 3389, 5000, 5432, 8080, 8443
]

TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
    646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1521, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900,
    6000, 6001, 6379, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9000, 9090, 9100, 9200, 9999, 10000, 27017, 32768
]

# Fast Liveness Discovery Ports (Used to identify live hosts on local subnets rapidly)
LIVENESS_PROBE_PORTS = [80, 443, 445, 135, 22, 8080, 3389, 53]


def get_service_name(port: int) -> str:
    """Returns friendly service name with socket fallback."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp").upper()
    except Exception:
        return "Unknown"


# ==============================================================================
# 2. Input Validation & Parsing Helpers
# ==============================================================================
def parse_port_selection(mode: str, custom_ports_str: Optional[str] = None) -> List[int]:
    """
    Parses and sanitizes port selections.
    Modes:
      - 'top20': 20 most critical services
      - 'top100': 100 most common services
      - 'wellknown': 1 through 1024
      - 'custom': User-defined list e.g. "80, 443, 8080, 3000-3005"
    """
    mode = str(mode).lower().strip()
    if mode == "top20":
        return sorted(list(set(TOP_20_PORTS)))
    elif mode == "top100":
        return sorted(list(set(TOP_100_PORTS)))
    elif mode == "wellknown":
        return list(range(1, 1025))
    elif mode == "custom":
        if not custom_ports_str or not custom_ports_str.strip():
            raise ValueError("Custom ports string cannot be empty.")
        
        ports = set()
        parts = custom_ports_str.split(",")
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                tokens = part.split("-")
                if len(tokens) != 2:
                    raise ValueError(f"Invalid port range format: '{part}'")
                start, end = int(tokens[0].strip()), int(tokens[1].strip())
                if start > end:
                    start, end = end, start
                if start < 1 or end > 65535:
                    raise ValueError(f"Port range out of bounds [1-65535]: '{part}'")
                if (end - start) > 2500:
                    raise ValueError(f"Port range too large (max 2500 ports per range): '{part}'")
                ports.update(range(start, end + 1))
            else:
                p = int(part)
                if p < 1 or p > 65535:
                    raise ValueError(f"Port number out of bounds [1-65535]: {p}")
                ports.add(p)

        if not ports:
            raise ValueError("No valid ports parsed from custom input.")
        if len(ports) > 3000:
            raise ValueError(f"Total number of custom ports ({len(ports)}) exceeds safe session limit of 3000.")
        return sorted(list(ports))
    else:
        raise ValueError(f"Unrecognized ports mode: '{mode}'. Expected: top20, top100, wellknown, or custom.")


def validate_and_resolve_target(scan_type: str, raw_target: str) -> Tuple[str, Optional[ipaddress.IPv4Network]]:
    """
    Validates and sanitizes scan targets strictly according to the scan type.
    Returns: (resolved_target_str, optional_network_object)
    """
    scan_type = str(scan_type).lower().strip()
    raw_target = str(raw_target).strip()

    if scan_type == "localhost":
        # Strictly fixed to 127.0.0.1 for local host safety
        return "127.0.0.1", None

    elif scan_type == "target_ip":
        if not raw_target:
            raise ValueError("Target IP address or hostname is required.")
        # Attempt IPv4 resolution
        try:
            # Check if it's already a valid IP string
            ip_obj = ipaddress.ip_address(raw_target)
            if ip_obj.version != 4:
                raise ValueError("Only IPv4 addresses are currently supported.")
            return str(ip_obj), None
        except ValueError:
            # Attempt DNS resolution for hostname
            try:
                resolved_ip = socket.gethostbyname(raw_target)
                return resolved_ip, None
            except socket.gaierror:
                raise ValueError(f"Could not resolve hostname or IP address: '{raw_target}'")

    elif scan_type == "network":
        if not raw_target:
            raise ValueError("Network CIDR subnet is required (e.g. 192.168.1.0/24).")
        try:
            net = ipaddress.ip_network(raw_target, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid network CIDR specification: '{raw_target}' ({e})")

        if net.version != 4:
            raise ValueError("Only IPv4 subnets are currently supported.")

        # Enforce safety restrictions: Max /24 (256 addresses)
        if net.prefixlen < 24:
            raise ValueError(
                f"Subnet /{net.prefixlen} is too large. For performance and network safety, "
                f"maximum allowed subnet size is /24 (up to 256 addresses)."
            )

        # Restrict Network Scan to Private / Local networks (RFC 1918 + Loopback)
        if not (net.is_private or net.is_loopback):
            raise ValueError(
                f"Network scanning is restricted to private RFC 1918 subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) "
                f"or loopback. Scanning public subnet '{net}' is not permitted."
            )

        return str(net), net

    else:
        raise ValueError(f"Unrecognized scan_type: '{scan_type}'. Expected: localhost, target_ip, or network.")


# ==============================================================================
# 3. Asyncio Core Scanning Primitives (Zero External Dependencies)
# ==============================================================================
async def probe_single_port(ip: str, port: int, timeout: float = 0.5) -> Dict[str, Any]:
    """
    Tests TCP connectivity on (ip, port) and performs non-intrusive banner grabbing.
    Returns port status dictionary.
    Accurately classifies state:
      - 'open': TCP handshake completed successfully
      - 'closed': Explicit TCP RST received from host stack
      - 'filtered': TCP connection timed out with no response
      - 'error': Socket or network error (e.g. host unreachable, network down)
    """
    start_t = time.perf_counter()
    service = get_service_name(port)

    conn_coro = asyncio.open_connection(ip, port)
    try:
        reader, writer = await asyncio.wait_for(conn_coro, timeout=timeout)
        rtt_ms = round((time.perf_counter() - start_t) * 1000, 1)
        banner = ""

        # Non-intrusive banner grabbing for open ports
        try:
            # 1. Send HTTP HEAD for web ports
            if port in [80, 8080, 8000, 3000, 5000]:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: DDoS-Guard-Scanner\r\n\r\n")
                await writer.drain()

            # Read initial greeting or response banner with short timeout
            banner_bytes = await asyncio.wait_for(reader.read(256), timeout=0.35)
            if banner_bytes:
                # Sanitize printable characters
                decoded = banner_bytes.decode("utf-8", errors="ignore").strip()
                first_line = decoded.split("\r\n")[0].split("\n")[0].strip()
                banner = first_line[:90]
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

        return {
            "port": port,
            "protocol": "TCP",
            "state": "open",
            "service": service,
            "banner": banner,
            "latency_ms": rtt_ms
        }

    except asyncio.TimeoutError:
        return {
            "port": port,
            "protocol": "TCP",
            "state": "filtered",
            "service": service,
            "banner": "",
            "latency_ms": None
        }
    except ConnectionRefusedError:
        # Explicit TCP RST received
        return {
            "port": port,
            "protocol": "TCP",
            "state": "closed",
            "service": service,
            "banner": "",
            "latency_ms": None
        }
    except OSError as e:
        err_code = getattr(e, 'winerror', None) or getattr(e, 'errno', None)
        # Windows: WSAECONNREFUSED (10061); POSIX: ECONNREFUSED (111, 61)
        if err_code in (10061, 111, 61):
            return {
                "port": port,
                "protocol": "TCP",
                "state": "closed",
                "service": service,
                "banner": "",
                "latency_ms": None
            }
        # Windows: WSAETIMEDOUT (10060); POSIX: ETIMEDOUT (110)
        elif err_code in (10060, 110):
            return {
                "port": port,
                "protocol": "TCP",
                "state": "filtered",
                "service": service,
                "banner": "",
                "latency_ms": None
            }
        else:
            return {
                "port": port,
                "protocol": "TCP",
                "state": "error",
                "service": service,
                "banner": f"Network error ({err_code})",
                "latency_ms": None
            }
    except Exception as e:
        return {
            "port": port,
            "protocol": "TCP",
            "state": "error",
            "service": service,
            "banner": f"Scan error: {str(e)[:40]}",
            "latency_ms": None
        }


async def probe_host_liveness(ip: str, timeout: float = 0.3) -> bool:
    """
    Rapidly tests if a host is alive by probing primary local ports.
    If ANY port opens or responds with RST (ConnectionRefused / 10061), host is ALIVE.
    """
    for p in LIVENESS_PROBE_PORTS:
        try:
            conn_coro = asyncio.open_connection(ip, p)
            reader, writer = await asyncio.wait_for(conn_coro, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except ConnectionRefusedError:
            # Explicit RST packet received -> Host network stack is ALIVE!
            return True
        except asyncio.TimeoutError:
            continue
        except OSError as e:
            err_code = getattr(e, 'winerror', None) or getattr(e, 'errno', None)
            if err_code in (10061, 111, 61):
                return True
            continue
        except Exception:
            continue
    return False


# ==============================================================================
# 4. Thread-Safe Port Scanner Manager & Lifecycle Orchestrator
# ==============================================================================
class PortScannerManager:
    """
    Fully isolated, thread-safe asynchronous port scanner controller.
    Runs its own dedicated background thread and asyncio event loop.
    Guaranteed zero interaction with DDoS-Guard's WinDivert, IPC, or AI model.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._stop_event = asyncio.Event()
        self._worker_thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._is_running = False
        self.last_completed_scan: Optional[Dict[str, Any]] = None

        # Independent session state
        self.session: Dict[str, Any] = {
            "status": "ready",           # ready, scanning, completed, stopped, error
            "scan_id": None,
            "scan_type": None,           # localhost, target_ip, network
            "target": None,
            "resolved_ip": None,
            "started_at": None,
            "completed_at": None,
            "completed_at_str": None,
            "duration_s": 0.0,
            "progress_pct": 0.0,
            "scanned_ports": 0,
            "total_ports": 0,
            "open_ports_count": 0,
            "active_hosts_count": 0,
            "results": [],               # List of host result dictionaries
            "last_completed_scan": None,
            "error": None,
            "message": "Port Scanner ready."
        }

    def get_status(self) -> Dict[str, Any]:
        """Thread-safe snapshot of the current scan session."""
        with self._lock:
            state = dict(self.session)
            state["results"] = list(self.session.get("results", []))
            state["last_completed_scan"] = dict(self.last_completed_scan) if self.last_completed_scan else None
            if state.get("status") == "scanning" and state.get("started_at"):
                state["duration_s"] = round(time.time() - state["started_at"], 1)
            return state

    def start_scan(
        self,
        scan_type: str = "localhost",
        target: Optional[str] = None,
        ports_mode: str = "top20",
        custom_ports: Optional[str] = None,
        timeout: float = 0.5,
        concurrency: int = 150
    ) -> Dict[str, Any]:
        """Validates input, resets state, and initiates scan on a dedicated daemon thread."""
        with self._lock:
            if self._is_running:
                return {
                    "status": "already_scanning",
                    "message": "A port scan is already actively running.",
                    "scan_id": self.session.get("scan_id")
                }

            # 1. If previous scan completed, snapshot into last_completed_scan first
            if self.session.get("status") == "completed" and self.session.get("scan_id"):
                self.last_completed_scan = {
                    "scan_id": self.session.get("scan_id"),
                    "scan_type": self.session.get("scan_type"),
                    "target": self.session.get("target"),
                    "resolved_target": self.session.get("resolved_target"),
                    "ports_mode": self.session.get("ports_mode"),
                    "completed_at": self.session.get("completed_at"),
                    "completed_at_str": self.session.get("completed_at_str"),
                    "duration_s": self.session.get("duration_s", 0.0),
                    "open_ports_count": self.session.get("open_ports_count", 0),
                    "total_ports": self.session.get("total_ports", 0),
                    "active_hosts_count": self.session.get("active_hosts_count", 0),
                    "results": list(self.session.get("results", []))
                }

            # 2. Rescan fallback if target is empty and a previous scan exists
            target_str = (target or "").strip()
            if not target_str and self.last_completed_scan:
                target_str = self.last_completed_scan.get("target") or "127.0.0.1"
                scan_type = self.last_completed_scan.get("scan_type") or scan_type
                ports_mode = self.last_completed_scan.get("ports_mode") or ports_mode
            elif not target_str:
                target_str = "127.0.0.1" if scan_type == "localhost" else ""

            # 1. Validate inputs
            resolved_target, net_obj = validate_and_resolve_target(scan_type, target_str)
            ports = parse_port_selection(ports_mode, custom_ports)
            concurrency = max(10, min(concurrency, 300))
            timeout = max(0.1, min(timeout, 3.0))

            scan_id = f"pscan_{int(time.time() * 1000)}"

            # 2. Reset session state
            self.session.update({
                "status": "scanning",
                "scan_id": scan_id,
                "scan_type": scan_type,
                "target": target_str,
                "resolved_target": resolved_target,
                "ports_mode": ports_mode,
                "ports_count_per_host": len(ports),
                "started_at": time.time(),
                "completed_at": None,
                "completed_at_str": None,
                "duration_s": 0.0,
                "progress_pct": 0.0,
                "scanned_ports": 0,
                "total_ports": len(ports) if scan_type != "network" else 0,
                "open_ports_count": 0,
                "active_hosts_count": 0,
                "results": [],
                "last_completed_scan": self.last_completed_scan,
                "error": None,
                "message": f"Starting {scan_type} scan on {resolved_target}..."
            })
            self._is_running = True

        # 3. Launch background daemon thread
        self._worker_thread = threading.Thread(
            target=self._run_async_worker,
            args=(scan_id, scan_type, resolved_target, net_obj, ports, timeout, concurrency),
            daemon=True
        )
        self._worker_thread.start()

        return {
            "status": "started",
            "scan_id": scan_id,
            "scan_type": scan_type,
            "target": target_str,
            "resolved_target": resolved_target,
            "total_ports": len(ports)
        }

    def stop_scan(self) -> Dict[str, Any]:
        """Cooperatively signals immediate cancellation to the async engine."""
        with self._lock:
            if not self._is_running:
                return {"status": "not_running", "message": "No active port scan to stop."}

            self.session.update({
                "status": "stopped",
                "message": "Scan cancelled by user."
            })
            if self.session.get("started_at"):
                self.session["duration_s"] = round(time.time() - self.session["started_at"], 2)
            self._is_running = False

        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._stop_event.set)

        return {"status": "stopped", "message": "Port scan cancelled successfully."}

    def _run_async_worker(
        self,
        scan_id: str,
        scan_type: str,
        target_str: str,
        net_obj: Optional[ipaddress.IPv4Network],
        ports: List[int],
        timeout: float,
        concurrency: int
    ):
        """Worker thread entrypoint establishing a clean, isolated asyncio event loop."""
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._stop_event = asyncio.Event()

        try:
            self._loop.run_until_complete(
                self._execute_scan(scan_id, scan_type, target_str, net_obj, ports, timeout, concurrency)
            )
        except Exception as e:
            with self._lock:
                if self.session.get("scan_id") == scan_id:
                    self.session.update({
                        "status": "error",
                        "error": str(e),
                        "message": f"Port scanner error: {e}"
                    })
        finally:
            with self._lock:
                self._is_running = False
            self._loop.close()

    async def _execute_scan(
        self,
        scan_id: str,
        scan_type: str,
        target_str: str,
        net_obj: Optional[ipaddress.IPv4Network],
        ports: List[int],
        timeout: float,
        concurrency: int
    ):
        """Asynchronous execution dispatcher for single-host or multi-host subnet scanning."""
        semaphore = asyncio.Semaphore(concurrency)

        # ----------------------------------------------------------------------
        # MODE 1 & 2: Localhost or Target IP Scan (Single Host)
        # ----------------------------------------------------------------------
        if scan_type in ["localhost", "target_ip"]:
            total_ports = len(ports)
            scanned_so_far = 0
            open_results = []
            all_port_results = []

            async def scan_task(p: int):
                nonlocal scanned_so_far
                if self._stop_event.is_set():
                    return None
                async with semaphore:
                    if self._stop_event.is_set():
                        return None
                    res = await probe_single_port(target_str, p, timeout)
                    scanned_so_far += 1
                    pct = round((scanned_so_far / total_ports) * 100, 1)

                    with self._lock:
                        if self.session.get("scan_id") == scan_id and self.session.get("status") == "scanning":
                            self.session["scanned_ports"] = scanned_so_far
                            self.session["progress_pct"] = pct
                    return res

            tasks = [scan_task(p) for p in ports]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, dict) and r.get("state") == "open":
                    open_results.append(r)
                if isinstance(r, dict):
                    all_port_results.append(r)

            open_results.sort(key=lambda x: x["port"])
            all_port_results.sort(key=lambda x: x["port"])

            # Resolve reverse hostname if possible
            hostname = target_str
            try:
                hostname = socket.gethostbyaddr(target_str)[0]
            except Exception:
                pass

            host_entry = {
                "host": target_str,
                "hostname": hostname,
                "status": "online",
                "open_ports_count": len(open_results),
                "total_scanned_ports": len(all_port_results),
                "open_ports": open_results,
                "all_ports": all_port_results
            }

            completed_time = time.time()
            completed_str = time.strftime("%H:%M:%S")
            completed_record = {
                "scan_id": scan_id,
                "scan_type": scan_type,
                "target": target_str,
                "resolved_target": target_str,
                "ports_mode": self.session.get("ports_mode"),
                "completed_at": completed_time,
                "completed_at_str": completed_str,
                "duration_s": round(completed_time - self.session["started_at"], 2),
                "open_ports_count": len(open_results),
                "total_ports": total_ports,
                "active_hosts_count": 1,
                "results": [host_entry]
            }

            with self._lock:
                if self.session.get("scan_id") == scan_id and self.session.get("status") == "scanning":
                    self.last_completed_scan = completed_record
                    self.session.update({
                        "status": "completed",
                        "progress_pct": 100.0,
                        "scanned_ports": total_ports,
                        "open_ports_count": len(open_results),
                        "active_hosts_count": 1,
                        "results": [host_entry],
                        "completed_at": completed_time,
                        "completed_at_str": completed_str,
                        "last_completed_scan": completed_record,
                        "duration_s": round(completed_time - self.session["started_at"], 2),
                        "message": f"Scan completed. Found {len(open_results)} open port(s) on {target_str}."
                    })

        # ----------------------------------------------------------------------
        # MODE 3: Network Subnet Scan (Two-Phase Host Discovery + Port Scan)
        # ----------------------------------------------------------------------
        elif scan_type == "network" and net_obj is not None:
            # Phase 1: Host Liveness Discovery across usable subnet IPs
            hosts_to_probe = [str(ip) for ip in net_obj.hosts()]
            total_hosts = len(hosts_to_probe)

            with self._lock:
                if self.session.get("scan_id") == scan_id:
                    self.session["message"] = f"Phase 1/2: Discovering active hosts on {net_obj} ({total_hosts} addresses)..."

            discovered_live_hosts = []
            hosts_checked = 0

            async def liveness_task(host_ip: str):
                nonlocal hosts_checked
                if self._stop_event.is_set():
                    return None
                async with semaphore:
                    if self._stop_event.is_set():
                        return None
                    is_alive = await probe_host_liveness(host_ip, timeout=0.35)
                    hosts_checked += 1
                    phase1_pct = round((hosts_checked / total_hosts) * 40.0, 1)  # Phase 1 is 40% of overall progress

                    with self._lock:
                        if self.session.get("scan_id") == scan_id and self.session.get("status") == "scanning":
                            self.session["progress_pct"] = phase1_pct
                    if is_alive:
                        return host_ip
                return None

            liveness_tasks = [liveness_task(h) for h in hosts_to_probe]
            liveness_results = await asyncio.gather(*liveness_tasks, return_exceptions=True)

            for res in liveness_results:
                if isinstance(res, str) and res:
                    discovered_live_hosts.append(res)

            with self._lock:
                if self.session.get("scan_id") == scan_id:
                    self.session["active_hosts_count"] = len(discovered_live_hosts)
                    self.session["message"] = (
                        f"Phase 2/2: Found {len(discovered_live_hosts)} active host(s). "
                        f"Enumerating ports..."
                    )

            if not discovered_live_hosts:
                completed_time = time.time()
                completed_str = time.strftime("%H:%M:%S")
                completed_record = {
                    "scan_id": scan_id,
                    "scan_type": scan_type,
                    "target": str(net_obj),
                    "resolved_target": str(net_obj),
                    "ports_mode": self.session.get("ports_mode"),
                    "completed_at": completed_time,
                    "completed_at_str": completed_str,
                    "duration_s": round(completed_time - self.session["started_at"], 2),
                    "open_ports_count": 0,
                    "total_ports": 0,
                    "active_hosts_count": 0,
                    "results": []
                }
                with self._lock:
                    if self.session.get("scan_id") == scan_id and self.session.get("status") == "scanning":
                        self.last_completed_scan = completed_record
                        self.session.update({
                            "status": "completed",
                            "progress_pct": 100.0,
                            "active_hosts_count": 0,
                            "open_ports_count": 0,
                            "results": [],
                            "completed_at": completed_time,
                            "completed_at_str": completed_str,
                            "last_completed_scan": completed_record,
                            "duration_s": round(completed_time - self.session["started_at"], 2),
                            "message": f"Network scan completed. No active hosts responded in {net_obj}."
                        })
                return

            # Phase 2: Port Enumeration on discovered live hosts only
            total_port_checks = len(discovered_live_hosts) * len(ports)
            port_checks_done = 0
            all_network_results = []
            total_open_across_network = 0

            with self._lock:
                if self.session.get("scan_id") == scan_id:
                    self.session["total_ports"] = total_port_checks

            for host_ip in discovered_live_hosts:
                if self._stop_event.is_set():
                    break

                host_open = []
                host_all = []

                async def host_port_task(p: int):
                    nonlocal port_checks_done
                    if self._stop_event.is_set():
                        return None
                    async with semaphore:
                        if self._stop_event.is_set():
                            return None
                        pres = await probe_single_port(host_ip, p, timeout)
                        port_checks_done += 1
                        # Phase 2 covers progress 40% to 100%
                        phase2_pct = round(40.0 + ((port_checks_done / total_port_checks) * 60.0), 1)

                        with self._lock:
                            if self.session.get("scan_id") == scan_id and self.session.get("status") == "scanning":
                                self.session["scanned_ports"] = port_checks_done
                                self.session["progress_pct"] = phase2_pct
                        return pres

                host_tasks = [host_port_task(p) for p in ports]
                host_port_results = await asyncio.gather(*host_tasks, return_exceptions=True)

                for r in host_port_results:
                    if isinstance(r, dict) and r.get("state") == "open":
                        host_open.append(r)
                    if isinstance(r, dict):
                        host_all.append(r)

                host_open.sort(key=lambda x: x["port"])
                host_all.sort(key=lambda x: x["port"])
                total_open_across_network += len(host_open)

                hostname = host_ip
                try:
                    hostname = socket.gethostbyaddr(host_ip)[0]
                except Exception:
                    pass

                host_entry = {
                    "host": host_ip,
                    "hostname": hostname,
                    "status": "online",
                    "open_ports_count": len(host_open),
                    "total_scanned_ports": len(host_all),
                    "open_ports": host_open,
                    "all_ports": host_all
                }
                all_network_results.append(host_entry)

                with self._lock:
                    if self.session.get("scan_id") == scan_id and self.session.get("status") == "scanning":
                        self.session["results"] = list(all_network_results)
                        self.session["open_ports_count"] = total_open_across_network

            completed_time = time.time()
            completed_str = time.strftime("%H:%M:%S")
            completed_record = {
                "scan_id": scan_id,
                "scan_type": scan_type,
                "target": str(net_obj),
                "resolved_target": str(net_obj),
                "ports_mode": self.session.get("ports_mode"),
                "completed_at": completed_time,
                "completed_at_str": completed_str,
                "duration_s": round(completed_time - self.session["started_at"], 2),
                "open_ports_count": total_open_across_network,
                "total_ports": total_port_checks,
                "active_hosts_count": len(discovered_live_hosts),
                "results": all_network_results
            }

            with self._lock:
                if self.session.get("scan_id") == scan_id and self.session.get("status") == "scanning":
                    self.last_completed_scan = completed_record
                    self.session.update({
                        "status": "completed",
                        "progress_pct": 100.0,
                        "scanned_ports": total_port_checks,
                        "open_ports_count": total_open_across_network,
                        "active_hosts_count": len(discovered_live_hosts),
                        "results": all_network_results,
                        "completed_at": completed_time,
                        "completed_at_str": completed_str,
                        "last_completed_scan": completed_record,
                        "duration_s": round(completed_time - self.session["started_at"], 2),
                        "message": (
                            f"Network scan complete: Discovered {len(discovered_live_hosts)} active host(s) "
                            f"with {total_open_across_network} open port(s) in {net_obj}."
                        )
                    })


# Global singleton instance for the port scanner manager
port_scanner_manager = PortScannerManager()
