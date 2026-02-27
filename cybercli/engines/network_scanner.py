"""
Asynchronous TCP network scanner.

This module provides functions to perform real network scans by attempting to
establish TCP connections to a list of ports on one or more hosts. It uses
Python's ``asyncio`` library to run connection attempts concurrently while
respecting a concurrency limit. The scanner returns a mapping of each host to
the list of ports that responded to a connection attempt.

The functions here do not perform SYN scans like Nmap and therefore require
complete connection handshakes. They are suitable for quick assessments of
open TCP services in controlled environments. For more advanced scanning
capabilities (UDP, service detection, OS fingerprinting, etc.), consider
integrating Nmap via the ``python-nmap`` library or system calls to ``nmap``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from typing import Dict, Iterable, List, Optional


async def _scan_port(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> Optional[int]:
    """Attempt to connect to a host:port and return the port if it is open.

    This helper function uses a semaphore to limit concurrency. It resolves the
    host to an IP address and creates a TCP connection. If the connection
    succeeds within the timeout, the port is considered open; otherwise it is
    closed or filtered.

    :param host: Hostname or IP address to scan.
    :param port: TCP port number to scan.
    :param timeout: Timeout in seconds for the connection attempt.
    :param sem: An asyncio.Semaphore controlling concurrency.
    :return: The port number if open, or ``None`` if closed or connection fails.
    """
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return port
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None


async def _scan_host(host: str, ports: Iterable[int], timeout: float, concurrency: int) -> List[int]:
    """Scan a single host for open TCP ports.

    :param host: Hostname or IP address.
    :param ports: Iterable of port numbers to check.
    :param timeout: Timeout in seconds per port.
    :param concurrency: Maximum number of simultaneous connection attempts.
    :return: Sorted list of open ports.
    """
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(_scan_port(host, port, timeout, sem)) for port in ports]
    results = await asyncio.gather(*tasks)
    return sorted([port for port in results if port is not None])


def scan_network(
    target: str,
    ports: List[int],
    timeout: float = 1.0,
    concurrency: int = 100,
) -> Dict[str, List[int]]:
    """Perform an asynchronous TCP port scan against a target range or host.

    :param target: CIDR notation (e.g. ``192.168.1.0/24``) or single IP/hostname.
    :param ports: List of ports to scan.
    :param timeout: Connection timeout in seconds.
    :param concurrency: Maximum concurrent connections across all hosts.
    :return: Mapping from each scanned host (as string) to a list of open ports.
    """
    # Determine list of hosts to scan
    try:
        # Try to interpret as network
        network = ipaddress.ip_network(target, strict=False)
        hosts = [str(ip) for ip in network.hosts()]
    except ValueError:
        # Not a network; treat as single host/IP
        hosts = [target]
    # Run scanning loop
    async def run():
        results: Dict[str, List[int]] = {}
        # Use separate semaphore per host but share concurrency across tasks
        sem = asyncio.Semaphore(concurrency)
        # Create tasks for each host
        host_tasks = []
        for host in hosts:
            task = asyncio.create_task(_scan_host(host, ports, timeout, concurrency))
            host_tasks.append((host, task))
        for host, task in host_tasks:
            open_ports = await task
            results[host] = open_ports
        return results
    return asyncio.run(run())