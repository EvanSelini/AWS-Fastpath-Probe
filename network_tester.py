"""
Network Tester

Tests network connectivity and measures latency using the 5-tuple.
"""

import asyncio
import re
import socket
import time
from typing import Tuple, Optional
import platform

from five_tuple import FiveTuple


class NetworkTester:
    """Tests network connections and measures latency."""
    
    def __init__(self):
        self.system = platform.system().lower()
    
    async def test_connection(
        self,
        five_tuple: FiveTuple,
        timeout: float = 5.0
    ) -> Tuple[float, bool, Optional[str]]:
        """
        Test a network connection using the 5-tuple.
        
        Args:
            five_tuple: The 5-tuple defining the connection
            timeout: Timeout in seconds
            
        Returns:
            Tuple of (latency_ms, success, error_message)
        """
        protocol = five_tuple.protocol.upper()
        
        if protocol == "TCP":
            return await self._test_tcp(five_tuple, timeout)
        elif protocol == "UDP":
            return await self._test_udp(five_tuple, timeout)
        else:
            return float('inf'), False, f"Unsupported protocol: {protocol}"
    
    async def _test_tcp(
        self,
        five_tuple: FiveTuple,
        timeout: float
    ) -> Tuple[float, bool, Optional[str]]:
        """Test TCP connection."""
        start_time = time.time()
        
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Bind to specific source IP and port if provided
            # This ensures packets go out the interface connected to the source IP
            bind_addr = ''
            if five_tuple.source_ip:
                bind_addr = five_tuple.source_ip
            
            if five_tuple.source_port and five_tuple.source_port != 0:
                try:
                    sock.bind((bind_addr, five_tuple.source_port))
                except OSError as e:
                    # Port might be in use, or IP not configured
                    if bind_addr:
                        raise Exception(f"Cannot bind to source IP {bind_addr}: {e}")
                    pass
            elif bind_addr:
                # Bind to source IP even if no specific port
                try:
                    sock.bind((bind_addr, 0))
                except OSError as e:
                    raise Exception(f"Cannot bind to source IP {bind_addr}: {e}")
            
            # Connect
            connect_start = time.time()
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sock.connect((five_tuple.dest_ip, five_tuple.dest_port))
            )
            connect_time = (time.time() - connect_start) * 1000  # Convert to ms
            
            # Get actual source port used (in case OS assigned different one)
            actual_source_port = sock.getsockname()[1]
            
            sock.close()
            
            # Return latency, success, error, and actual source port
            # Note: We'll need to modify the return type, but for now just return as before
            # The actual port will be captured in the PathResult
            return connect_time, True, None
            
        except socket.timeout:
            return float('inf'), False, "Connection timeout"
        except socket.gaierror as e:
            return float('inf'), False, f"DNS resolution error: {e}"
        except ConnectionRefusedError:
            return float('inf'), False, "Connection refused"
        except Exception as e:
            return float('inf'), False, f"TCP error: {str(e)}"
    
    async def _test_udp(
        self,
        five_tuple: FiveTuple,
        timeout: float
    ) -> Tuple[float, bool, Optional[str]]:
        """Test UDP connection (sends packet and measures RTT)."""
        start_time = time.time()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            
            # Bind to specific source IP and port if provided
            # This ensures packets go out the interface connected to the source IP
            bind_addr = ''
            if five_tuple.source_ip:
                bind_addr = five_tuple.source_ip
            
            if five_tuple.source_port and five_tuple.source_port != 0:
                try:
                    sock.bind((bind_addr, five_tuple.source_port))
                except OSError as e:
                    # Port might be in use, or IP not configured
                    if bind_addr:
                        raise Exception(f"Cannot bind to source IP {bind_addr}: {e}")
                    pass
            elif bind_addr:
                # Bind to source IP even if no specific port
                try:
                    sock.bind((bind_addr, 0))
                except OSError as e:
                    raise Exception(f"Cannot bind to source IP {bind_addr}: {e}")
            
            # Send a test packet
            test_data = b"TEST"
            send_start = time.time()
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: sock.sendto(test_data, (five_tuple.dest_ip, five_tuple.dest_port))
            )
            
            # Try to receive response (many UDP services won't respond)
            try:
                await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None,
                        lambda: sock.recvfrom(1024)
                    ),
                    timeout=timeout
                )
                rtt = (time.time() - send_start) * 1000
                sock.close()
                return rtt, True, None
            except asyncio.TimeoutError:
                # UDP often doesn't get a response, but packet was sent
                send_time = (time.time() - send_start) * 1000
                sock.close()
                # Consider it successful if we can send (latency is send time)
                return send_time, True, "No response (UDP)"
            
        except socket.timeout:
            return float('inf'), False, "UDP timeout"
        except Exception as e:
            return float('inf'), False, f"UDP error: {str(e)}"
