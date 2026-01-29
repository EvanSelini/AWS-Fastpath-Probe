#!/usr/bin/env python3
"""
Fastest Path Finder - AWS Region Network Path Analyzer

This application finds the fastest network path between two IP addresses
across AWS regions, considering the 5-tuple networking concept.
"""

import argparse
import asyncio
import csv
import os
import random
import socket
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime

from network_tester import NetworkTester
from aws_region_mapper import AWSRegionMapper
from five_tuple import FiveTuple


@dataclass
class PathResult:
    """Result of a network path test."""
    source_ip: str
    dest_ip: str
    source_region: str
    dest_region: str
    five_tuple: FiveTuple
    latency_ms: float
    success: bool
    error: Optional[str] = None
    timestamp: datetime = None
    actual_source_port: Optional[int] = None  # Track actual port used

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class FastestPathFinder:
    """Main class for finding fastest paths between IPs across AWS regions."""
    
    def __init__(self):
        self.region_mapper = AWSRegionMapper()
        self.network_tester = NetworkTester()
        self.local_ip = None
        self.local_region = None
        self.port_range = self._get_port_range()
    
    def _get_port_range(self) -> Tuple[int, int]:
        """Get the local port range from /proc/sys/net/ipv4/ip_local_port_range."""
        try:
            with open('/proc/sys/net/ipv4/ip_local_port_range', 'r') as f:
                content = f.read().strip()
                min_port, max_port = map(int, content.split())
                return (min_port, max_port)
        except (FileNotFoundError, IOError, ValueError):
            # Fallback to default ephemeral port range
            # Linux default is usually 32768-60999
            return (32768, 60999)
    
    def select_source_ports(self, sample_size: int = 300) -> List[int]:
        """Select random sample of source ports from the ephemeral port range."""
        min_port, max_port = self.port_range
        total = max_port - min_port + 1
        
        if sample_size >= total:
            # If sample size exceeds range, use all ports
            return list(range(min_port, max_port + 1))
        
        # Random sampling without replacement
        return random.sample(range(min_port, max_port + 1), sample_size)
    
    def _get_local_ip(self) -> str:
        """Get the local machine's public IP address."""
        if self.local_ip:
            return self.local_ip
        
        try:
            # Connect to a remote server to determine local IP
            # This gets the IP used for outbound connections
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            try:
                # Doesn't actually connect, just determines route
                s.connect(('8.8.8.8', 80))
                self.local_ip = s.getsockname()[0]
            except Exception:
                # Fallback: try to get hostname IP
                self.local_ip = socket.gethostbyname(socket.gethostname())
            finally:
                s.close()
        except Exception:
            self.local_ip = "unknown"
        
        return self.local_ip
    
    async def _get_local_region(self) -> List[str]:
        """Get the AWS region(s) for the local machine."""
        if self.local_region:
            return self.local_region
        
        local_ip = self._get_local_ip()
        if local_ip and local_ip != "unknown":
            self.local_region = await self.region_mapper.get_regions_for_ip(local_ip)
        else:
            self.local_region = ["unknown"]
        
        return self.local_region
    
    async def find_fastest_path(
        self,
        source_ip: str,
        dest_ip: str,
        protocol: str = "TCP",
        source_port: Optional[int] = None,
        dest_port: Optional[int] = None,
        test_count: int = 3,
        timeout: float = 5.0
    ) -> Tuple[PathResult, List[PathResult]]:
        """
        Find the fastest path between two IPs across AWS regions.
        
        Args:
            source_ip: Source IP address
            dest_ip: Destination IP address
            protocol: Protocol (TCP, UDP)
            source_port: Source port (optional)
            dest_port: Destination port (required for TCP/UDP)
            test_count: Number of tests per path
            timeout: Timeout per test in seconds
            
        Returns:
            Tuple of (fastest_path_result, all_results)
        """
        # Detect local machine's region (where tests will run from)
        local_regions = await self._get_local_region()
        local_ip = self._get_local_ip()
        
        # Detect regions for both IPs
        source_regions = await self.region_mapper.get_regions_for_ip(source_ip)
        dest_regions = await self.region_mapper.get_regions_for_ip(dest_ip)
        
        print(f"\nTesting from local machine:")
        print(f"   Local IP: {local_ip}")
        print(f"   Local region(s): {local_regions}")
        print(f"\nTarget path:")
        print(f"   Source IP {source_ip} detected in regions: {source_regions}")
        print(f"   Destination IP {dest_ip} detected in regions: {dest_regions}")
        
        # Warn if source IP doesn't match local machine
        if source_ip != local_ip and local_ip != "unknown":
            print(f"\nWARNING: Tests are running from local machine ({local_ip})")
            print(f"   but source IP is specified as {source_ip}.")
            print(f"   To accurately test region X → region Y, run this script from a host in region X.")
            print(f"   Current tests measure: {local_regions} → {dest_regions}")
        
        # Generate 5-tuple configurations
        five_tuples = self._generate_five_tuples(
            source_ip, dest_ip, protocol, source_port, dest_port
        )
        
        # Test all paths
        all_results = []
        tasks = []
        
        for five_tuple in five_tuples:
            for source_region in source_regions:
                for dest_region in dest_regions:
                    task = self._test_path(
                        five_tuple, source_region, dest_region, test_count, timeout
                    )
                    tasks.append(task)
        
        # Run all tests concurrently
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, Exception):
                print(f"Error in path test: {result}", file=sys.stderr)
            elif result:
                all_results.extend(result)
        
        # Find fastest successful path
        successful_results = [r for r in all_results if r.success]
        
        if not successful_results:
            print("No successful paths found!", file=sys.stderr)
            return None, all_results
        
        fastest = min(successful_results, key=lambda x: x.latency_ms)
        
        return fastest, all_results
    
    def _generate_five_tuples(
        self,
        source_ip: str,
        dest_ip: str,
        protocol: str,
        source_port: Optional[int],
        dest_port: Optional[int]
    ) -> List[FiveTuple]:
        """Generate 5-tuple configurations to test."""
        five_tuples = []
        
        # Default ports based on protocol
        if protocol.upper() == "TCP":
            if dest_port is None:
                dest_port = 80  # Default HTTP
            # Source port will be set dynamically during testing
        elif protocol.upper() == "UDP":
            if dest_port is None:
                dest_port = 53  # Default DNS
            # Source port will be set dynamically during testing
        
        # For TCP/UDP, we'll use dynamic source ports, so set to None here
        # The actual port will be assigned during connection
        if protocol.upper() in ["TCP", "UDP"]:
            source_port = None
        
        five_tuple = FiveTuple(
            source_ip=source_ip,
            dest_ip=dest_ip,
            source_port=source_port,
            dest_port=dest_port,
            protocol=protocol.upper()
        )
        five_tuples.append(five_tuple)
        
        return five_tuples
    
    
    async def find_fastest_to_multiple_destinations(
        self,
        source_ip: str,
        dest_ips: List[str],
        protocol: str = "TCP",
        source_port: Optional[int] = None,
        dest_port: Optional[int] = None,
        test_count: int = 3,
        timeout: float = 5.0
    ) -> List[Tuple[str, Optional[PathResult], List[PathResult]]]:
        """
        Find fastest path from source to multiple destinations.
        
        Args:
            source_ip: Source IP address
            dest_ips: List of destination IP addresses to test
            protocol: Protocol (TCP, UDP)
            source_port: Source port (optional)
            dest_port: Destination port (required for TCP/UDP)
            test_count: Number of tests per path
            timeout: Timeout per test in seconds
            
        Returns:
            List of tuples: (dest_ip, fastest_result, all_results_for_dest)
        """
        # Detect local machine's region
        local_regions = await self._get_local_region()
        local_ip = self._get_local_ip()
        
        print(f"\nTesting from local machine:")
        print(f"   Local IP: {local_ip}")
        print(f"   Local region(s): {local_regions}")
        print(f"\nTesting to {len(dest_ips)} destination(s):")
        for dest_ip in dest_ips:
            dest_regions = await self.region_mapper.get_regions_for_ip(dest_ip)
            print(f"   - {dest_ip} (regions: {dest_regions})")
        
        # Test all destinations concurrently
        tasks = []
        for dest_ip in dest_ips:
            task = self.find_fastest_path(
                source_ip=source_ip,
                dest_ip=dest_ip,
                protocol=protocol,
                source_port=source_port,
                dest_port=dest_port,
                test_count=test_count,
                timeout=timeout
            )
            tasks.append((dest_ip, task))
        
        # Wait for all tests to complete
        results = []
        for dest_ip, task in tasks:
            fastest, all_results = await task
            results.append((dest_ip, fastest, all_results))
        
        return results
    
    def _calculate_percentage_faster(self, faster_latency: float, slower_latency: float) -> float:
        """Calculate percentage faster (positive) or slower (negative)."""
        if slower_latency == 0:
            return 0.0
        return ((slower_latency - faster_latency) / slower_latency) * 100
    
    def _get_percentage_comparison(self, current_latency: float, all_latencies: List[float], current_label: str) -> str:
        """Get percentage comparison string for a given latency."""
        faster_than = []
        slower_than = []
        
        for other_latency in all_latencies:
            if other_latency == current_latency:
                continue
            
            if current_latency < other_latency:
                # Current is faster
                pct = self._calculate_percentage_faster(current_latency, other_latency)
                faster_than.append((other_latency, pct))
            else:
                # Current is slower
                pct = self._calculate_percentage_faster(other_latency, current_latency)
                slower_than.append((other_latency, pct))
        
        comparisons = []
        
        if faster_than:
            # Group by similar percentages
            faster_than.sort(key=lambda x: x[1], reverse=True)
            avg_faster = sum(pct for _, pct in faster_than) / len(faster_than)
            count = len(faster_than)
            comparisons.append(f"{current_label} is {avg_faster:.1f}% faster than {count} other destination(s)")
        
        if slower_than:
            slower_than.sort(key=lambda x: x[1], reverse=True)
            avg_slower = sum(pct for _, pct in slower_than) / len(slower_than)
            count = len(slower_than)
            comparisons.append(f"{current_label} is {avg_slower:.1f}% slower than {count} other destination(s)")
        
        return " | ".join(comparisons) if comparisons else ""
    
    def print_multi_destination_results(
        self,
        results: List[Tuple[str, Optional[PathResult], List[PathResult]]]
    ):
        """Print formatted results for multiple destinations."""
        # Filter successful results
        successful = [(dest_ip, fastest) for dest_ip, fastest, _ in results if fastest is not None]
        
        if not successful:
            print("\nNo successful paths found to any destination!")
            return
        
        # Sort by latency
        successful.sort(key=lambda x: x[1].latency_ms)
        
        # Get all latencies for comparison
        all_latencies = [fastest.latency_ms for _, fastest in successful]
        fastest_latency = all_latencies[0] if all_latencies else 0
        
        print("\n" + "="*80)
        print("FASTEST PATHS TO MULTIPLE DESTINATIONS")
        print("="*80)
        print(f"Ranked by latency (from {self.local_ip}):\n")
        
        for rank, (dest_ip, fastest) in enumerate(successful, 1):
            marker = f"{rank}."
            dest_label = f"{dest_ip} ({fastest.dest_region})"
            
            print(f"{marker} Destination: {dest_label}")
            print(f"   Latency: {fastest.latency_ms:.2f} ms")
            print(f"   Protocol: {fastest.five_tuple.protocol}")
            if fastest.five_tuple.dest_port:
                print(f"   Port: {fastest.five_tuple.dest_port}")
            
            # Add percentage comparison
            if len(successful) > 1:
                comparison = self._get_percentage_comparison(
                    fastest.latency_ms, 
                    all_latencies, 
                    dest_label
                )
                if comparison:
                    print(f"   {comparison}")
            
            print()
        
        print("="*80)
        
        # Show detailed fastest result
        if successful:
            fastest_dest_ip, fastest_result = successful[0]
            # Find all results for the fastest destination
            all_results_for_fastest = next(
                (all_r for dest_ip, _, all_r in results if dest_ip == fastest_dest_ip),
                []
            )
            print(f"\nDETAILED RESULT FOR FASTEST DESTINATION ({fastest_dest_ip}):")
            self.print_results(fastest_result, all_results_for_fastest)
    
    def print_results(self, fastest: Optional[PathResult], all_results: List[PathResult]):
        """Print formatted results."""
        if fastest is None:
            print("\nNo successful paths found!")
            return
        
        local_regions_str = ', '.join(self.local_region) if self.local_region else 'unknown'
        
        print("\n" + "="*80)
        print("FASTEST PATH RESULT")
        print("="*80)
        print(f"Tested from:      {self.local_ip} ({local_regions_str})")
        print(f"Source IP:        {fastest.source_ip} ({fastest.source_region})")
        print(f"Destination IP:   {fastest.dest_ip} ({fastest.dest_region})")
        print(f"Protocol:         {fastest.five_tuple.protocol}")
        if fastest.five_tuple.source_port:
            print(f"Source Port:      {fastest.five_tuple.source_port}")
        if fastest.five_tuple.dest_port:
            print(f"Destination Port: {fastest.five_tuple.dest_port}")
        print(f"Latency:          {fastest.latency_ms:.2f} ms")
        print(f"Status:           Success")
        print(f"Timestamp:        {fastest.timestamp}")
        print("="*80)
        
        # Show top 5 paths
        successful = sorted(
            [r for r in all_results if r.success],
            key=lambda x: x.latency_ms
        )[:5]
        
        if len(successful) > 1:
            print("\nTOP 5 PATHS:")
            print("-"*80)
            all_path_latencies = [r.latency_ms for r in successful]
            
            for i, result in enumerate(successful, 1):
                path_label = f"{result.source_region} -> {result.dest_region}"
                print(f"{i}. {path_label}: {result.latency_ms:.2f} ms ({result.five_tuple.protocol})")
                
                # Add percentage comparison
                comparison = self._get_percentage_comparison(
                    result.latency_ms,
                    all_path_latencies,
                    path_label
                )
                if comparison:
                    print(f"   {comparison}")
    
    def _jaccard_similarity(self, set1: Set, set2: Set) -> float:
        """Calculate Jaccard similarity between two sets."""
        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0
    
    def _get_top_k_ports(self, results_by_port: Dict[int, List[float]], k: int) -> Set[int]:
        """Get Top-K ports by median latency."""
        if not results_by_port:
            return set()
        
        # Calculate median latency for each port
        port_medians = {}
        for port, latencies in results_by_port.items():
            if latencies:
                sorted_latencies = sorted(latencies)
                n = len(sorted_latencies)
                if n % 2 == 0:
                    median = (sorted_latencies[n//2 - 1] + sorted_latencies[n//2]) / 2
                else:
                    median = sorted_latencies[n//2]
                port_medians[port] = median
        
        # Get Top-K ports
        sorted_ports = sorted(port_medians.items(), key=lambda x: x[1])
        top_k_ports = {port for port, _ in sorted_ports[:k]}
        
        return top_k_ports
    
    def _check_convergence(
        self,
        top_k_history: List[Set[int]],
        best_latency_history: List[float],
        convergence_rounds: int,
        convergence_threshold: float,
        latency_improvement_threshold: float,
        latency_improvement_percent: float
    ) -> bool:
        """Check if convergence criteria are met."""
        if len(top_k_history) < convergence_rounds:
            return False
        
        # Check Top-K stability (last N rounds)
        recent_rounds = top_k_history[-convergence_rounds:]
        all_similar = True
        
        for i in range(1, len(recent_rounds)):
            similarity = self._jaccard_similarity(recent_rounds[i-1], recent_rounds[i])
            if similarity < convergence_threshold:
                all_similar = False
                break
        
        if not all_similar:
            return False
        
        # Check latency improvement
        if len(best_latency_history) < convergence_rounds:
            return False
        
        recent_latencies = best_latency_history[-convergence_rounds:]
        oldest_latency = recent_latencies[0]
        newest_latency = recent_latencies[-1]
        
        # Check absolute improvement
        absolute_improvement = oldest_latency - newest_latency
        if absolute_improvement > latency_improvement_threshold:
            return False
        
        # Check percentage improvement
        if oldest_latency > 0:
            percent_improvement = (absolute_improvement / oldest_latency) * 100
            if percent_improvement > latency_improvement_percent:
                return False
        
        return True
    
    def write_csv_results(self, all_results: List[PathResult], filename: str):
        """Write results to CSV file with specified format.
        
        Groups results by (source_ip+region, source_port, dest_ip+region, dest_port, protocol)
        and averages latency for each group.
        """
        if not all_results:
            return
        
        # Group results by (source_ip, source_region, source_port, dest_ip, dest_region, dest_port, protocol)
        # and calculate average latency
        grouped = {}
        
        for result in all_results:
            # Use source_port from actual_source_port or from five_tuple
            source_port = result.actual_source_port
            if source_port is None and result.five_tuple.source_port:
                source_port = result.five_tuple.source_port
            
            key = (
                result.source_ip,
                result.source_region,
                source_port,
                result.dest_ip,
                result.dest_region,
                result.five_tuple.dest_port if result.five_tuple.dest_port else "N/A",
                result.five_tuple.protocol
            )
            
            if key not in grouped:
                grouped[key] = {
                    'latencies': [],
                    'success_count': 0,
                    'total_count': 0
                }
            
            grouped[key]['total_count'] += 1
            if result.success:
                grouped[key]['latencies'].append(result.latency_ms)
                grouped[key]['success_count'] += 1
        
        # Write CSV
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Header
            writer.writerow([
                'source (ip and region)',
                'source port (dynamic from average of runs)',
                'destination (ip and region)',
                'destination port (static)',
                'protocol'
            ])
            
            # Data rows - one per source port/protocol/destination combination
            for key, data in grouped.items():
                source_ip, source_region, source_port, dest_ip, dest_region, dest_port, protocol = key
                
                # Calculate average latency from successful runs
                avg_latency = "N/A"
                if data['latencies']:
                    avg_latency = sum(data['latencies']) / len(data['latencies'])
                
                # Only write successful results (or you can include all with avg_latency)
                if data['success_count'] > 0:
                    source_str = f"{source_ip} ({source_region})"
                    dest_str = f"{dest_ip} ({dest_region})"
                    
                    source_port_str = source_port
                    
                    writer.writerow([
                        source_str,
                        source_port_str,
                        dest_str,
                        dest_port,
                        protocol
                    ])
        
        print(f"\nResults written to {filename}")


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Find fastest network path between IPs across AWS regions",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test single destination
  %(prog)s --source 192.168.1.1 --destination 10.0.0.1 --protocol TCP --dest-port 443

  # Test multiple destinations (comma-separated)
  %(prog)s --source 192.168.1.1 --destination 10.0.0.1,10.0.0.2,10.0.0.3,10.0.0.4 --protocol TCP --dest-port 443

  # Test multiple destinations (multiple flags)
  %(prog)s --source 192.168.1.1 --destination 10.0.0.1 --destination 10.0.0.2 --destination 10.0.0.3 --protocol TCP
        """
    )
    parser.add_argument(
        "--source", "-s",
        required=True,
        help="Source IP address"
    )
    parser.add_argument(
        "--destination", "-d",
        action="append",
        required=True,
        help="Destination in format IP:PORT (e.g., 10.0.0.1:8080). Can specify multiple times or use comma-separated values"
    )
    parser.add_argument(
        "--protocol", "-p",
        choices=["TCP", "UDP"],
        default=None,
        help="Protocol to use. If not specified, tests both TCP and UDP"
    )
    parser.add_argument(
        "--test-count", "-n",
        type=int,
        default=5,
        help="Number of tests to run per source port (default: 5)"
    )
    parser.add_argument(
        "--port-sample-size",
        type=int,
        default=300,
        help="Maximum number of source ports to test (default: 300). Testing stops early if convergence is reached."
    )
    parser.add_argument(
        "--top-k",
        type=int,
        default=10,
        help="Number of top ports to track for convergence (default: 10)"
    )
    parser.add_argument(
        "--convergence-rounds",
        type=int,
        default=3,
        help="Number of consecutive rounds with stable Top-K for convergence (default: 3)"
    )
    parser.add_argument(
        "--convergence-threshold",
        type=float,
        default=0.9,
        help="Jaccard similarity threshold for Top-K stability (default: 0.9)"
    )
    parser.add_argument(
        "--latency-improvement-threshold",
        type=float,
        default=1.0,
        help="Maximum latency improvement (ms) to consider converged (default: 1.0)"
    )
    parser.add_argument(
        "--latency-improvement-percent",
        type=float,
        default=5.0,
        help="Maximum latency improvement percentage to consider converged (default: 5.0)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=5.0,
        help="Timeout per test in seconds (default: 5.0)"
    )
    
    args = parser.parse_args()
    
    # Parse destinations - format is IP:PORT
    destinations = []
    if args.destination:
        for dest_arg in args.destination:
            # Split by comma and strip whitespace
            dests = [d.strip() for d in dest_arg.split(',')]
            for dest in dests:
                if ':' not in dest:
                    parser.error(f"Destination must be in format IP:PORT, got: {dest}")
                try:
                    dest_ip, dest_port_str = dest.rsplit(':', 1)
                    dest_port = int(dest_port_str)
                    destinations.append((dest_ip, dest_port))
                except ValueError:
                    parser.error(f"Invalid destination format: {dest}. Expected IP:PORT")
    
    if not destinations:
        parser.error("At least one --destination is required")
    
    finder = FastestPathFinder()
    
    try:
        # Get local region for CSV filename
        local_regions = await finder._get_local_region()
        source_region_str = local_regions[0] if local_regions else "unknown"
        
        # Determine protocols to test
        if args.protocol:
            protocols = [args.protocol.upper()]
        else:
            protocols = ["TCP", "UDP"]
        
        # Get source IP and regions
        source_ip = args.source
        source_regions = await finder.region_mapper.get_regions_for_ip(source_ip)
        source_region = source_regions[0] if source_regions else "unknown"
        
        # Select source ports to test (only for TCP/UDP)
        all_results = []
        
        print(f"\nTesting from local machine:")
        print(f"   Local IP: {finder._get_local_ip()}")
        print(f"   Local region(s): {local_regions}")
        print(f"\nTesting to {len(destinations)} destination(s):")
        for dest_ip, dest_port in destinations:
            dest_regions = await finder.region_mapper.get_regions_for_ip(dest_ip)
            print(f"   - {dest_ip}:{dest_port} (regions: {dest_regions})")
        
        print(f"\nProtocols to test: {', '.join(protocols)}")
        
        # Get random sampling of 300 ports
        all_available_ports = finder.select_source_ports(args.port_sample_size)
        print(f"\nTesting {len(all_available_ports)} source ports (sample size: {args.port_sample_size})")
        
        # For each destination, test all protocols for each port
        for dest_ip, dest_port in destinations:
            dest_regions = await finder.region_mapper.get_regions_for_ip(dest_ip)
            dest_region = dest_regions[0] if dest_regions else "unknown"
            
            print(f"\nTesting destination {dest_ip}:{dest_port}...")
            
            # Track results by port and protocol separately for convergence
            results_by_port_protocol: Dict[Tuple[int, str], List[float]] = defaultdict(list)
            tested_ports: Set[int] = set()
            
            # Track Top-K per protocol for convergence
            top_k_history_by_protocol: Dict[str, List[Set[int]]] = {
                "TCP": [],
                "UDP": []
            }
            best_latency_history_by_protocol: Dict[str, List[float]] = {
                "TCP": [],
                "UDP": []
            }
            
            batch_size = 50
            round_num = 0
            converged_protocols: Set[str] = set()
            
            # Process ports in batches until convergence or all ports tested
            for batch_start in range(0, len(all_available_ports), batch_size):
                batch_ports = all_available_ports[batch_start:batch_start + batch_size]
                round_num += 1
                
                print(f"   Round {round_num}: Testing batch of {len(batch_ports)} ports...")
                
                # Test each port with both TCP and UDP (if not converged)
                for source_port in batch_ports:
                    tested_ports.add(source_port)
                    
                    # Test TCP if not converged
                    if "TCP" not in converged_protocols and "TCP" in protocols:
                        tcp_results = await finder._test_path_with_source_port(
                            source_ip=source_ip,
                            dest_ip=dest_ip,
                            source_port=source_port,
                            dest_port=dest_port,
                            protocol="TCP",
                            source_region=source_region,
                            dest_region=dest_region,
                            test_count=args.test_count,
                            timeout=args.timeout
                        )
                        all_results.extend(tcp_results)
                        
                        # Calculate average latency for this port/protocol
                        successful_latencies = [r.latency_ms for r in tcp_results if r.success]
                        if successful_latencies:
                            avg_latency = sum(successful_latencies) / len(successful_latencies)
                            results_by_port_protocol[(source_port, "TCP")].append(avg_latency)
                    
                    # Test UDP if not converged
                    if "UDP" not in converged_protocols and "UDP" in protocols:
                        udp_results = await finder._test_path_with_source_port(
                            source_ip=source_ip,
                            dest_ip=dest_ip,
                            source_port=source_port,
                            dest_port=dest_port,
                            protocol="UDP",
                            source_region=source_region,
                            dest_region=dest_region,
                            test_count=args.test_count,
                            timeout=args.timeout
                        )
                        all_results.extend(udp_results)
                        
                        # Calculate average latency for this port/protocol
                        successful_latencies = [r.latency_ms for r in udp_results if r.success]
                        if successful_latencies:
                            avg_latency = sum(successful_latencies) / len(successful_latencies)
                            results_by_port_protocol[(source_port, "UDP")].append(avg_latency)
                
                # Check convergence for each protocol separately
                for protocol in protocols:
                    if protocol in converged_protocols:
                        continue
                    
                    # Get results for this protocol
                    protocol_results_by_port: Dict[int, List[float]] = {}
                    for (port, proto), latencies in results_by_port_protocol.items():
                        if proto == protocol and latencies:
                            # Use the average latency for median calculation
                            protocol_results_by_port[port] = latencies
                    
                    if not protocol_results_by_port:
                        continue
                    
                    # Calculate median latency for each port
                    port_medians = {}
                    for port, avg_latencies in protocol_results_by_port.items():
                        sorted_latencies = sorted(avg_latencies)
                        n = len(sorted_latencies)
                        if n % 2 == 0:
                            median = (sorted_latencies[n//2 - 1] + sorted_latencies[n//2]) / 2
                        else:
                            median = sorted_latencies[n//2]
                        port_medians[port] = median
                    
                    # Get Top-K ports for this protocol
                    sorted_ports = sorted(port_medians.items(), key=lambda x: x[1])
                    top_k_ports = {port for port, _ in sorted_ports[:args.top_k]}
                    top_k_history_by_protocol[protocol].append(top_k_ports)
                    
                    # Get best median latency
                    if port_medians:
                        best_latency_history_by_protocol[protocol].append(min(port_medians.values()))
                    
                    # Check convergence for this protocol
                    if finder._check_convergence(
                        top_k_history_by_protocol[protocol],
                        best_latency_history_by_protocol[protocol],
                        args.convergence_rounds,
                        args.convergence_threshold,
                        args.latency_improvement_threshold,
                        args.latency_improvement_percent
                    ):
                        print(f"   {protocol} convergence reached after {round_num} rounds!")
                        converged_protocols.add(protocol)
                
                # Print progress
                for protocol in protocols:
                    if protocol not in converged_protocols:
                        if top_k_history_by_protocol[protocol]:
                            top_k = top_k_history_by_protocol[protocol][-1]
                            if top_k:
                                print(f"      {protocol} Top-{args.top_k} ports: {sorted(list(top_k))[:5]}... (showing first 5)")
                        if best_latency_history_by_protocol[protocol]:
                            print(f"      {protocol} best median latency: {best_latency_history_by_protocol[protocol][-1]:.2f} ms")
                
                # Stop if all protocols converged
                if len(converged_protocols) == len(protocols):
                    print(f"   All protocols converged after {round_num} rounds!")
                    break
            
            print(f"   Completed testing {len(tested_ports)} source ports for {dest_ip}:{dest_port}")
        
        # Write separate CSV files per protocol with averaged results
        # Group results by (source_port, protocol, destination) and calculate averages
        results_by_port_protocol_dest: Dict[Tuple[int, str, str, int], List[float]] = defaultdict(list)
        
        for result in all_results:
            if result.success:
                source_port = result.actual_source_port
                if source_port is None and result.five_tuple.source_port:
                    source_port = result.five_tuple.source_port
                
                if source_port is not None:
                    key = (
                        source_port,
                        result.five_tuple.protocol.upper(),
                        result.dest_ip,
                        result.five_tuple.dest_port if result.five_tuple.dest_port else 0
                    )
                    results_by_port_protocol_dest[key].append(result.latency_ms)
        
        # Generate timestamp for CSV filenames
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        # Write CSV files per protocol
        csv_files_written = []
        for protocol in ["TCP", "UDP"]:
            if protocol not in protocols:
                continue
            
            # Format: region-ipaddress-protocol-fastestpath-YYYYMMDD-HHMMSS.csv (lowercase protocol)
            csv_filename = f"{source_region_str}-{source_ip.replace('.', '-')}-{protocol.lower()}-fastestpath-{timestamp}.csv"
            
            with open(csv_filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                
                # Header
                writer.writerow([
                    'source (ip and region)',
                    'source port (dynamic from average of runs)',
                    'destination (ip and region)',
                    'destination port (static)',
                    'protocol'
                ])
                
                # Write rows for this protocol - one row per (source_port, destination)
                protocol_keys = [(k, v) for k, v in results_by_port_protocol_dest.items() if k[1] == protocol]
                protocol_keys.sort(key=lambda x: (x[0][2], x[0][0]))  # Sort by dest_ip, then source_port
                
                for key, latencies in protocol_keys:
                    source_port, proto, dest_ip, dest_port = key
                    
                    # Calculate average latency (already averaged from test runs)
                    avg_latency = sum(latencies) / len(latencies) if latencies else 0
                    
                    # Get destination region
                    dest_regions = await finder.region_mapper.get_regions_for_ip(dest_ip)
                    dest_region = dest_regions[0] if dest_regions else "unknown"
                    
                    source_str = f"{source_ip} ({source_region})"
                    dest_str = f"{dest_ip} ({dest_region})"
                    
                    writer.writerow([
                        source_str,
                        source_port,
                        dest_str,
                        dest_port,
                        proto.lower()
                    ])
            
            csv_files_written.append(csv_filename)
            print(f"Results written to {csv_filename}")
        
        # Calculate and print top 5 lowest latency paths
        print("\n" + "="*80)
        print("TOP 5 LOWEST LATENCY PATHS")
        print("="*80)
        
        # Create list of all paths with averaged latency
        all_paths = []
        for key, latencies in results_by_port_protocol_dest.items():
            source_port, protocol, dest_ip, dest_port = key
            if latencies:
                avg_latency = sum(latencies) / len(latencies)
                
                # Get regions
                dest_regions = await finder.region_mapper.get_regions_for_ip(dest_ip)
                dest_region = dest_regions[0] if dest_regions else "unknown"
                
                all_paths.append({
                    'source_ip': source_ip,
                    'source_region': source_region,
                    'source_port': source_port,
                    'dest_ip': dest_ip,
                    'dest_region': dest_region,
                    'dest_port': dest_port,
                    'protocol': protocol,
                    'avg_latency': avg_latency
                })
        
        # Sort by latency and get top 5
        all_paths.sort(key=lambda x: x['avg_latency'])
        top_5 = all_paths[:5]
        
        if top_5:
            for rank, path in enumerate(top_5, 1):
                print(f"\n{rank}. {path['protocol']} - Source Port {path['source_port']}")
                print(f"   Source:      {path['source_ip']} ({path['source_region']})")
                print(f"   Destination: {path['dest_ip']} ({path['dest_region']}):{path['dest_port']}")
                print(f"   Latency:     {path['avg_latency']:.2f} ms")
        else:
            print("\nNo successful paths found!")
        
        print("="*80)
        
        # Print summary
        successful = [r for r in all_results if r.success]
        print(f"\nCompleted: {len(successful)} successful tests out of {len(all_results)} total")
        print(f"CSV files written: {', '.join(csv_files_written)}")
        
        sys.exit(0 if successful else 1)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
