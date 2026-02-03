"""
AWS Region Mapper

Maps IP addresses to AWS regions and provides region information
"""

import asyncio
import ipaddress
from typing import List, Set, Optional, Tuple
import aiohttp


class AWSRegionMapper:
    """Maps IP addresses to AWS regions."""
    
    # AWS IP ranges JSON URL
    AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
    
    # Common AWS region endpoints for testing
    AWS_REGIONS = [
        "us-east-1",      # N. Virginia
        "us-east-2",      # Ohio
        "us-west-1",      # N. California
        "us-west-2",      # Oregon
        "eu-west-1",      # Ireland
        "eu-west-2",      # London
        "eu-west-3",      # Paris
        "eu-central-1",  # Frankfurt
        "ap-southeast-1", # Singapore
        "ap-southeast-2", # Sydney
        "ap-northeast-1", # Tokyo
        "ap-south-1",    # Mumbai
        "ap-east-1",     # Hong Kong
        "sa-east-1",     # São Paulo
    ]
    
    # Commercial regions for ENI scanning (as of 2025)
    COMMERCIAL_REGIONS = [
        # US
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        # Canada
        "ca-central-1",
        # South America
        "sa-east-1",
        # Europe
        "eu-north-1", "eu-west-1", "eu-west-2", "eu-west-3",
        "eu-central-1", "eu-south-1", "eu-south-2",
        # Middle East
        "me-central-1",
        # Asia Pacific
        "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
        "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4",
        "ap-south-1", "ap-south-2",
        "ap-east-1",
    ]
    
    def __init__(self):
        self.ip_ranges_cache = None
        self.cache_timestamp = None
        self.metadata_region = None
        self.metadata_az = None
        self.eni_scan_cache = {}  # Cache for ENI scan results: {ip: region}
    
    async def _fetch_aws_ip_ranges(self) -> dict:
        """Fetch AWS IP ranges from official source."""
        async with aiohttp.ClientSession() as session:
            async with session.get(self.AWS_IP_RANGES_URL) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    raise Exception(f"Failed to fetch AWS IP ranges: {response.status}")
    
    async def _get_ip_ranges(self) -> dict:
        """Get AWS IP ranges (with caching)."""
        # Cache for 1 hour
        import time
        if (self.ip_ranges_cache is None or 
            self.cache_timestamp is None or 
            time.time() - self.cache_timestamp > 3600):
            self.ip_ranges_cache = await self._fetch_aws_ip_ranges()
            self.cache_timestamp = time.time()
        
        return self.ip_ranges_cache
    
    async def get_region_from_metadata(self) -> Tuple[Optional[str], Optional[str]]:
        """
        Get AWS region and availability zone from instance metadata service.
        
        Returns:
            Tuple of (region, availability_zone) or (None, None) if not available
        """
        if self.metadata_region and self.metadata_az:
            return (self.metadata_region, self.metadata_az)
        
        try:
            async with aiohttp.ClientSession() as session:
                # Get availability zone
                try:
                    async with session.get(
                        'http://169.254.169.254/latest/meta-data/placement/availability-zone',
                        timeout=aiohttp.ClientTimeout(total=2)
                    ) as response:
                        if response.status == 200:
                            az = await response.text()
                            az = az.strip()
                            # Extract region from AZ (e.g., us-east-1a -> us-east-1)
                            # AZ format is typically region-letter (e.g., us-east-1a, us-west-2b)
                            # Remove the trailing letter to get region
                            if az:
                                # Most AZs end with a single letter, but some regions have different formats
                                # Try to extract region by removing the last character if it's a letter
                                if len(az) > 1 and az[-1].isalpha():
                                    region = az[:-1]
                                else:
                                    # Fallback: try to find region pattern
                                    # Split by common patterns
                                    parts = az.split('-')
                                    if len(parts) >= 3:
                                        region = '-'.join(parts[:3])  # e.g., us-east-1
                                    else:
                                        region = az
                                
                                self.metadata_az = az
                                self.metadata_region = region
                                return (region, az)
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    pass
        except Exception:
            pass
        
        return (None, None)
    
    async def get_regions_for_ip(self, ip: str) -> List[str]:
        """
        Get AWS regions that contain the given IP address.
        
        Args:
            ip: IP address to check
            
        Returns:
            List of region codes where this IP might be located
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            # If not a valid IP, try to resolve it or return default regions
            return self.AWS_REGIONS
        
        # Check if IP is in AWS ranges
        ip_ranges = await self._get_ip_ranges()
        regions = set()
        
        for prefix in ip_ranges.get("prefixes", []):
            try:
                network = ipaddress.ip_network(prefix["ip_prefix"])
                if ip_obj in network:
                    regions.add(prefix["region"])
            except (ValueError, KeyError):
                continue
        
        # Also check IPv6 ranges
        for prefix in ip_ranges.get("ipv6_prefixes", []):
            try:
                network = ipaddress.ip_network(prefix["ipv6_prefix"])
                if ip_obj in network:
                    regions.add(prefix["region"])
            except (ValueError, KeyError):
                continue
        
        # If no regions found, try to infer from IP geolocation
        if not regions:
            # For demonstration, we'll try to infer
            # In production, you might use a geolocation service
            inferred = self._infer_region_from_ip(ip)
            if inferred:
                regions = inferred
            else:
                # If we can't determine region, return empty list
                # The caller should handle "unknown" region
                return []
        
        return list(regions)
    
    def _infer_region_from_ip(self, ip: str) -> Set[str]:
        """
        Infer likely AWS region from IP address.
        This is a simple heuristic - in production, use a proper geolocation service.
        Note: This should only be used as a last resort when IP is not in AWS IP ranges.
        """
        # This is a placeholder - in production, use MaxMind GeoIP2 or similar
        # For now, return empty set to indicate we couldn't determine region
        # The caller should handle this appropriately
        return set()
    
    def get_region_endpoints(self, region: str) -> List[str]:
        """Get test endpoints for a given AWS region."""
        # Common AWS service endpoints per region
        endpoints = {
            "us-east-1": ["ec2.us-east-1.amazonaws.com"],
            "us-east-2": ["ec2.us-east-2.amazonaws.com"],
            "us-west-1": ["ec2.us-west-1.amazonaws.com"],
            "us-west-2": ["ec2.us-west-2.amazonaws.com"],
            "eu-west-1": ["ec2.eu-west-1.amazonaws.com"],
            "eu-west-2": ["ec2.eu-west-2.amazonaws.com"],
            "eu-west-3": ["ec2.eu-west-3.amazonaws.com"],
            "eu-central-1": ["ec2.eu-central-1.amazonaws.com"],
            "ap-southeast-1": ["ec2.ap-southeast-1.amazonaws.com"],
            "ap-southeast-2": ["ec2.ap-southeast-2.amazonaws.com"],
            "ap-northeast-1": ["ec2.ap-northeast-1.amazonaws.com"],
            "ap-south-1": ["ec2.ap-south-1.amazonaws.com"],
            "sa-east-1": ["ec2.sa-east-1.amazonaws.com"],
        }
        
        return endpoints.get(region, [])
    
    async def find_destination_region_from_eni(self, ip: str, timeout_seconds: int = 5, stop_on_first: bool = True) -> Optional[str]:
        """
        Scan AWS regions to find which region contains an ENI/EC2 instance with the given private IP.
        This is the most accurate method for determining destination region.
        
        Args:
            ip: Private IP address to search for
            timeout_seconds: Per-call connect/read timeout
            stop_on_first: Stop scanning as soon as a match is found
            
        Returns:
            Region name if found, None otherwise
        """
        # Check cache first
        if ip in self.eni_scan_cache:
            return self.eni_scan_cache[ip]
        
        try:
            import boto3
            from botocore.config import Config
            from botocore.exceptions import BotoCoreError, ClientError
        except ImportError:
            # boto3 not available, skip ENI scanning
            return None
        
        # Check if IP is private (ENI scanning only works for private IPs)
        try:
            ip_obj = ipaddress.ip_address(ip)
            if not ip_obj.is_private:
                # Public IPs won't be found via ENI scanning
                return None
        except ValueError:
            return None
        
        # Create boto3 session and config
        try:
            session = boto3.Session()
            cfg = Config(
                connect_timeout=timeout_seconds,
                read_timeout=timeout_seconds,
                retries={"max_attempts": 2, "mode": "standard"},
            )
        except Exception:
            # No AWS credentials or boto3 not properly configured
            return None
        
        # Scan regions concurrently
        regions = self.COMMERCIAL_REGIONS
        
        async def scan_region(region: str) -> Optional[str]:
            """Scan a single region for the IP."""
            try:
                # Run boto3 call in executor since it's synchronous
                loop = asyncio.get_event_loop()
                ec2 = session.client("ec2", region_name=region, config=cfg)
                
                def describe_enis():
                    return ec2.describe_network_interfaces(
                        Filters=[{"Name": "addresses.private-ip-address", "Values": [ip]}]
                    )
                
                resp = await loop.run_in_executor(None, describe_enis)
                
                if resp.get("NetworkInterfaces"):
                    # Found the IP in this region
                    return region
            except (ClientError, BotoCoreError):
                # Permission denied or other AWS error - skip this region
                pass
            except Exception:
                # Other errors - skip this region
                pass
            
            return None
        
        # Scan all regions concurrently (with limit to avoid too many concurrent requests)
        # Use semaphore to limit concurrent scans
        semaphore = asyncio.Semaphore(10)  # Max 10 concurrent region scans
        
        async def scan_with_limit(region: str):
            async with semaphore:
                return await scan_region(region)
        
        # Create tasks for all regions
        tasks = [scan_with_limit(region) for region in regions]
        
        # Wait for results, stopping early if stop_on_first and we find a match
        if stop_on_first:
            # Use as_completed to stop as soon as we find a match
            for coro in asyncio.as_completed(tasks):
                result = await coro
                if result:
                    self.eni_scan_cache[ip] = result
                    return result
        else:
            # Wait for all tasks
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, str):
                    self.eni_scan_cache[ip] = result
                    return result
        
        # Not found in any region
        self.eni_scan_cache[ip] = None
        return None