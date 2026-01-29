"""
AWS Region Mapper

Maps IP addresses to AWS regions and provides region information.
"""

import asyncio
import ipaddress
from typing import List, Set
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
        "sa-east-1",     # São Paulo
    ]
    
    def __init__(self):
        self.ip_ranges_cache = None
        self.cache_timestamp = None
    
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
        
        # If no regions found, try to infer from IP geolocation or return all
        if not regions:
            # For demonstration, we'll return common regions
            # In production, you might use a geolocation service
            regions = self._infer_region_from_ip(ip)
        
        return list(regions) if regions else self.AWS_REGIONS
    
    def _infer_region_from_ip(self, ip: str) -> Set[str]:
        """
        Infer likely AWS region from IP address.
        This is a simple heuristic - in production, use a proper geolocation service.
        """
        # This is a placeholder - in production, use MaxMind GeoIP2 or similar
        # For now, return a subset of regions based on common patterns
        
        # Private IP ranges - assume us-east-1
        if ip.startswith(("10.", "172.16.", "192.168.")):
            return {"us-east-1"}
        
        # Default to major regions
        return {"us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"}
    
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
