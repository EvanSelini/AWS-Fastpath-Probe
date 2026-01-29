"""
5-Tuple Network Flow Identifier

The 5-tuple consists of:
- Source IP Address
- Destination IP Address
- Source Port
- Destination Port
- Protocol Number
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class FiveTuple:
    """Represents a 5-tuple network flow identifier."""
    
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str  # TCP, UDP
    
    def __post_init__(self):
        """Validate the 5-tuple."""
        if not self.source_ip or not self.dest_ip:
            raise ValueError("Source and destination IPs are required")
        
        if self.protocol.upper() in ["TCP", "UDP"]:
            if self.dest_port is None:
                raise ValueError(f"Destination port is required for {self.protocol}")
    
    def __str__(self) -> str:
        """String representation of the 5-tuple."""
        parts = [
            f"src={self.source_ip}",
            f"dst={self.dest_ip}",
        ]
        
        if self.source_port is not None:
            parts.append(f"sport={self.source_port}")
        if self.dest_port is not None:
            parts.append(f"dport={self.dest_port}")
        
        parts.append(f"proto={self.protocol}")
        
        return " ".join(parts)
    
    def __hash__(self) -> int:
        """Make 5-tuple hashable for use in sets/dicts."""
        return hash((
            self.source_ip,
            self.dest_ip,
            self.source_port,
            self.dest_port,
            self.protocol.upper()
        ))
    
    def __eq__(self, other) -> bool:
        """Equality comparison."""
        if not isinstance(other, FiveTuple):
            return False
        
        return (
            self.source_ip == other.source_ip and
            self.dest_ip == other.dest_ip and
            self.source_port == other.source_port and
            self.dest_port == other.dest_port and
            self.protocol.upper() == other.protocol.upper()
        )
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "source_port": self.source_port,
            "dest_port": self.dest_port,
            "protocol": self.protocol
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "FiveTuple":
        """Create from dictionary."""
        return cls(
            source_ip=data["source_ip"],
            dest_ip=data["dest_ip"],
            source_port=data.get("source_port"),
            dest_port=data.get("dest_port"),
            protocol=data["protocol"]
        )
