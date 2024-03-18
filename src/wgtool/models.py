from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import Dict, List, Optional, Union

from pydantic import BaseModel, Field, validator

DEFAULT_PORT = 51820
DEFAULT_FILE = "/etc/wireguard/wg0.conf"


class WGServerEndpoint(BaseModel):
    address: str = "host.example.com"
    port: int = Field(default=DEFAULT_PORT, ge=1024, le=65535)
    public_key: str = ""
    private_key: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.address}:{self.port}"


class WGPeerConfig(BaseModel):
    name: str = Field(pattern=r"[a-zA-Z][a-zA-Z0-9-_]+")
    public_key: str = ""
    preshared_key: str = ""
    private_key: str = ""
    server: WGServerEndpoint = WGServerEndpoint()
    ipv4: Optional[IPv4Interface] = None
    ipv6: Optional[IPv6Interface] = None
    allowed_ips: List[Union[IPv4Network, IPv6Network]] = Field(default_factory=list)
    dns: List[Union[IPv4Address, IPv6Address]] = Field(default_factory=list)
    others: Dict[str, str] = Field(default_factory=dict)

    @property
    def address(self) -> str:
        return ", ".join([str(ip) for ip in [self.ipv4, self.ipv6] if ip])

    @validator("others")
    def valid_others(cls, value: Dict[str, str]) -> Dict[str, str]:
        return {k: v for k, v in value.items() if k[0].upper() == k[0]}

    class Config:
        validate_assignment = True


class WGServerConfig(BaseModel):
    server: WGServerEndpoint = Field(default_factory=lambda: WGServerEndpoint())
    ipv4: IPv4Interface = IPv4Interface("10.6.0.1/24")
    ipv6: Optional[IPv6Interface] = None
    mtu: int = Field(default=1420, ge=1280, le=65535)
    post_up: str = ""
    post_down: str = ""
    others: Dict[str, str] = Field(default_factory=dict)
    peers: List[WGPeerConfig] = Field(default_factory=list)

    @property
    def address(self) -> str:
        return ", ".join([str(ip) for ip in [self.ipv4, self.ipv6] if ip])

    @validator("others")
    def valid_others(cls, value: Dict[str, str]) -> Dict[str, str]:
        return {k: v for k, v in value.items() if k[0].upper() == k[0]}

    @validator("ipv4")
    def ipv4_max_prefix_len(cls, value: IPv4Interface) -> IPv4Interface:
        if value.network.prefixlen > 30:
            raise ValueError("Server interface ipv4 address mask must be <= 30")
        return value

    @validator("ipv6")
    def ipv6_max_prefix_len(cls, value: Optional[IPv6Interface]) -> Optional[IPv6Interface]:
        if value is not None and value.network.prefixlen <= 126:
            raise ValueError("Server interface ipv6 address mask must be <= 126")
        return value

    class Config:
        validate_assignment = True


@dataclass
class WGConfigGroup:
    name: str
    key_values: Dict[str, str]
