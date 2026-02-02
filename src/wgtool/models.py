from dataclasses import dataclass
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)

from pydantic import BaseModel, Field, field_validator

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
    ipv4: IPv4Interface | None = None
    ipv6: IPv6Interface | None = None
    allowed_ips: list[IPv4Network | IPv6Network] = Field(default_factory=list)
    dns: list[IPv4Address | IPv6Address] = Field(default_factory=list)
    others: dict[str, str] = Field(default_factory=dict)

    @property
    def address(self) -> str:
        return ", ".join([str(ip) for ip in [self.ipv4, self.ipv6] if ip])

    @field_validator("others")
    @classmethod
    def valid_others(cls, value: dict[str, str]) -> dict[str, str]:
        return {k: v for k, v in value.items() if k[0].upper() == k[0]}

    model_config = {"validate_assignment": True}


class WGServerConfig(BaseModel):
    server: WGServerEndpoint = Field(default_factory=lambda: WGServerEndpoint())
    ipv4: IPv4Interface = IPv4Interface("10.6.0.1/24")
    ipv6: IPv6Interface | None = None
    mtu: int = Field(default=1420, ge=1280, le=65535)
    post_up: str = ""
    post_down: str = ""
    others: dict[str, str] = Field(default_factory=dict)
    peers: list[WGPeerConfig] = Field(default_factory=list)

    @property
    def address(self) -> str:
        return ", ".join([str(ip) for ip in [self.ipv4, self.ipv6] if ip])

    @field_validator("others")
    @classmethod
    def valid_others(cls, value: dict[str, str]) -> dict[str, str]:
        return {k: v for k, v in value.items() if k[0].upper() == k[0]}

    @field_validator("ipv4")
    @classmethod
    def ipv4_max_prefix_len(cls, value: IPv4Interface) -> IPv4Interface:
        if value.network.prefixlen > 30:
            raise ValueError("Server interface ipv4 address mask must be <= 30")
        return value

    @field_validator("ipv6")
    @classmethod
    def ipv6_max_prefix_len(cls, value: IPv6Interface | None) -> IPv6Interface | None:
        if value is not None and value.network.prefixlen <= 126:
            raise ValueError("Server interface ipv6 address mask must be <= 126")
        return value

    model_config = {"validate_assignment": True}


@dataclass
class WGConfigGroup:
    name: str
    key_values: dict[str, str]
