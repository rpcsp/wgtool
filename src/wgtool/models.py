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
    """A WireGuard server endpoint configuration.

    Attributes:
        address: The server address (default: "host.example.com")
        port: The server port (default: 51820, range: 1024-65535)
        public_key: The server's public key
        private_key: The server's private key
    """

    address: str = "host.example.com"
    port: int = Field(default=DEFAULT_PORT, ge=1024, le=65535)
    public_key: str = ""
    private_key: str = ""

    @property
    def endpoint(self) -> str:
        """Return the endpoint as 'address:port' string."""
        return f"{self.address}:{self.port}"


class WGPeerConfig(BaseModel):
    """A WireGuard peer configuration.

    Attributes:
        name: The peer name
        public_key: The peer's public key
        preshared_key: The peer's preshared key
        private_key: The peer's private key
        server: The server endpoint configuration
        ipv4: The peer's IPv4 address
        ipv6: The peer's IPv6 address
        allowed_ips: List of allowed IP networks
        dns: List of DNS servers
        others: Additional key-value pairs
    """

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
        """Return the address as a comma-separated string of IPv4 and IPv6 addresses."""
        return ", ".join([str(ip) for ip in [self.ipv4, self.ipv6] if ip])

    @field_validator("others")
    @classmethod
    def valid_others(cls, value: dict[str, str]) -> dict[str, str]:
        """Validate that all keys in 'others' start with an uppercase letter."""
        return {k: v for k, v in value.items() if k[0].upper() == k[0]}

    model_config = {"validate_assignment": True}


class WGServerConfig(BaseModel):
    """A WireGuard server configuration.

    Attributes:
        server: The server endpoint configuration
        ipv4: The server's IPv4 address (default: 10.6.0.1/24)
        ipv6: The server's IPv6 address
        mtu: The Maximum Transmission Unit (default: 1420, range: 1280-65535)
        post_up: Post-up script
        post_down: Post-down script
        others: Additional key-value pairs
        peers: List of peer configurations
    """

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
        """Return the address as a comma-separated string of IPv4 and IPv6 addresses."""
        return ", ".join([str(ip) for ip in [self.ipv4, self.ipv6] if ip])

    @field_validator("others")
    @classmethod
    def valid_others(cls, value: dict[str, str]) -> dict[str, str]:
        """Validate that all keys in 'others' start with an uppercase letter."""
        return {k: v for k, v in value.items() if k[0].upper() == k[0]}

    @field_validator("ipv4")
    @classmethod
    def ipv4_max_prefix_len(cls, value: IPv4Interface) -> IPv4Interface:
        """Validate that the IPv4 prefix length is <= 30."""
        if value.network.prefixlen > 30:
            raise ValueError("Server interface ipv4 address mask must be <= 30")
        return value

    @field_validator("ipv6")
    @classmethod
    def ipv6_max_prefix_len(cls, value: IPv6Interface | None) -> IPv6Interface | None:
        """Validate that the IPv6 prefix length is <= 126."""
        if value is not None and value.network.prefixlen <= 126:
            raise ValueError("Server interface ipv6 address mask must be <= 126")
        return value

    model_config = {"validate_assignment": True}


@dataclass
class WGConfigGroup:
    name: str
    key_values: dict[str, str]
