from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List
from pydantic import BaseModel, Field


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
    allowed_ips: str = ""
    server: WGServerEndpoint = WGServerEndpoint()
    ipv4: str = ""
    ipv6: str = ""
    dns: str = ""
    others: Dict[str, str] = Field(default_factory=dict)


class WGServerConfig(BaseModel):
    server: WGServerEndpoint = Field(default_factory=lambda: WGServerEndpoint())
    ipv4: str = "10.6.0.1/24"
    ipv6: str = ""
    mtu: int = Field(default=1420, ge=1280, le=65535)
    post_up: str = ""
    post_down: str = ""
    others: Dict[str, str] = Field(default_factory=dict)
    peers: List[WGPeerConfig] = Field(default_factory=list)


@dataclass
class WGConfigGroup:
    name: str
    key_values: Dict[str, str]
