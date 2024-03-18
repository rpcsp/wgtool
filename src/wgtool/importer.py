import re
from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv6Address,
    IPv6Interface,
    ip_address,
    ip_interface,
)
from typing import Dict, List, Optional, Union

from wgtool.exceptions import WGToolError
from wgtool.models import WGConfigGroup, WGPeerConfig, WGServerConfig

re_group = re.compile(r"\[(\w+)\]")
re_key_value = re.compile(r"^([^=]+)\s*=\s*(.+)$")


class WGServerConfigImporter:
    def __init__(self, current_config: Optional[WGServerConfig] = None) -> None:
        self.config = current_config or WGServerConfig()
        self.interface = WGPeerConfig(name="Interface")
        self.peers: List[WGPeerConfig] = []

    def read_interface(self, attrs: Dict[str, str]) -> None:
        cfg = self.config
        for ip in self._to_ip_interface_list(attrs.pop("Address", "")):
            if isinstance(ip, IPv6Interface):
                self.ipv6 = ip
            else:
                self.ipv4 = ip
        cfg.mtu = int(attrs.pop("MTU", "") or cfg.mtu)
        cfg.post_up = attrs.pop("PostUp", "") or cfg.post_up
        cfg.post_down = attrs.pop("PostDown", "") or cfg.post_down
        cfg.server.private_key = attrs.pop("PrivateKey", "") or cfg.server.private_key
        cfg.server.port = int(attrs.pop("ListenPort", "") or cfg.server.port)
        cfg.server.address = (attrs.pop("# Endpoint", "") or cfg.server.address).split(":")[0]
        cfg.others = {k: v for k, v in attrs.items() if k[0] == k[0].upper()}

    def read_peers(self, peers: List[WGConfigGroup]) -> None:

        class PeerNames:
            def __init__(self) -> None:
                self.i = 0

            def get_name(self) -> str:
                self.i += 1
                return f"Peer {self.i}"

        peer_names = PeerNames()
        for peer in peers:
            name = peer.key_values.pop("# Name", "") or peer_names.get_name()
            pc = WGPeerConfig(name=name)
            for ip in self._to_ip_interface_list(peer.key_values.pop("AllowedIPs", "")):
                if isinstance(ip, IPv4Interface):
                    pc.ipv4 = ip
                else:
                    pc.ipv6 = ip
            pc.public_key = peer.key_values.pop("PublicKey", pc.public_key)
            pc.preshared_key = peer.key_values.pop("PresharedKey", pc.preshared_key)
            pc.dns = self._to_ip_address_list(peer.key_values.pop("DNS", "")) or pc.dns
            pc.server = self.config.server
            pc.others = {k: v for k, v in peer.key_values.items() if k[0] == k[0].upper()}
            self.config.peers.append(pc)

    def from_file(self, file: str) -> WGServerConfig:
        groups = self._from_file(file)
        for i, group in enumerate(groups):
            if group.name == "Interface":
                self.read_interface(group.key_values)
                groups.pop(i)
                break
        else:
            raise WGToolError("Config not found")
        self.read_peers(groups)
        return self.config

    def _from_file(self, file: str) -> List[WGConfigGroup]:
        with open(file) as f:
            content = f.read()

        config: List[WGConfigGroup] = []
        key_values: Dict[str, str] = {}
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            if match := re_group.match(line):
                name = match.group(1).strip()
                key_values = {}
                config.append(WGConfigGroup(name, key_values))
            elif match := re_key_value.match(line):
                key = match.group(1).strip()
                value = match.group(2).strip()
                key_values[key] = value
        return config

    def _to_ip_interface_list(self, address: str) -> List[Union[IPv4Interface, IPv6Interface]]:
        return [ip_interface(ip.strip()) for ip in address.split(",") if ip.strip()]

    def _to_ip_address_list(self, address: str) -> List[Union[IPv4Address, IPv6Address]]:
        return [ip_address(ip.strip()) for ip in address.split(",") if ip.strip()]
